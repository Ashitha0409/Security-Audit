"""
rag.py — a lightweight Retrieval-Augmented Generation pipeline over scan data.

Instead of dumping the entire scan into the prompt, we:
  1. turn the scan result into small retrievable documents,
  2. index them,
  3. retrieve only the chunks relevant to the user's question,
  4. hand those grounded chunks to the LLM (see chatbot.py).

This keeps answers grounded in the user's actual scan, cuts token usage, and
scales to the heavier advanced-scan output (nmap/nikto/sqlmap/breach data).

Embedding backend (auto-selected, graceful fallback — mirrors the AI provider
chain philosophy of the rest of the app):
  1. sentence-transformers  → dense semantic search (best quality, if installed)
  2. pure-Python TF-IDF cosine → always works, zero dependencies
"""
import math
import re
from collections import Counter

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokenize(text: str):
    return _TOKEN_RE.findall((text or "").lower())


# ──────────────────────────────────────────────
# 1. DOCUMENT BUILDER — scan result → retrievable chunks
# ──────────────────────────────────────────────

def build_documents(scan_context: dict):
    """Flatten a scan_context dict into a list of {id, text, metadata} docs."""
    docs = []

    def add(doc_id, text, meta=None):
        text = (text or "").strip()
        if text:
            docs.append({"id": doc_id, "text": text, "metadata": meta or {}})

    if not scan_context:
        return docs

    url = scan_context.get("url", "the website")
    add(
        "overview",
        f"Overview for {url}. Security score {scan_context.get('score', 'N/A')} out of 100, "
        f"risk level {scan_context.get('risk_level', 'unknown')}. "
        f"Summary: {scan_context.get('ai_summary', '')}",
        {"type": "overview"},
    )

    # Core scan findings
    for i, f in enumerate(scan_context.get("findings", []) or []):
        add(
            f"finding-{i}",
            f"{f.get('check', '')} — status {f.get('status', '')}, "
            f"severity {f.get('severity', '')}. {f.get('details', '')} "
            f"Recommended fix: {f.get('fix', '') or 'none'}",
            {
                "type": "finding",
                "check": f.get("check"),
                "severity": f.get("severity"),
                "status": f.get("status"),
            },
        )

    # Advanced scan output (nmap / nikto / sqlmap), if present
    adv = scan_context.get("advanced_scan") or {}
    if isinstance(adv, dict):
        nmap = adv.get("nmap") or {}
        for r in (nmap.get("risk_findings", []) if isinstance(nmap, dict) else []):
            add(
                f"nmap-{r.get('port')}",
                f"Nmap found open port {r.get('port')} ({r.get('service')}): "
                f"{r.get('description')}. Severity {r.get('severity')}. "
                f"Version: {r.get('version', '')}",
                {"type": "nmap", "port": r.get("port"), "severity": r.get("severity")},
            )

        nikto = adv.get("nikto") or {}
        for j, v in enumerate(nikto.get("vulnerabilities", []) if isinstance(nikto, dict) else []):
            add(
                f"nikto-{j}",
                f"Nikto web vulnerability: {v.get('description')}. "
                f"Severity {v.get('severity')}. Reference {v.get('reference') or 'n/a'}",
                {"type": "nikto", "severity": v.get("severity")},
            )

        sql = adv.get("sqlmap") or {}
        if isinstance(sql, dict) and sql.get("injectable"):
            add(
                "sqlmap",
                f"SQLMap detected SQL injection. Back-end DBMS: {sql.get('dbms')}. "
                f"Vulnerable parameters: {', '.join(sql.get('parameters', []) or [])}. "
                f"{sql.get('summary', '')}",
                {"type": "sqlmap", "severity": "critical"},
            )

    return docs


# ──────────────────────────────────────────────
# 2. RETRIEVERS
# ──────────────────────────────────────────────

def _cosine_sparse(a: dict, b: dict) -> float:
    if not a or not b:
        return 0.0
    common = set(a) & set(b)
    dot = sum(a[t] * b[t] for t in common)
    na = math.sqrt(sum(x * x for x in a.values()))
    nb = math.sqrt(sum(x * x for x in b.values()))
    return dot / (na * nb) if na and nb else 0.0


class _TfidfIndex:
    """Pure-Python TF-IDF cosine retriever — no third-party dependencies."""

    def __init__(self, docs):
        self.docs = docs
        tokenised = [_tokenize(d["text"]) for d in docs]
        n = len(docs)
        df = Counter()
        for toks in tokenised:
            for t in set(toks):
                df[t] += 1
        self.idf = {t: math.log((1 + n) / (1 + c)) + 1.0 for t, c in df.items()}
        self.vectors = [self._vectorize(toks) for toks in tokenised]

    def _vectorize(self, toks):
        if not toks:
            return {}
        tf = Counter(toks)
        length = len(toks)
        return {t: (c / length) * self.idf.get(t, 0.0) for t, c in tf.items()}

    def query(self, text, k):
        qv = self._vectorize(_tokenize(text))
        scored = [(_cosine_sparse(qv, v), d) for v, d in zip(self.vectors, self.docs)]
        scored.sort(key=lambda x: x[0], reverse=True)
        return [(s, d) for s, d in scored[:k] if s > 0.0]


class _SentenceTransformerIndex:
    """Dense semantic retriever — used only if sentence-transformers is installed."""

    _model = None

    def __init__(self, docs):
        self.docs = docs
        model = self._load_model()
        self._embeddings = model.encode(
            [d["text"] for d in docs], normalize_embeddings=True
        ).tolist()

    @classmethod
    def _load_model(cls):
        if cls._model is None:
            from sentence_transformers import SentenceTransformer
            cls._model = SentenceTransformer("all-MiniLM-L6-v2")
        return cls._model

    @staticmethod
    def _dot(a, b):
        return sum(x * y for x, y in zip(a, b))

    def query(self, text, k):
        qv = self._load_model().encode([text], normalize_embeddings=True).tolist()[0]
        scored = [(self._dot(qv, e), d) for e, d in zip(self._embeddings, self.docs)]
        scored.sort(key=lambda x: x[0], reverse=True)
        return [(s, d) for s, d in scored[:k] if s > 0.0]


_BACKEND_CHOICE = "uninitialised"


def _build_index(docs):
    """Pick the best available retriever for these docs (cached choice)."""
    global _BACKEND_CHOICE
    if _BACKEND_CHOICE in ("uninitialised", "sentence-transformers"):
        try:
            index = _SentenceTransformerIndex(docs)
            _BACKEND_CHOICE = "sentence-transformers"
            return index
        except Exception:
            _BACKEND_CHOICE = "tfidf"
    return _TfidfIndex(docs)


# ──────────────────────────────────────────────
# 3. PUBLIC API
# ──────────────────────────────────────────────

def retrieve(query: str, scan_context: dict, k: int = 6):
    """Return up to k (score, document) tuples most relevant to the query."""
    docs = build_documents(scan_context)
    if not docs:
        return []
    return _build_index(docs).query(query, k)


def _source_label(doc: dict) -> str:
    """Human-readable citation label for a retrieved document."""
    m = doc.get("metadata", {})
    t = m.get("type")
    if t == "finding":
        return m.get("check") or "Finding"
    if t == "nmap":
        return f"Open port {m.get('port')} (Nmap)"
    if t == "nikto":
        return "Web vulnerability (Nikto)"
    if t == "sqlmap":
        return "SQL injection (SQLMap)"
    if t == "overview":
        return "Scan overview"
    return "Scan detail"


def get_sources(query: str, scan_context: dict, k: int = 5):
    """
    Return the scan findings used to ground an answer, for display as
    citations in the UI: [{label, type, severity, relevance}].
    """
    sources = []
    seen = set()
    for score, doc in retrieve(query, scan_context, k):
        label = _source_label(doc)
        if label in seen:
            continue
        seen.add(label)
        sources.append({
            "label": label,
            "type": doc["metadata"].get("type"),
            "severity": doc["metadata"].get("severity") or "info",
            "relevance": round(float(score), 3),
        })
    return sources


def build_rag_context(query: str, scan_context: dict, k: int = 6) -> str:
    """
    Build a focused, grounded context string for the chatbot prompt:
    a compact header plus only the scan details relevant to this question.
    """
    if not scan_context:
        return "No scan data available yet. The user hasn't scanned a website."

    header = (
        f"WEBSITE: {scan_context.get('url', 'Unknown')} | "
        f"SCORE: {scan_context.get('score', 'N/A')}/100 | "
        f"RISK: {scan_context.get('risk_level', 'Unknown')}"
    )

    results = retrieve(query, scan_context, k)

    # Fallback: if nothing matched (e.g. a vague greeting), surface the overview
    # plus the highest-severity findings so the model still has grounding.
    if not results:
        docs = build_documents(scan_context)
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        docs.sort(key=lambda d: sev_rank.get(d["metadata"].get("severity"), 4))
        results = [(0.0, d) for d in docs[:k]]

    lines = [header, "", "MOST RELEVANT SCAN DETAILS (retrieved for this question):"]
    lines += [f"- {d['text']}" for _, d in results]
    return "\n".join(lines)
