# PRAWL — Build & Architecture Specification
### Four-feature expansion: compliance, attack-path reasoning, attack-path graph, phishing-domain watch

---

**Document control**

| Field | Value |
|---|---|
| Project | PRAWL — security + compliance layer for Indian small and medium businesses |
| Document type | Engineering build specification + architecture reference |
| Version | 1.0 |
| Status | Build-ready |
| Scope | Four new features, end to end: data model, algorithms, code skeletons, datasets, dependencies, testing, legal safeguards, roadmap |
| Audience | You (the implementer) and any teammate joining the sprint |
| Out of scope | The stack-aware auto-remediation feature and the continuous-monitoring scheduler are referenced where they touch these four, but their full build is deferred to a Phase 2 document |

**The four features this document specifies**

1. **DPDP compliance engine** — maps every technical finding to an Indian legal obligation and a rupee-denominated penalty band, and emits a DPDP Readiness Score.
2. **Agentic attack-path reasoning engine** — chains findings into grounded attack paths, scores real-world exploitability, and replaces the naive additive score.
3. **Attack-path graph visualization** — the interactive directed graph the engine feeds, rendered in the browser.
4. **Lookalike / phishing-domain watch** — detects domains impersonating the business via typosquatting permutations and Certificate Transparency logs.

A note on style: this document is blunt by design. Where something will get you torn apart in a demo, or is a trap you will walk into, it says so in a **Reality check** callout. Read those twice.

---

## Table of contents

1. Executive summary
2. System context — what PRAWL is today
3. Cross-cutting architecture — how the four features plug in
4. Shared data contracts
5. Feature 1 — DPDP compliance engine
6. Feature 2 — agentic attack-path reasoning engine
7. Feature 3 — attack-path graph visualization
8. Feature 4 — lookalike / phishing-domain watch
9. Unified API surface
10. Dependencies, extensions & infrastructure
11. Datasets & external sources (consolidated)
12. Security, ethics & legal safeguards
13. Build roadmap & phasing
14. Testing & validation strategy
15. Risk register & known limitations
16. Appendix A — full DPDP obligation table
17. Appendix B — full attack-transition table
18. Appendix C — glossary & abbreviations

---

## 1. Executive summary

PRAWL today is a competent orchestration wrapper around well-known open-source security engines — Network Mapper (Nmap), Nikto, the Structured Query Language injection tool (SQLMap), WhatWeb, and Certificate Transparency log enumeration through crt.sh — with a Large Language Model (LLM) summary layer and Indian-language localization on top. It works. It is also, technically, not novel: every engine inside it is decades old, and "Artificial Intelligence summary on a vulnerability scanner" is a crowded category.

The four features in this document exist to move PRAWL from *commodity scanner* to *defensible product* by adding the one thing the free tooling in this space does not have: a translation layer from raw technical findings into the two things an Indian business owner actually cares about — **legal exposure** and **realistic attack risk** — expressed in plain language and rupees.

The strategic spine connecting all four:

- **Feature 1** answers *"what does this cost me legally?"* — and the answer is timely because India's Digital Personal Data Protection Act, 2023 (DPDP Act) is now live, with rules notified in November 2025 and full substantive enforcement landing 14 May 2027. Roughly 70% of organizations report limited familiarity with the law. That is a compliance vacuum, and a scanner already measures the exact technical posture the law penalizes.
- **Feature 2** answers *"how would someone actually break in?"* — by chaining findings into grounded attack paths instead of a flat checklist, and scoring exploitability by reachability to a crown-jewel goal.
- **Feature 3** makes Feature 2 *legible* — the directed graph is the demo centerpiece, and the terminal node fuses back into Feature 1's penalty band.
- **Feature 4** answers *"who is pretending to be me?"* — extending the Certificate Transparency data source already in the codebase to catch brand-impersonation domains, which matter enormously to Indian businesses targeted for Unified Payments Interface (UPI) fraud.

> **Reality check.** The novelty is not in any single feature — each one, alone, has prior art somewhere. The novelty is in the *fusion specific to the Indian small-business context*: technical finding → grounded exploit path → Indian legal consequence in rupees → plain-language regional fix. Do not let a judge frame any one feature in isolation. Always tell the joined story.

---

## 2. System context — what PRAWL is today

You are extending an existing Flask application. The relevant existing modules:

| Module | Responsibility | Touched by new features? |
|---|---|---|
| `backend/app.py` | Flask server, API routes, rate limiting, Cross-Origin Resource Sharing (CORS) | Yes — new routes added |
| `backend/scanner.py` | Passive checks: SSL/TLS, security headers, HTTPS redirect, basic port socket scan, software version disclosure, cookies, CORS, exposed files (`.env`, `.git`), the additive `calculate_score()` | Yes — `calculate_score()` is replaced; findings become the input to all four features |
| `advanced_scanner.py` | Docker-based active tools: Nmap, Nikto, SQLMap, WhatWeb; plus crt.sh subdomain enumeration | Yes — its output feeds Features 2 and 4; crt.sh logic is reused by Feature 4 |
| `backend/chatbot.py` | LLM provider chain: Groq → Anthropic → OpenRouter → rule-based fallback | Yes — reused for compliance briefs and attack narratives |
| `backend/report_generator.py` | PDF reports via ReportLab | Yes — new sections appended |
| `backend/prawl_history.db` | SQLite scan history | Yes — new tables for compliance, paths, impersonators |
| `frontend/templates/index.html` | Single-page UI, Chart.js | Yes — graph canvas + compliance panel + phishing panel |

The single most important existing artifact for the new work is the **finding object** produced throughout `scanner.py`:

```python
{
  'check':    'Dangerous Open Ports',   # human label
  'status':   'fail',                   # pass | fail | warning | error
  'severity': 'high',                   # critical | high | medium | low | info | none
  'details':  'Risky ports exposed: 3306 (MySQL)',
  'fix':      'Close these ports in your firewall...'
}
```

Every new feature consumes a list of these objects. The first engineering task before any feature is to make this schema reliable and machine-readable, because right now `check` is a free-text label and the new logic needs stable identifiers.

> **Reality check.** Your current findings are keyed on `check` strings like `"Header: X-Frame-Options"`. String matching against display labels is fragile — a wording change silently breaks every downstream mapping. Add a stable `finding_id` (a slug enum) to every finding *first*. This is unglamorous and it is the foundation the whole document stands on. Skip it and Features 1, 2, and 4 will be a swamp of brittle `if "MySQL" in check:` checks.

---

## 3. Cross-cutting architecture — how the four features plug in

### 3.1 Target directory structure

```
backend/
├── app.py                       # + new routes
├── scanner.py                   # findings now carry finding_id; calculate_score() retired
├── advanced_scanner.py
├── chatbot.py
├── report_generator.py
│
├── core/
│   ├── finding_ids.py           # the canonical slug enum (NEW)
│   └── schemas.py               # typed dataclasses for findings/paths/etc (NEW)
│
├── compliance/                  # FEATURE 1
│   ├── __init__.py
│   ├── obligations.py           # the DPDP/CERT-In obligation knowledge base
│   ├── compliance_mapper.py     # finding_id -> obligation mapping + readiness score
│   └── brief_generator.py       # LLM compliance brief (regional languages)
│
├── attackpath/                  # FEATURE 2
│   ├── __init__.py
│   ├── attack_transitions.py    # the curated transition knowledge base
│   ├── attack_graph.py          # grounded DiGraph builder + JSON export
│   ├── path_scorer.py           # reachability-based exploitability score
│   └── narrative.py             # LLM walk-the-path narration
│
├── phishing/                    # FEATURE 4
│   ├── __init__.py
│   ├── permutations.py          # typosquat generation (dnstwist wrapper)
│   ├── ct_monitor.py            # Certificate Transparency lookups (reuses crt.sh)
│   └── impersonator_scorer.py   # rank candidate domains by threat
│
└── data/
    ├── dpdp_obligations.json    # legal mapping data (Feature 1)
    └── attack_transitions.json  # transition primitives (Feature 2)

frontend/
├── templates/index.html         # + graph canvas, compliance + phishing panels
└── static/
    └── js/
        ├── attack_graph.js      # FEATURE 3 — Cytoscape.js renderer
        ├── compliance_panel.js
        └── phishing_panel.js
```

### 3.2 The unified scan pipeline

The orchestration changes from "run scanners → score → summarize" to a layered pipeline. Each layer consumes the layer before it:

```
            ┌──────────────────────────────────────────────┐
   URL  ──► │  LAYER 0: COLLECTION                          │
            │  scanner.py + advanced_scanner.py             │
            │  → List[Finding]  (each with stable finding_id)│
            └──────────────────────────────────────────────┘
                              │ findings
            ┌─────────────────┼──────────────────┐
            ▼                 ▼                  ▼
   ┌───────────────┐  ┌────────────────┐  ┌──────────────────┐
   │ LAYER 1A      │  │ LAYER 1B       │  │ LAYER 1C         │
   │ Attack-path   │  │ Compliance     │  │ Phishing watch   │
   │ engine (F2)   │  │ engine (F1)    │  │ (F4)             │
   │ → graph JSON  │  │ → readiness    │  │ → impersonators  │
   │ → exploit     │  │   score +      │  │                  │
   │   score       │  │   obligations  │  │                  │
   └───────────────┘  └────────────────┘  └──────────────────┘
            │ graph + impact node │ obligations         │
            └─────────┬───────────┘                     │
                      ▼                                  │
            ┌──────────────────────┐                     │
            │ LAYER 2: FUSION      │ ◄───────────────────┘
            │ - attack goal node   │
            │   carries DPDP band  │
            │ - LLM briefs (F1,F2) │
            └──────────────────────┘
                      │
                      ▼
            ┌──────────────────────┐
            │ LAYER 3: PRESENTATION│
            │ graph (F3) + panels  │
            │ + PDF + chatbot      │
            └──────────────────────┘
```

Key dependency: **Feature 1's compliance mapping wants the attack-path result.** A missing security header in isolation is a low-grade obligation gap; the *same* header on a node that sits on a live path to a customer-data breach is a "reasonable security safeguards" failure with a much higher penalty band. So run Feature 2 before Feature 1 finalizes its bands, or have Feature 1 read the exploit reachability flag per finding. This coupling is what makes the output feel intelligent rather than mechanical.

### 3.3 Execution model

Layers 1A, 1B, and 1C are independent and should run concurrently (you already use `concurrent.futures.ThreadPoolExecutor` in `advanced_scanner.py` — extend that pattern). Layer 2 joins them. Budget the LLM calls carefully: you have up to four LLM generations per scan (compliance brief, attack narrative, existing summary, chatbot). Batch or cache where you can; the free Groq tier has rate limits.

---

## 4. Shared data contracts

Define these once in `backend/core/schemas.py` using dataclasses. Everything downstream depends on them. Typed contracts are what stop a multi-module system from rotting.

```python
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"
    NONE     = "none"


class FindingStatus(str, Enum):
    PASS    = "pass"
    FAIL    = "fail"
    WARNING = "warning"
    ERROR   = "error"


@dataclass
class Finding:
    finding_id: str              # stable slug, e.g. "open_port_mysql"
    check: str                   # human display label
    status: FindingStatus
    severity: Severity
    details: str
    fix: str = ""
    evidence: dict = field(default_factory=dict)   # raw data: port, header value, leaked snippet
    on_exploit_path: bool = False                  # set by Feature 2, read by Feature 1


@dataclass
class ObligationHit:
    obligation_id: str
    law: str                     # "DPDP Act 2023" | "CERT-In Directions 2022"
    clause: str                  # "Section 8(4) — reasonable security safeguards"
    status: str                  # "gap" | "partial" | "met"
    penalty_ceiling_inr: int     # in rupees, e.g. 2_500_000_000 for ₹250 crore
    rationale: str
    triggering_finding_ids: list = field(default_factory=list)


@dataclass
class GraphNode:
    node_id: str
    label: str
    layer: str                   # "entry" | "finding" | "capability" | "impact"
    severity: Severity
    finding_id: Optional[str] = None
    penalty_ceiling_inr: Optional[int] = None      # only on impact nodes


@dataclass
class GraphEdge:
    source: str
    target: str
    confidence: float            # 0.0 - 1.0, from the transition KB
    transition_id: str
    rationale: str
```

The `finding_id` enum (in `core/finding_ids.py`) is the contract that ties the existing scanner to all new code. A starter set:

```python
class FindingID:
    SSL_EXPIRED          = "ssl_expired"
    SSL_EXPIRING         = "ssl_expiring"
    NO_HTTPS_REDIRECT    = "no_https_redirect"
    MISSING_HSTS         = "missing_hsts"
    MISSING_CSP          = "missing_csp"
    MISSING_XFO          = "missing_x_frame_options"
    OPEN_PORT_MYSQL      = "open_port_mysql"
    OPEN_PORT_POSTGRES   = "open_port_postgres"
    OPEN_PORT_MONGODB    = "open_port_mongodb"
    OPEN_PORT_REDIS      = "open_port_redis"
    OPEN_PORT_SSH        = "open_port_ssh"
    OPEN_PORT_RDP        = "open_port_rdp"
    EXPOSED_ENV          = "exposed_env_file"
    EXPOSED_GIT          = "exposed_git_dir"
    SQL_INJECTION        = "sql_injection"
    SOFTWARE_DISCLOSURE  = "software_version_disclosure"
    INSECURE_COOKIES     = "insecure_cookies"
    CORS_WILDCARD        = "cors_wildcard"
    BREACH_HISTORY       = "data_breach_history"
    # ...extend as scanner grows
```

Your first refactor: in `scanner.py`, attach the correct `finding_id` to every finding it already produces. Roughly a day of mechanical work. Do it before anything else.

---

## 5. Feature 1 — DPDP compliance engine

### 5.1 What it is and why it is novel

Every scanner outputs severity labels. None of the free ones tell an Indian shop owner that a finding maps to a specific clause of a specific Indian law carrying a specific rupee penalty with a specific enforcement deadline. That mapping is the feature.

The pitch line, which must survive Q&A: *"A generic scanner tells you a port is open. We tell you it is a reasonable-security-safeguards failure under Section 8(4) of the DPDP Act, exposing you to penalties up to ₹250 crore, with full enforcement from 14 May 2027 — and here is the fix."*

### 5.2 Legal grounding (verified, current as of mid-2026)

This is the factual backbone. Get it right; a lawyer in the audience will check.

**Digital Personal Data Protection Act, 2023 (DPDP Act) and DPDP Rules, 2025**

- The DPDP Act was passed in August 2023. The DPDP Rules were **notified on 13–14 November 2025**, with phased enforcement: institutional provisions immediate, consent-manager provisions from November 2026, and **full substantive obligations from 14 May 2027**. Treat 2026 as the "build year."
- The Act penalizes **failure to implement reasonable security safeguards** (Section 8(4)/8(5)) with fines **up to ₹250 crore**.
- **Breach notification** (Section 8(6), operationalized by Rule 7): an initial intimation to the **Data Protection Board of India** without undue delay, and a detailed report **within 72 hours** of becoming aware; affected **data principals** (individuals) must also be notified "without delay" in **clear and plain language**, stating the nature of the breach, categories of data affected, probable consequences, mitigation taken, what the individual should do, and a contact point. Failure to notify carries penalties **up to ₹200 crore**.
- The Act does not itself prescribe a security standard, but the associated Privacy Rules reference **IS/ISO/IEC 27001** as the reference information-security standard.
- The DPDP Rules add a **minimum 1-year retention** of traffic and processing logs.
- The Act is size-blind: a breach of ten records carries the same notification obligation as ten million. Small businesses face the same penalty structure as large enterprises.

**CERT-In (Indian Computer Emergency Response Team) Directions, April 2022** — these run in parallel and are *already in force*, under Section 70B of the Information Technology Act, 2000.

- Specified cyber incidents must be reported to CERT-In **within 6 hours** of noticing them.
- **180-day** retention of security logs, held within India.
- System clock synchronization with National Informatics Centre / National Physical Laboratory (NIC/NPL) time servers via Network Time Protocol (NTP).
- Non-compliance penalty: up to ₹1 lakh and up to 1 year imprisonment under IT Act Section 70B.

> **The killer detail.** A single customer-data breach starts *two clocks at once*: the 6-hour CERT-In cyber-incident clock and the 72-hour DPDP Board clock. Almost no SMB knows this. Your compliance engine surfacing the "dual-clock" obligation is a genuinely useful, genuinely differentiated output. Put it on a node in the report.

> **Reality check — this is not legal advice and you must say so.** You are a student building a scanner, not a law firm. Every compliance output must carry a visible disclaimer: *"Indicative compliance guidance generated from public information about the DPDP Act and CERT-In Directions. Not legal advice. Consult a qualified professional."* This protects the user from acting on a wrong mapping and protects you from liability. Non-negotiable.

### 5.3 The obligation knowledge base

There is **no public dataset** for finding→obligation mapping. You build it by hand, once, as `data/dpdp_obligations.json`. This hand-built mapping *is* the intellectual property of the feature. Each entry maps one or more `finding_id`s to one obligation. Structure:

```json
{
  "obligations": [
    {
      "obligation_id": "dpdp_reasonable_safeguards",
      "law": "DPDP Act 2023",
      "clause": "Section 8(4)/8(5) — reasonable security safeguards",
      "penalty_ceiling_inr": 2500000000,
      "description": "Data Fiduciaries must protect personal data with reasonable security safeguards to prevent a breach.",
      "triggers": {
        "open_port_mysql":   {"weight": "high",   "note": "Database directly reachable from the internet."},
        "open_port_mongodb": {"weight": "high",   "note": "Database directly reachable from the internet."},
        "exposed_env_file":  {"weight": "high",   "note": "Secrets and credentials publicly exposed."},
        "exposed_git_dir":   {"weight": "high",   "note": "Source code and history publicly exposed."},
        "sql_injection":     {"weight": "high",   "note": "Database contents reachable via injection."},
        "missing_hsts":      {"weight": "low",    "note": "Transport security not enforced."},
        "insecure_cookies":  {"weight": "medium", "note": "Session data transmittable in cleartext."}
      },
      "amplified_if_on_exploit_path": true
    },
    {
      "obligation_id": "dpdp_breach_notification",
      "law": "DPDP Act 2023",
      "clause": "Section 8(6) + Rule 7 — breach notification (72h to Board)",
      "penalty_ceiling_inr": 2000000000,
      "description": "On a personal-data breach, notify the Data Protection Board within 72 hours and affected individuals without delay.",
      "triggers": {
        "data_breach_history": {"weight": "high", "note": "Known historical breach — notification readiness must be proven."}
      },
      "advisory": "readiness"
    },
    {
      "obligation_id": "certin_incident_reporting",
      "law": "CERT-In Directions 2022",
      "clause": "6-hour cyber-incident reporting (IT Act s.70B)",
      "penalty_ceiling_inr": 100000,
      "description": "Report specified cyber incidents to CERT-In within 6 hours of detection.",
      "triggers": {
        "data_breach_history": {"weight": "high", "note": "Incident-response and 6-hour reporting capability required."}
      },
      "advisory": "readiness"
    }
  ]
}
```

The full table is in **Appendix A**. Aim for 8–12 obligations covering the findings your scanner actually produces. Do not invent obligations for findings you cannot detect — that is the kind of padding a judge spots.

### 5.4 The mapper

```python
# backend/compliance/compliance_mapper.py
import json
from pathlib import Path

_OBLIGATIONS = json.loads((Path(__file__).parent.parent / "data" / "dpdp_obligations.json").read_text())["obligations"]

_WEIGHT_SCORE = {"high": 3, "medium": 2, "low": 1}


def map_findings_to_obligations(findings):
    """findings: List[Finding]. Returns List[ObligationHit] for failing/warning findings."""
    failing = {f.finding_id: f for f in findings if f.status in ("fail", "warning")}
    hits = []

    for ob in _OBLIGATIONS:
        triggered = [fid for fid in ob["triggers"] if fid in failing]
        if not triggered:
            continue

        worst = max(_WEIGHT_SCORE[ob["triggers"][fid]["weight"]] for fid in triggered)
        on_path = any(failing[fid].on_exploit_path for fid in triggered)

        if on_path and ob.get("amplified_if_on_exploit_path"):
            status = "gap"            # confirmed reachable -> hard gap
        elif worst >= 3:
            status = "gap"
        else:
            status = "partial"

        hits.append({
            "obligation_id": ob["obligation_id"],
            "law": ob["law"],
            "clause": ob["clause"],
            "status": status,
            "penalty_ceiling_inr": ob["penalty_ceiling_inr"],
            "rationale": "; ".join(ob["triggers"][fid]["note"] for fid in triggered),
            "triggering_finding_ids": triggered,
        })
    return hits


def dpdp_readiness_score(hits, all_obligation_count=None):
    """0-100. Penalizes gaps more than partials; weights by penalty ceiling."""
    if not hits:
        return 100
    total_penalty = sum(h["penalty_ceiling_inr"] for h in hits)
    gap_penalty = sum(
        h["penalty_ceiling_inr"] * (1.0 if h["status"] == "gap" else 0.4)
        for h in hits
    )
    # Normalize: ratio of weighted gaps to total mapped exposure, inverted.
    ratio = gap_penalty / total_penalty if total_penalty else 0
    score = round(100 * (1 - ratio))
    return max(0, min(100, score))
```

> **Reality check — do not turn the penalty ceiling into a fake precise number.** Showing "your exposure is ₹187,43,21,000" is dishonest precision; the Board sets penalties case by case on nature, gravity, and duration. Always present it as a *ceiling band* ("up to ₹250 crore") and say the actual figure is at the Board's discretion. Fake precision is the fastest way to lose a knowledgeable judge's trust.

### 5.5 The compliance brief (regional languages)

Reuse `chatbot.py`'s provider chain. Feed the obligation hits, not the raw findings, so the brief is about *legal consequence*, not technical detail.

```python
# backend/compliance/brief_generator.py
def build_compliance_prompt(url, hits, readiness_score, language="english"):
    gap_lines = "\n".join(
        f"- {h['clause']} ({h['law']}): {h['status'].upper()} — up to ₹{h['penalty_ceiling_inr']//10000000} crore. {h['rationale']}"
        for h in hits
    )
    return f"""You are PRAWL, a compliance assistant for Indian small businesses.
Website: {url} | DPDP Readiness: {readiness_score}/100
Compliance gaps mapped to law:
{gap_lines or 'No mapped compliance gaps.'}

Write 4 short sentences for a non-technical Indian business owner:
1. State the readiness score and the single biggest legal risk.
2. Name the most urgent obligation and its rupee penalty ceiling.
3. Mention that a customer-data breach triggers BOTH a 6-hour CERT-In clock and a 72-hour DPDP clock.
4. Give one concrete action to take this week.
End with: "This is indicative guidance, not legal advice."
Language: {LANGUAGE_INSTRUCTIONS.get(language, 'Plain English')}.
Plain paragraph. No jargon. No bullet points."""
```

### 5.6 API and storage changes

- New route `POST /api/compliance` accepting a prior scan id or a fresh URL; returns `{readiness_score, hits[], brief}`.
- Or — preferred — fold it into the existing scan response so one scan returns everything. Add a `compliance` key.
- New SQLite table `compliance_history(scan_id, readiness_score, gap_count, created_at)` so the existing Chart.js history can plot a second line: technical score vs DPDP readiness over time. That dual-line chart is a strong, cheap visual.

### 5.7 Testing

- Unit-test the mapper with synthetic finding lists: empty (→ 100), one low-weight partial, one high-weight gap, one gap on an exploit path.
- Golden-file test the obligation JSON against the schema so a malformed edit fails loudly.
- Manually verify three real findings map to the clause a human would expect.

---

## 6. Feature 2 — agentic attack-path reasoning engine

### 6.1 What it is and why it is novel

A scanner returns a flat list. A penetration tester returns a *story*: "here is how I would chain these to actually steal your data." This feature automates that chaining for non-technical users, and uses it to score real-world exploitability instead of summing isolated severities.

The pitch line: *"We score real-world exploitability of finding combinations — convergence on a crown jewel — not isolated checkbox severity."*

### 6.2 The central design decision — grounded, not generated

This is the part that survives Q&A, so internalize it.

There are two ways to build an attack graph:

1. **Let the LLM generate the whole graph** — fast to prototype, fatal in a demo. The model invents plausible-sounding edges that do not follow from the actual scan. A technical judge asks "why is this edge here?" and your answer is "the model said so." You lose.
2. **Hybrid — rule-grounded topology, LLM narration** — the graph topology comes from a curated knowledge base of attack transitions, instantiated only where both endpoints trace back to real findings. The LLM only *describes* a path that already exists and *ranks* paths. It never draws an edge.

You build option 2. Always.

### 6.3 The attack-transition knowledge base

This is your real intellectual property for the feature — a small, curated dictionary of causal primitives, each grounded in an established framework so it is defensible. Reference frameworks (cite these, do not reinvent them):

- **MITRE ATT&CK** — adversary tactics and techniques (e.g. T1190 Exploit Public-Facing Application, T1212 credential access). Your transitions correspond to ATT&CK technique chains.
- **CAPEC (Common Attack Pattern Enumeration and Classification)** — attack patterns (e.g. CAPEC-66 SQL Injection, CAPEC-545 Pull Data from System Resources). Tag each transition with a CAPEC id.

Store as `data/attack_transitions.json`. Each transition: a precondition (a `finding_id` or a capability), a resulting capability, a confidence, and a framework reference.

```json
{
  "transitions": [
    {
      "transition_id": "git_to_source",
      "precondition": {"type": "finding", "id": "exposed_git_dir"},
      "yields":       {"type": "capability", "id": "source_code_disclosure"},
      "confidence": 0.95,
      "capec": "CAPEC-150",
      "attack": "T1213",
      "rationale": "An exposed .git directory lets an attacker reconstruct full source and history."
    },
    {
      "transition_id": "source_to_creds",
      "precondition": {"type": "capability", "id": "source_code_disclosure"},
      "yields":       {"type": "capability", "id": "leaked_db_credentials"},
      "confidence": 0.55,
      "requires_evidence": "credential_pattern_in_source",
      "capec": "CAPEC-637",
      "attack": "T1552",
      "rationale": "Source often contains hardcoded database credentials."
    },
    {
      "transition_id": "creds_plus_port_to_dbaccess",
      "precondition": {"type": "all_of",
                       "ids": ["leaked_db_credentials", "open_port_mysql"]},
      "yields":       {"type": "capability", "id": "database_access"},
      "confidence": 0.9,
      "capec": "CAPEC-555",
      "attack": "T1078",
      "rationale": "Leaked credentials plus a reachable database port equals direct access."
    },
    {
      "transition_id": "sqli_to_dbaccess",
      "precondition": {"type": "finding", "id": "sql_injection"},
      "yields":       {"type": "capability", "id": "database_access"},
      "confidence": 0.9,
      "capec": "CAPEC-66",
      "attack": "T1190",
      "rationale": "SQL injection grants direct read/write to the backing database."
    },
    {
      "transition_id": "dbaccess_to_pii_breach",
      "precondition": {"type": "capability", "id": "database_access"},
      "yields":       {"type": "impact", "id": "customer_pii_breach"},
      "confidence": 0.9,
      "capec": "CAPEC-545",
      "attack": "T1530",
      "rationale": "Database access enables exfiltration of customer personal data."
    }
  ]
}
```

The full starter table (15 transitions) is in **Appendix B**. Note the `requires_evidence` field on `source_to_creds`: that edge is only instantiated if a regex over the actually-leaked source finds a credential pattern. This is the difference between a grounded graph and a fantasy.

### 6.4 The graph model

Use `networkx.DiGraph`. Four node layers (matching the visualization taxonomy): `entry`, `finding`, `capability`, `impact`. Goal node(s) are `impact` nodes; the canonical one is `customer_pii_breach`, which carries the DPDP penalty band — this is the fusion point with Feature 1.

```python
# backend/attackpath/attack_graph.py
import json
import networkx as nx
from pathlib import Path

_TRANSITIONS = json.loads((Path(__file__).parent.parent / "data" / "attack_transitions.json").read_text())["transitions"]

IMPACT_PENALTY = {
    "customer_pii_breach": 2_500_000_000,   # ties to DPDP reasonable-safeguards ceiling
}


def _credential_pattern_present(findings):
    """Cheap evidence gate for the source->creds transition."""
    import re
    pat = re.compile(r"(DB_PASSWORD|password\s*=|mysqli_connect|mongodb\+srv|AKIA[0-9A-Z]{16})", re.I)
    for f in findings:
        blob = (f.evidence or {}).get("leaked_source", "")
        if pat.search(blob or ""):
            return True
    return False


def build_attack_graph(findings):
    present_finding_ids = {f.finding_id for f in findings if f.status in ("fail", "warning")}
    G = nx.DiGraph()

    # Seed finding nodes
    for f in findings:
        if f.status in ("fail", "warning"):
            G.add_node(f.finding_id, layer="finding", label=f.check, severity=f.severity.value)

    # Iteratively instantiate transitions whose preconditions are satisfied
    have_creds_evidence = _credential_pattern_present(findings)
    changed = True
    satisfied = set(present_finding_ids)

    while changed:
        changed = False
        for t in _TRANSITIONS:
            pre = t["precondition"]
            ok = False
            if pre["type"] == "finding":
                ok = pre["id"] in satisfied
            elif pre["type"] == "capability":
                ok = pre["id"] in satisfied
            elif pre["type"] == "all_of":
                ok = all(i in satisfied for i in pre["ids"])

            if t.get("requires_evidence") == "credential_pattern_in_source" and not have_creds_evidence:
                ok = False

            yld = t["yields"]["id"]
            if ok and yld not in satisfied:
                satisfied.add(yld)
                layer = t["yields"]["type"]   # "capability" | "impact"
                G.add_node(yld, layer=layer, label=yld.replace("_", " ").title(),
                           penalty_ceiling_inr=IMPACT_PENALTY.get(yld))
                changed = True

            if ok:
                # add the edge(s) into the yielded node
                sources = pre["ids"] if pre["type"] == "all_of" else [pre["id"]]
                for s in sources:
                    if s in satisfied:
                        G.add_edge(s, yld, confidence=t["confidence"],
                                   transition_id=t["transition_id"], rationale=t["rationale"],
                                   capec=t.get("capec"), attack=t.get("attack"))
    return G


def to_cytoscape_json(G):
    nodes = [{"data": {"id": n, **d}} for n, d in G.nodes(data=True)]
    edges = [{"data": {"id": f"{u}->{v}", "source": u, "target": v, **d}}
             for u, v, d in G.edges(data=True)]
    return {"nodes": nodes, "edges": edges}
```

### 6.5 Path-based exploitability scoring — retiring `calculate_score()`

The old additive score is replaced by reachability to the goal node. The intuition: a finding that leads nowhere scores far lower than one that sits on a confident, short path to a customer-data breach; and *multiple converging paths* are worse than the sum.

```python
# backend/attackpath/path_scorer.py
import networkx as nx

GOAL = "customer_pii_breach"


def exploitability(G):
    """Returns dict: 0-100 risk, plus the evidence behind it."""
    if GOAL not in G:
        return {"risk": _structural_risk(G), "reachable": False, "paths": []}

    entry_nodes = [n for n, d in G.nodes(data=True) if d.get("layer") == "finding"
                   and G.in_degree(n) == 0]
    all_paths = []
    for src in entry_nodes:
        for path in nx.all_simple_paths(G, src, GOAL, cutoff=8):
            conf = 1.0
            for a, b in zip(path, path[1:]):
                conf *= G[a][b]["confidence"]
            all_paths.append({"path": path, "length": len(path) - 1, "confidence": round(conf, 3)})

    if not all_paths:
        return {"risk": _structural_risk(G), "reachable": False, "paths": []}

    best = max(all_paths, key=lambda p: p["confidence"])
    distinct_routes = len({tuple(p["path"]) for p in all_paths})

    # Risk rises with best-path confidence, shortness, and number of converging routes.
    base = best["confidence"] * 100
    shortness_bonus = max(0, (5 - best["length"])) * 3
    convergence_bonus = min(15, (distinct_routes - 1) * 5)
    risk = min(100, round(base + shortness_bonus + convergence_bonus))

    return {"risk": risk, "reachable": True,
            "best_path": best, "distinct_routes": distinct_routes, "paths": all_paths}


def _structural_risk(G):
    """No path to goal: fall back to weighted finding severities, capped low."""
    weights = {"critical": 12, "high": 8, "medium": 4, "low": 1, "info": 0, "none": 0}
    s = sum(weights.get(d.get("severity", "none"), 0)
            for _, d in G.nodes(data=True) if d.get("layer") == "finding")
    return min(60, s)   # un-chained findings can never score "critical" risk
```

> **Reality check.** `nx.all_simple_paths` is exponential on dense graphs. Your graphs are tiny (single-digit to low-double-digit nodes), so it is fine — but cap `cutoff` and never let an untrusted/huge finding set blow it up. If you ever scale, switch to shortest-path plus a max-flow style convergence metric.

### 6.6 The narrative

The LLM walks an *existing* path and narrates it. It receives the node sequence and the per-edge rationale, and produces plain (and regional-language) prose. It is forbidden from adding steps.

```python
def build_narrative_prompt(best_path, node_labels, language="english"):
    steps = " -> ".join(node_labels[n] for n in best_path["path"])
    return f"""You are PRAWL explaining a real attack path to a non-technical Indian business owner.
The verified attack path is: {steps}
Confidence: {int(best_path['confidence']*100)}%.
Explain in 3-4 plain sentences how an attacker walks this exact path, ending at a customer-data breach.
Do NOT invent any step not in the path above.
Language: {language}."""
```

### 6.7 Data and datasets for Feature 2

| Source | Purpose | Cost |
|---|---|---|
| Your hand-built `attack_transitions.json` | The graph topology | Free, ~1 day to author |
| MITRE ATT&CK (attack.mitre.org) | Grounding/citation for transitions | Free, public |
| CAPEC (capec.mitre.org) | Attack-pattern ids per transition | Free, public |
| National Vulnerability Database (NVD) CVE feed | *Optional* — enrich `software_version_disclosure` findings with known CVEs to add more entry nodes | Free API, rate-limited |

You do not need to download ATT&CK/CAPEC as datasets; you reference their identifiers in your transition table so the grounding is auditable.

---

## 7. Feature 3 — attack-path graph visualization

### 7.1 The contract

Feature 3 is a pure renderer of the JSON Feature 2 emits (`to_cytoscape_json`). Keep the boundary clean: the frontend computes nothing about risk; it only draws.

### 7.2 Library choice

| Option | Verdict |
|---|---|
| **Cytoscape.js + cytoscape-dagre** | Build this. Purpose-built for directed graphs, layered left-to-right layout for free, styling by node class, hover and click handlers. |
| Mermaid `graph LR` | Acceptable week-1 prototype to validate the look; not interactive enough for the final demo. |
| D3 force-directed | Avoid. A physics blob discards the direction that *is* the meaning of an attack path. |

Load from the CDN allowlist:

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/dagre/0.8.5/dagre.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape-dagre/2.5.0/cytoscape-dagre.min.js"></script>
```

### 7.3 Renderer skeleton

```javascript
// frontend/static/js/attack_graph.js
function renderAttackGraph(containerId, graphJson, bestPath) {
  cytoscape.use(window.cytoscapeDagre);

  const LAYER_COLOR = {
    finding:    '#E24B4A',   // red — vulnerability
    capability: '#EF9F27',   // amber — capability gained
    impact:     '#A32D2D',   // dark red — crown-jewel impact
    entry:      '#378ADD'
  };

  const onPath = new Set(bestPath ? bestPath.path : []);

  const cy = cytoscape({
    container: document.getElementById(containerId),
    elements: graphJson,
    layout: { name: 'dagre', rankDir: 'LR', nodeSep: 40, rankSep: 90 },
    style: [
      { selector: 'node', style: {
          'background-color': ele => LAYER_COLOR[ele.data('layer')] || '#888',
          'label': 'data(label)', 'color': '#fff', 'font-size': 11,
          'text-wrap': 'wrap', 'text-max-width': 120,
          'text-valign': 'center', 'width': 'label', 'padding': 10,
          'shape': 'round-rectangle'
      }},
      { selector: 'node[penalty_ceiling_inr]', style: {
          'border-width': 3, 'border-color': '#501313'
      }},
      { selector: 'edge', style: {
          'width': ele => 1 + 3 * ele.data('confidence'),
          'line-color': '#bbb', 'target-arrow-color': '#bbb',
          'target-arrow-shape': 'triangle', 'curve-style': 'bezier'
      }},
      // highlight the critical path
      { selector: 'edge.critical', style: { 'line-color': '#E24B4A', 'target-arrow-color': '#E24B4A', 'width': 3 } },
      { selector: 'node.critical', style: { 'border-width': 3, 'border-color': '#E24B4A' } }
    ]
  });

  // mark critical path
  cy.nodes().forEach(n => { if (onPath.has(n.id())) n.addClass('critical'); });
  cy.edges().forEach(e => { if (onPath.has(e.source().id()) && onPath.has(e.target().id())) e.addClass('critical'); });

  // click a node -> ask the chatbot to explain it (reuses existing chatbot)
  cy.on('tap', 'node', evt => {
    const id = evt.target.id();
    askChatbot(`Explain the attack-graph node "${id}" and how to break this path.`);
  });

  return cy;
}
```

### 7.4 Frontend integration

- Add a `<div id="attack-graph" style="height:480px"></div>` card to `index.html`, below the findings list.
- When `/api/scan` returns, if `result.attack_graph` is present, call `renderAttackGraph('attack-graph', result.attack_graph, result.exploit.best_path)`.
- Show the exploitability risk number and the narrative beside the graph.
- Make impact nodes show the DPDP penalty band on hover (tooltip from `penalty_ceiling_inr`) — that single hover interaction tells the whole fused story.

> **Reality check — accessibility and the empty state.** Two things demos forget: (1) when there is no path to the goal (a well-secured site), render a friendly "no viable attack path found" state, not an empty black box; (2) a graph is invisible to a screen reader — also render the path as an ordered text list. Both cost ten minutes and both get noticed by good judges.

---

## 8. Feature 4 — lookalike / phishing-domain watch

### 8.1 What it is and why it is novel

You already pull Certificate Transparency (CT) logs from crt.sh to enumerate subdomains. This feature reuses that exact data source for a different question: *who is registering domains that impersonate this business?* Indian SMBs are impersonated constantly for UPI and payment fraud, so this is genuinely useful, not a checkbox.

The pitch line: *"We watch the same Certificate Transparency logs the attacker's fake domain shows up in — and we catch `razorpey.com` the day its certificate is issued."*

### 8.2 Approach — three signals, combined

1. **Permutation generation** — from the real domain, generate plausible typosquats (character swaps, omissions, homoglyphs, common TLD swaps, hyphenation, brand-plus-keyword like `flipkart-offers`). Use **dnstwist**, the standard open-source OSINT typosquat engine, rather than hand-rolling permutations.
2. **Existence check** — for each candidate, check whether it actually exists: a CT-log hit on crt.sh (a certificate was issued for it) and/or a DNS resolution. A permutation nobody registered is noise; a registered one is a signal.
3. **Threat scoring** — rank existing impersonators by how dangerous they look: does it resolve, does it have a live certificate, how young is the domain (new registrations are more suspicious — use WHOIS creation date if available), does its content mention the brand or a payment flow.

> **Reality check — false positives will swamp you if you skip step 2.** dnstwist alone generates hundreds of permutations, almost all unregistered. Reporting all of them as "threats" is noise that destroys credibility. The product is the *filter*: only surface permutations that actually exist (CT hit or DNS resolution). State this filter explicitly in the demo — it shows judgment.

### 8.3 Architecture

```python
# backend/phishing/permutations.py
def generate_permutations(domain):
    """Wrap dnstwist's fuzzing. Returns list of candidate domains."""
    import dnstwist
    fuzz = dnstwist.Fuzzer(domain)
    fuzz.generate()
    return [e['domain'] for e in fuzz.domains if e['domain'] != domain]
```

```python
# backend/phishing/ct_monitor.py  (reuses the crt.sh pattern already in advanced_scanner.py)
import requests

def domain_exists_in_ct(candidate):
    """A certificate issued for the candidate is strong evidence it is live."""
    try:
        r = requests.get(f"https://crt.sh/?q={candidate}&output=json",
                         headers={'User-Agent': 'PRAWL-Scanner/1.0'}, timeout=12)
        return r.status_code == 200 and len(r.json()) > 0
    except Exception:
        return False


def resolves(candidate):
    import socket
    try:
        socket.gethostbyname(candidate)
        return True
    except Exception:
        return False
```

```python
# backend/phishing/impersonator_scorer.py
def score_impersonators(real_domain, candidates):
    results = []
    for c in candidates:
        ct = domain_exists_in_ct(c)
        dns = resolves(c)
        if not (ct or dns):
            continue                       # the all-important filter
        threat = 0
        threat += 40 if ct else 0          # has a certificate -> can serve HTTPS phishing
        threat += 30 if dns else 0         # resolves -> live
        threat += 30 if any(k in c for k in ("login", "pay", "secure", "offers", "verify")) else 0
        results.append({"domain": c, "has_cert": ct, "resolves": dns, "threat": min(100, threat)})
    return sorted(results, key=lambda x: x["threat"], reverse=True)
```

### 8.4 Continuous-monitoring hook

This feature is most valuable *over time* — a new impersonator appearing next week is the real alert. Persist seen impersonators in SQLite (`impersonators(real_domain, fake_domain, first_seen, threat)`) and, when the (deferred) scheduler re-runs, diff against the stored set and flag *new* appearances. Even without the scheduler, store results so a repeat manual scan shows what is new.

### 8.5 Visualization — keep it OUT of the attack graph

Do not put impersonator domains on the attack-path graph. It is a different threat class (external impersonation, not a path through your own infrastructure). Give it its own simple panel: a ranked table, or a small radial with the real domain in the center and impersonators around it sized by threat. Two clean visuals beat one muddled one — and resisting the urge to over-stuff reads as product judgment.

### 8.6 Datasets and sources for Feature 4

| Source | Purpose | Cost / caveat |
|---|---|---|
| dnstwist (library) | Typosquat permutation generation | Free, pip-installable |
| crt.sh Certificate Transparency | Existence check via issued certificates | Free, public; be gentle with rate |
| DNS resolution | Existence check (live domains) | Free |
| WHOIS (e.g. python-whois) | Domain age — new domains are more suspicious | Free but rate-limited and flaky; optional |
| PhishTank / OpenPhish feeds | Cross-reference candidates against known-phishing lists | Free tiers exist; require signup/API key; optional enrichment |

---

## 9. Unified API surface

Prefer one rich scan response over many endpoints — fewer round trips, simpler frontend.

```
POST /api/scan
  body: { url, language, consent_active_scan: bool }
  returns:
  {
    "url": "...",
    "scanned_at": "...",
    "findings": [ {finding_id, check, status, severity, details, fix, on_exploit_path}, ... ],

    "exploit": {                       // Feature 2
      "risk": 86,
      "reachable": true,
      "best_path": { "path": [...], "confidence": 0.81, "length": 2 },
      "distinct_routes": 2,
      "narrative": "An attacker would ..."
    },
    "attack_graph": { "nodes": [...], "edges": [...] },   // Feature 3 input

    "compliance": {                    // Feature 1
      "readiness_score": 41,
      "hits": [ {obligation_id, law, clause, status, penalty_ceiling_inr, rationale}, ... ],
      "brief": "Your readiness is 41/100 ...",
      "disclaimer": "Indicative guidance, not legal advice."
    },

    "impersonators": [                 // Feature 4
      {"domain": "razorpey.com", "has_cert": true, "resolves": true, "threat": 100}
    ],

    "technical_score": 58              // kept for backwards compatibility / history chart
  }
}
```

Other routes: `GET /api/history` (now returns both technical and DPDP-readiness series for the dual-line chart), and the existing chatbot/report routes extended to include the new sections.

---

## 10. Dependencies, extensions & infrastructure

### 10.1 New Python packages (add to `requirements.txt`)

```
networkx>=3.2          # attack graph (Feature 2)
dnstwist>=20240..      # typosquat permutations (Feature 4)
python-whois>=0.9      # optional domain age (Feature 4)
```

Already present and reused: `requests`, `groq`/LLM clients, `Flask`, `Flask-Limiter`, `reportlab`.

### 10.2 Frontend libraries (CDN, already allowlisted)

```
cytoscape 3.28.x, dagre 0.8.x, cytoscape-dagre 2.5.x   # Feature 3
chart.js (already present)                              # dual-line history
```

### 10.3 External services / APIs

| Service | Used by | Key needed | Notes |
|---|---|---|---|
| Groq (Llama 3.3) | F1 briefs, F2 narrative | Yes (free tier) | Mind rate limits — up to 4 generations per scan |
| crt.sh | F2 (subdomains), F4 | No | Public; throttle politely |
| NVD CVE API | F2 (optional enrichment) | Optional | Rate-limited |
| PhishTank / OpenPhish | F4 (optional) | Yes (free) | Optional enrichment only |

### 10.4 Environment variables (additions)

```
GROQ_API_KEY=...            # existing
NVD_API_KEY=...             # optional (Feature 2 enrichment)
PHISHTANK_API_KEY=...       # optional (Feature 4 enrichment)
PRAWL_ENABLE_ACTIVE_SCAN=false   # global kill-switch for SQLMap/Nikto without consent
```

### 10.5 Docker note

Feature 2's graph engine, Feature 1's mapper, and Feature 4's permutation logic are pure Python — no Docker needed. They run inside the existing Flask process. Only the existing active scanners (Nmap/Nikto/SQLMap) need Docker, unchanged.

---

## 11. Datasets & external sources (consolidated)

You asked specifically about datasets. The honest answer: **three of the four features need no downloaded dataset — they need hand-built knowledge bases**, which is *more* defensible because it is your own work, not a borrowed corpus.

| Feature | "Dataset" | Type | How you get it |
|---|---|---|---|
| F1 Compliance | `dpdp_obligations.json` | Hand-built mapping | Author from the DPDP Act 2023, DPDP Rules 2025, CERT-In Directions 2022 (public legal texts) |
| F2 Attack-path | `attack_transitions.json` | Hand-built KB | Author, grounded in MITRE ATT&CK + CAPEC identifiers (public) |
| F2 (optional) | NVD CVE feed | Live API | National Vulnerability Database API |
| F3 Graph | none | — | Pure renderer of F2 output |
| F4 Phishing | dnstwist permutations + crt.sh CT logs | Generated + live | dnstwist library + crt.sh; optional PhishTank/OpenPhish lists |

The legal texts you need to read once to author Appendix A: the DPDP Act 2023 (gazette), the DPDP Rules 2025 (notified 13 November 2025), and the CERT-In Directions of 28 April 2022. All public.

---

## 12. Security, ethics & legal safeguards

This is not optional boilerplate. You are shipping a tool that runs active scans (SQLMap, Nikto) and enumerates domains. Mishandled, it is both an ethics problem and a personal legal exposure for *you*.

1. **Mandatory, loud authorization gate.** Active scanning (SQLMap, Nikto, port probing) must be gated behind an explicit, unticked-by-default consent control affirming the user owns or has written permission to test the target. The `PRAWL_ENABLE_ACTIVE_SCAN` kill-switch and the per-scan `consent_active_scan` flag enforce this. Passive checks (headers, SSL, CT logs) are lower-risk but still scope them to declared ownership.
2. **Rate limiting stays on.** Keep Flask-Limiter; unauthenticated active scans are an abuse vector.
3. **The compliance disclaimer is mandatory** on every compliance output: indicative guidance, not legal advice. (See 5.2.)
4. **Phishing watch is read-only OSINT.** It only *observes* public CT logs and DNS. It must never probe, scrape credentials from, or interact with a suspected impersonator domain. Detect and report; do not engage.
5. **Responsible-disclosure framing.** If a scan of an authorized target finds a critical issue, present it as something for the owner to fix — never as an exploit recipe. The attack narrative explains *that* a path exists and *how to break it*, not a copy-paste exploit.
6. **Data minimization, eat your own dog food.** You are building a DPDP-compliance tool; store scan results with the same restraint you preach. Do not retain leaked-source snippets longer than needed to render the result.

> **Reality check.** The fastest way to turn an impressive demo into a disqualification is to scan a domain you do not own, live, on stage. Demo against a target you control or a deliberately vulnerable test app (see §14). Never point it at a real third party "to show it works."

---

## 13. Build roadmap & phasing

Build the headless logic before the pixels. Three of four features are pure Python you can unit-test with zero frontend.

**Phase 0 — Foundation (do this first, ~1 day)**
- Add `finding_id` to every finding in `scanner.py`.
- Create `core/schemas.py` and `core/finding_ids.py`.
- This unblocks everything else.

**Phase 1 — Feature 2 core (the spine, ~2 days)**
- Author `attack_transitions.json` (start with the 15 in Appendix B).
- Build `attack_graph.py`, `path_scorer.py`. Unit-test headless with synthetic findings.
- Retire `calculate_score()`; wire `exploitability()` into the scan response.

**Phase 2 — Feature 1 (the headline, ~2 days)**
- Author `dpdp_obligations.json` (Appendix A).
- Build `compliance_mapper.py`, `brief_generator.py`. Unit-test.
- Wire the `on_exploit_path` coupling from Feature 2.
- Add the dual-line history chart.

**Phase 3 — Feature 3 (the demo centerpiece, ~1.5 days)**
- Drop in Cytoscape.js + dagre. Render the JSON from Phase 1.
- Critical-path highlight, click-to-chatbot, impact-node penalty hover.
- Empty-state + screen-reader path list.

**Phase 4 — Feature 4 (the wow, ~1 day)**
- `permutations.py` + `ct_monitor.py` + `impersonator_scorer.py`.
- The existence filter is the whole point — get it right.
- Separate panel, not the graph.

**Phase 5 — Fusion, polish, safety (~1 day)**
- The disclaimer, the consent gate, the unified response, the PDF sections.
- Rehearse the joined narrative: finding → path → ₹ penalty → fix.

Total: roughly 8–9 focused days. Cut Feature 4 first if time runs short; Features 1+2+3 together are the defensible core.

---

## 14. Testing & validation strategy

- **Unit tests, headless.** Features 1, 2, 4 are pure functions over data — test them with synthetic finding lists and golden outputs. No network, no browser. This is why you build the logic first.
- **Schema validation.** Golden-file the two JSON knowledge bases against their schemas so a malformed hand-edit fails CI loudly.
- **Deliberately vulnerable target for end-to-end.** Run the full pipeline against a local instance of a known-vulnerable app — OWASP Juice Shop or Damn Vulnerable Web Application (DVWA) in Docker — which you control. This safely produces real findings that chain into a real attack path, perfect for the demo.
- **Adversarial check on the graph.** Feed a finding set with NO path to the goal and confirm: graph shows the empty state, exploitability falls back to capped structural risk, compliance shows fewer gaps. Demonstrating the *secure* case is as convincing as the broken one.
- **LLM guardrail test.** Confirm the narrative never introduces a node absent from `best_path` (sample several runs; the prompt forbids it, but verify).

---

## 15. Risk register & known limitations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| LLM hallucinates an attack edge | Medium | High (credibility) | Topology is rule-built; LLM only narrates. Never let it draw edges. |
| Fragile string matching on `check` labels | High if skipped | High | Phase 0 `finding_id` enum. |
| Phishing false-positive flood | High if filter skipped | High | Existence filter (CT/DNS) before reporting. |
| Compliance mapping is wrong / over-claims | Medium | High (legal + trust) | Disclaimer everywhere; ceiling bands not precise figures; cite clauses you verified. |
| `all_simple_paths` blows up | Low (tiny graphs) | Medium | Cap cutoff; switch to shortest-path if scaling. |
| LLM rate limits (4 calls/scan) | Medium | Medium | Cache, batch, degrade to rule-based fallback (already in chatbot.py). |
| Scanning an unauthorized domain in demo | Low if disciplined | Fatal (disqualification/legal) | Consent gate + demo only against controlled targets. |
| crt.sh throttling under load | Medium | Low | Cache results; back off politely. |

Honest limitations to state up front (stating them builds credibility):
- The transition KB is curated, not exhaustive — it covers common SMB web-attack surface, not every technique.
- The compliance mapping is indicative, built from public legal texts, not a substitute for counsel.
- Exploitability confidence is heuristic, derived from curated edge confidences, not from live exploitation.

---

## 16. Appendix A — DPDP obligation table (starter, extend to taste)

| obligation_id | Law / clause | Penalty ceiling | Triggering finding_ids |
|---|---|---|---|
| dpdp_reasonable_safeguards | DPDP Act s.8(4)/(5) — reasonable security safeguards | ₹250 crore | open_port_mysql, open_port_postgres, open_port_mongodb, open_port_redis, exposed_env_file, exposed_git_dir, sql_injection, insecure_cookies, missing_hsts |
| dpdp_breach_notification | DPDP Act s.8(6) + Rule 7 — notify Board within 72h, individuals without delay | ₹200 crore | data_breach_history |
| dpdp_data_in_transit | DPDP Act s.8(4) (read with ISO 27001 ref in Privacy Rules) — protect data in transit | ₹250 crore | no_https_redirect, missing_hsts, ssl_expired, insecure_cookies |
| dpdp_access_control | DPDP Act s.8(4) — restrict access to personal data | ₹250 crore | open_port_ssh, open_port_rdp, cors_wildcard |
| dpdp_secret_exposure | DPDP Act s.8(4) — prevent unauthorized access via leaked secrets | ₹250 crore | exposed_env_file, exposed_git_dir |
| certin_incident_reporting | CERT-In Directions 2022 — 6-hour cyber-incident reporting | ₹1 lakh + s.70B liability | data_breach_history |
| certin_log_retention | CERT-In Directions 2022 — 180-day log retention in India | ₹1 lakh + s.70B liability | (advisory / readiness) |
| dpdp_children_data | DPDP Act — verifiable consent for children's data | ₹200 crore | (advisory if site collects children's data) |

Author the JSON form (§5.3) from this table. Each row becomes one obligation object. Verify each clause against the source text before you ship — do not cite a section number you have not read.

## 17. Appendix B — attack-transition table (starter set of 15)

| transition_id | precondition | yields | conf | CAPEC / ATT&CK |
|---|---|---|---|---|
| git_to_source | exposed_git_dir | source_code_disclosure | 0.95 | CAPEC-150 / T1213 |
| env_to_secrets | exposed_env_file | leaked_db_credentials | 0.85 | CAPEC-637 / T1552 |
| source_to_creds | source_code_disclosure (+evidence) | leaked_db_credentials | 0.55 | CAPEC-637 / T1552 |
| creds_plus_port_to_dbaccess | leaked_db_credentials + open_port_mysql | database_access | 0.90 | CAPEC-555 / T1078 |
| creds_plus_pg_to_dbaccess | leaked_db_credentials + open_port_postgres | database_access | 0.90 | CAPEC-555 / T1078 |
| sqli_to_dbaccess | sql_injection | database_access | 0.90 | CAPEC-66 / T1190 |
| mongo_open_to_dbaccess | open_port_mongodb | database_access | 0.80 | CAPEC-555 / T1190 |
| redis_open_to_dbaccess | open_port_redis | database_access | 0.75 | CAPEC-555 / T1190 |
| dbaccess_to_pii_breach | database_access | customer_pii_breach | 0.90 | CAPEC-545 / T1530 |
| missing_csp_to_xss | missing_csp | stored_xss | 0.45 | CAPEC-592 / T1059 |
| xss_to_session_hijack | stored_xss | session_hijack | 0.60 | CAPEC-593 / T1539 |
| session_to_account_takeover | session_hijack | account_takeover | 0.70 | CAPEC-593 / T1078 |
| takeover_to_pii_breach | account_takeover | customer_pii_breach | 0.65 | CAPEC-545 / T1530 |
| rdp_open_to_foothold | open_port_rdp | server_foothold | 0.65 | CAPEC-555 / T1133 |
| foothold_to_pii_breach | server_foothold | customer_pii_breach | 0.70 | CAPEC-545 / T1530 |

Capabilities/impacts referenced: source_code_disclosure, leaked_db_credentials, database_access, stored_xss, session_hijack, account_takeover, server_foothold (capabilities); customer_pii_breach (impact, carries the DPDP penalty band).

## 18. Appendix C — glossary & abbreviations

| Term | Expansion / meaning |
|---|---|
| CAPEC | Common Attack Pattern Enumeration and Classification — MITRE catalogue of attack patterns |
| CERT-In | Indian Computer Emergency Response Team — national cyber-incident agency under IT Act s.70B |
| CORS | Cross-Origin Resource Sharing — browser policy controlling cross-site requests |
| CSP | Content-Security-Policy — HTTP header mitigating cross-site scripting |
| CT | Certificate Transparency — public logs of issued TLS certificates (queried via crt.sh) |
| CVE | Common Vulnerabilities and Exposures — public catalogue of known software vulnerabilities |
| Data Fiduciary | DPDP term for the entity deciding how/why personal data is processed (like a controller) |
| Data Principal | DPDP term for the individual the personal data is about |
| DPDP Act | Digital Personal Data Protection Act, 2023 — India's data protection law |
| DPDP Rules | Digital Personal Data Protection Rules, 2025 — operational rules, notified 13 Nov 2025 |
| dnstwist | Open-source typosquat / domain-permutation OSINT tool |
| HSTS | HTTP Strict-Transport-Security — header enforcing HTTPS |
| LLM | Large Language Model |
| MITRE ATT&CK | Public knowledge base of adversary tactics and techniques |
| Nmap | Network Mapper — port and service scanner |
| NTP | Network Time Protocol — clock synchronization |
| NVD | National Vulnerability Database — US CVE feed with severity scores |
| OSINT | Open-Source Intelligence — gathering from public sources |
| PII | Personally Identifiable Information |
| SMB | Small and Medium Business |
| SQL | Structured Query Language |
| SQLMap | Automated SQL-injection testing tool |
| SSL/TLS | Secure Sockets Layer / Transport Layer Security — transport encryption |
| UPI | Unified Payments Interface — India's real-time payment system |
| WHOIS | Protocol/service for domain registration records |
| XFO | X-Frame-Options — header mitigating clickjacking |

---

*End of specification. Build the spine (Phase 0–1) before anything visual. The four features are individually borrowed and collectively novel — keep telling the joined story: technical finding to grounded attack path to Indian legal consequence in rupees to a plain-language fix.*
