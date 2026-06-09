"""Tests for backend/rag.py — the pure-Python RAG retrieval pipeline.

These exercise the TF-IDF retriever (the always-available fallback), so they
run deterministically without sentence-transformers installed.
"""
import rag


SCAN = {
    "url": "https://shop.local",
    "score": 42,
    "risk_level": "HIGH",
    "ai_summary": "Several issues found.",
    "findings": [
        {
            "check": "SSL Certificate",
            "status": "fail",
            "severity": "high",
            "details": "Certificate expired three weeks ago.",
            "fix": "Renew the TLS certificate.",
        },
        {
            "check": "Security Headers",
            "status": "warn",
            "severity": "medium",
            "details": "Missing Content-Security-Policy header.",
            "fix": "Add a CSP header.",
        },
    ],
    "advanced_scan": {
        "nmap": {
            "risk_findings": [
                {
                    "port": 3306,
                    "service": "mysql",
                    "description": "MySQL database exposed to the internet.",
                    "severity": "critical",
                    "version": "8.0.32",
                }
            ]
        },
        "nikto": {
            "vulnerabilities": [
                {
                    "description": "Outdated Apache version detected.",
                    "severity": "medium",
                    "reference": "CVE-2021-1234",
                }
            ]
        },
        "sqlmap": {
            "injectable": True,
            "dbms": "MySQL",
            "parameters": ["cat"],
            "summary": "Boolean-based blind injection.",
        },
    },
}


# ── build_documents ───────────────────────────────────────────────────────

def test_empty_scan_yields_no_documents():
    assert rag.build_documents({}) == []
    assert rag.build_documents(None) == []


def test_build_documents_covers_all_sources():
    ids = {d["id"] for d in rag.build_documents(SCAN)}
    assert "overview" in ids
    assert "finding-0" in ids and "finding-1" in ids
    assert "nmap-3306" in ids
    assert "nikto-0" in ids
    assert "sqlmap" in ids


def test_sqlmap_doc_skipped_when_not_injectable():
    scan = {"url": "x", "advanced_scan": {"sqlmap": {"injectable": False}}}
    ids = {d["id"] for d in rag.build_documents(scan)}
    assert "sqlmap" not in ids


# ── retrieve ──────────────────────────────────────────────────────────────

def test_retrieve_ranks_relevant_finding_first():
    results = rag.retrieve("Is my SSL certificate expired?", SCAN, k=3)
    assert results, "expected at least one retrieved document"
    top_doc = results[0][1]
    assert "SSL" in top_doc["text"] or top_doc["metadata"].get("check") == "SSL Certificate"
    # scores are sorted descending and strictly positive
    scores = [s for s, _ in results]
    assert scores == sorted(scores, reverse=True)
    assert all(s > 0 for s in scores)


def test_retrieve_returns_nothing_for_empty_scan():
    assert rag.retrieve("anything", {}, k=5) == []


def test_retrieve_respects_k():
    results = rag.retrieve("mysql database injection port", SCAN, k=2)
    assert len(results) <= 2


# ── get_sources ───────────────────────────────────────────────────────────

def test_get_sources_shape_and_dedup():
    sources = rag.get_sources("mysql exposed on port 3306", SCAN, k=5)
    assert sources
    for s in sources:
        assert set(s) == {"label", "type", "severity", "relevance"}
        assert isinstance(s["relevance"], float)
    labels = [s["label"] for s in sources]
    assert len(labels) == len(set(labels)), "labels should be de-duplicated"


# ── build_rag_context ─────────────────────────────────────────────────────

def test_build_rag_context_includes_header_and_details():
    ctx = rag.build_rag_context("Tell me about the database port", SCAN)
    assert "shop.local" in ctx
    assert "SCORE: 42" in ctx
    assert "RISK: HIGH" in ctx


def test_build_rag_context_no_scan():
    ctx = rag.build_rag_context("hello", {})
    assert "No scan data" in ctx


def test_build_rag_context_falls_back_for_vague_query():
    # A greeting matches no tokens; fallback should still surface findings,
    # highest-severity first (critical MySQL finding).
    ctx = rag.build_rag_context("hi there", SCAN)
    assert "MOST RELEVANT SCAN DETAILS" in ctx
    assert "MySQL" in ctx
