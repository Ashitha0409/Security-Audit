"""
engagement.py — penetration-test engagement framing for a PRAWL scan.

Syllabus Unit III: "planning a penetration test, structuring a penetration test, execution,
information sharing during a penetration test, reporting the results".
This module records, honestly, what a scan covered and what it did NOT do, orders the
fixes into a remediation plan, and serves the concept notes in data/concepts.json.
"""
import json
from pathlib import Path

_CONCEPTS_PATH = Path(__file__).parent / "data" / "concepts.json"


def load_concepts():
    try:
        return json.loads(_CONCEPTS_PATH.read_text(encoding="utf-8"))["concepts"]
    except Exception:
        return []


def concepts_for_findings(findings, limit=4):
    ids = {f.get("finding_id") for f in findings if f.get("status") in ("fail", "warning")}
    out = []
    for c in load_concepts():
        if ids & set(c.get("related_finding_ids", [])):
            out.append({k: c[k] for k in ("id", "unit", "title", "summary", "source")})
    return out[:limit]


RULES_OF_ENGAGEMENT = [
    "Scope is limited to the single hostname entered (no subdomain or IP-range expansion in the basic scan).",
    "Only scan systems you own or have written permission to test.",
    "Non-destructive: no exploitation, no brute-forcing, no denial-of-service, no data modification.",
    "Light-touch requests only: GET/OPTIONS, TCP connects to a short list of ports, DNS lookups.",
    "Findings are evidence-based; version-based CVE matches are indicators, not proof of exploitability.",
]

OUT_OF_SCOPE = [
    "Exploitation and post-exploitation (Metasploit/Meterpreter, privilege escalation)",
    "Memory-corruption exploit development (stack/SEH overflows, DEP/ASLR bypass), which needs binary access",
    "Social-engineering campaigns and physical / insider testing",
    "Authenticated testing behind a login, business-logic flaws, source-code review of your repository",
]


def build_methodology(page, findings):
    blocked = bool(getattr(page, "blocked", False))
    phases = [
        {"phase": "1. Planning & scoping", "status": "done",
         "detail": "Target, scope and rules of engagement fixed before scanning (see below). Authorisation is the scanner user's responsibility."},
        {"phase": "2. Information gathering", "status": "done",
         "detail": "DNS (MX/SPF/DMARC), TLS certificate, HTTP banners, CDN detection, robots.txt/security.txt."},
        {"phase": "3. Vulnerability analysis (passive)", "status": "limited" if blocked else "done",
         "detail": ("Headers, cookies, HTML source and version fingerprints." if not blocked else
                    "The target's bot protection returned a challenge page, so header/cookie/HTML analysis was skipped rather than guessed.")},
        {"phase": "4. Vulnerability analysis (active, non-destructive)", "status": "done",
         "detail": "Port connect checks, TLS downgrade test, CORS/TRACE probes, reflected-input marker, exposed-file signatures."},
        {"phase": "5. Exploitation", "status": "not_performed",
         "detail": "PRAWL does not exploit anything. CVE results are version matches against NVD / CISA KEV data."},
        {"phase": "6. Reporting", "status": "done",
         "detail": "Findings carry OWASP Top 10 + CWE tags, severity, evidence, fixes and a prioritised plan."},
    ]
    return {
        "framework": "Penetration-test lifecycle (planning, recon, vulnerability analysis, exploitation, reporting)",
        "phases": phases,
        "rules_of_engagement": RULES_OF_ENGAGEMENT,
        "out_of_scope": OUT_OF_SCOPE,
        "http_layer_assessed": not blocked,
    }


_PRIORITY = {
    "critical": "P1: fix today (within 24 h)",
    "high": "P1: fix today (within 24 h)",
    "medium": "P2: fix this week",
    "low": "P3: fix this month",
}


def remediation_plan(findings):
    """Ordered fix list: severity first, then by score impact."""
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    items = []
    for f in findings:
        if f.get("status") in ("fail", "warning") and f.get("severity") in rank:
            sev = f["severity"]
            items.append({"priority": _PRIORITY[sev], "severity": sev, "check": f["check"],
                          "fix": f.get("fix", ""), "owasp": f.get("owasp"), "cwe": f.get("cwe"),
                          "_k": (rank[sev], -(f.get("weight") or 0))})
    items.sort(key=lambda i: i["_k"])
    for i in items:
        i.pop("_k")
    return items
