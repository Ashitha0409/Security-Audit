"""
taxonomy.py — maps every PRAWL finding to the standard vocabulary a penetration-test
report uses: OWASP Top 10 (2021) category, CWE weakness id and the pen-test phase
in which the evidence was gathered.

Syllabus links (Vulnerability Assessment & Penetration Testing, Unit IV and Unit III):
  * "Overview of top web application security vulnerabilities / OWASP Top Ten"
  * "Vulnerability Analysis: Passive Analysis, Source Code Analysis"
  * "Reporting the results of a penetration test"
"""

OWASP_2021 = {
    "A01": "A01:2021 Broken Access Control",
    "A02": "A02:2021 Cryptographic Failures",
    "A03": "A03:2021 Injection",
    "A04": "A04:2021 Insecure Design",
    "A05": "A05:2021 Security Misconfiguration",
    "A06": "A06:2021 Vulnerable and Outdated Components",
    "A07": "A07:2021 Identification and Authentication Failures",
    "A08": "A08:2021 Software and Data Integrity Failures",
    "A09": "A09:2021 Security Logging and Monitoring Failures",
    "A10": "A10:2021 Server-Side Request Forgery",
}

# finding_id -> (OWASP key, CWE id, pen-test phase)
PHASE_PASSIVE = "Vulnerability analysis (passive)"
PHASE_ACTIVE  = "Vulnerability analysis (active, non-destructive)"
PHASE_RECON   = "Information gathering"

_MAP = {
    "ssl_expired":                   ("A02", "CWE-298", PHASE_PASSIVE),
    "ssl_expiring":                  ("A02", "CWE-298", PHASE_PASSIVE),
    "ssl_invalid":                   ("A02", "CWE-295", PHASE_PASSIVE),
    "weak_tls_protocol":             ("A02", "CWE-326", PHASE_ACTIVE),
    "no_https_redirect":             ("A02", "CWE-319", PHASE_PASSIVE),
    "missing_hsts":                  ("A05", "CWE-319", PHASE_PASSIVE),
    "weak_hsts":                     ("A05", "CWE-319", PHASE_PASSIVE),
    "missing_csp":                   ("A05", "CWE-693", PHASE_PASSIVE),
    "csp_unsafe_inline":             ("A05", "CWE-693", PHASE_PASSIVE),
    "missing_x_frame_options":       ("A05", "CWE-1021", PHASE_PASSIVE),
    "missing_x_content_type_options": ("A05", "CWE-693", PHASE_PASSIVE),
    "missing_referrer_policy":       ("A05", "CWE-200", PHASE_PASSIVE),
    "missing_permissions_policy":    ("A05", "CWE-693", PHASE_PASSIVE),
    "insecure_cookies":              ("A05", "CWE-614", PHASE_PASSIVE),
    "cors_wildcard":                 ("A05", "CWE-942", PHASE_ACTIVE),
    "software_version_disclosure":   ("A05", "CWE-200", PHASE_PASSIVE),
    "known_cve_software":            ("A06", "CWE-1104", PHASE_PASSIVE),
    "exposed_env_file":              ("A05", "CWE-538", PHASE_ACTIVE),
    "exposed_git_dir":               ("A05", "CWE-538", PHASE_ACTIVE),
    "exposed_sensitive_file":        ("A05", "CWE-538", PHASE_ACTIVE),
    "directory_listing":             ("A05", "CWE-548", PHASE_ACTIVE),
    "http_trace_enabled":            ("A05", "CWE-693", PHASE_ACTIVE),
    "reflected_xss":                 ("A03", "CWE-79",  PHASE_ACTIVE),
    "sql_injection":                 ("A03", "CWE-89",  PHASE_ACTIVE),
    "mixed_content":                 ("A02", "CWE-319", PHASE_PASSIVE),
    "login_form_over_http":          ("A02", "CWE-319", PHASE_PASSIVE),
    "missing_dmarc":                 ("A05", "CWE-290", PHASE_RECON),
    "missing_spf":                   ("A05", "CWE-290", PHASE_RECON),
    "redis_unauthenticated":         ("A07", "CWE-306", PHASE_ACTIVE),
    "data_breach_history":           ("A09", "CWE-200", PHASE_RECON),
}
_PORT_PREFIX = ("open_port_", "A05", "CWE-668", PHASE_ACTIVE)


def classify(finding_id):
    """Return {'owasp','cwe','phase'} for a finding id, or {} if unmapped."""
    if not finding_id:
        return {}
    hit = _MAP.get(finding_id)
    if hit is None and finding_id.startswith(_PORT_PREFIX[0]):
        hit = _PORT_PREFIX[1:]
    if hit is None:
        return {}
    return {"owasp": OWASP_2021[hit[0]], "cwe": hit[1], "phase": hit[2]}


def enrich_findings(findings):
    """Attach owasp / cwe / phase to every failing or warning finding (in place)."""
    for f in findings:
        if f.get("status") in ("fail", "warning"):
            f.update(classify(f.get("finding_id")))
    return findings


def owasp_coverage(findings):
    """
    OWASP Top 10 table: for every category, how many checks PRAWL ran that map to it and how many failed.
    Categories PRAWL cannot test from the outside are reported as 'not assessed' — never as 'passed'.
    """
    rows = {k: {"category": v, "issues": 0, "assessed": False} for k, v in OWASP_2021.items()}
    pass_ids = {"ssl_valid": "A02", "hsts_pass": "A05", "csp_pass": "A05", "https_redirect_pass": "A02",
                "cookies_pass": "A05", "cors_pass": "A05", "exposed_files_pass": "A05",
                "software_version_pass": "A05", "open_ports_pass": "A05", "tls_pass": "A02",
                "reflection_pass": "A03", "cve_pass": "A06", "email_auth_pass": "A05"}
    by_name = {v: k for k, v in OWASP_2021.items()}
    for f in findings:
        fid = f.get("finding_id", "")
        if f.get("status") in ("fail", "warning"):
            cat = classify(fid).get("owasp")
            if cat:
                r = rows[by_name[cat]]
                r["issues"] += 1
                r["assessed"] = True
        elif fid in pass_ids:
            rows[pass_ids[fid]]["assessed"] = True
    return [{"id": k, **v} for k, v in rows.items()]
