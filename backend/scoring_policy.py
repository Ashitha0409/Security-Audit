"""
scoring_policy.py — every tunable number behind the PRAWL score, in one place.

These are POLICY CHOICES made by the project authors, not measured probabilities or an industry
standard. They are exposed in every scan result (`score_policy`) and in the report so a reader can
see exactly how a score was produced and change it here.

Rationale (kept deliberately simple and explainable):
  * Default weight by severity: how many points one confirmed issue of that severity costs.
  * Individual checks may override the default (e.g. a missing Permissions-Policy header is "low"
    and costs 1 point, a publicly downloadable .env costs 30).
  * Caps: a critical issue can never leave the site above 35, a high issue above 59, so serious
    problems cannot hide behind many passing checks.
  * Bands: >=80 green (LOW risk) ... mirrors the README table.
"""

SEVERITY_WEIGHT = {'critical': 25, 'high': 15, 'medium': 8, 'low': 3, 'info': 0, 'none': 0}

SCORE_CAPS = {'critical': 35, 'high': 59}

# (minimum score, label, colour) — evaluated top to bottom
RISK_BANDS = [
    (80, 'LOW',      '#00d4aa'),
    (60, 'MEDIUM',   '#f59e0b'),
    (40, 'HIGH',     '#f97316'),
    (0,  'CRITICAL', '#ef4444'),
]

# Rule of thumb used for per-check overrides in scanner.py
CHECK_WEIGHT_GUIDE = {
    'exposed secrets / database dump': 30,
    'unauthenticated data store (e.g. Redis)': 30,
    'CVE on CISA Known Exploited list': 20,
    'database / RDP / Telnet port exposed': 15,
    'login form over HTTP': 15,
    'reflected input not encoded': 12,
    'missing CSP / HSTS / HTTPS redirect': 6,
    'missing X-Frame-Options': 4,
    'missing nosniff / Referrer-Policy': 2,
    'missing Permissions-Policy': 1,
}


def as_dict():
    return {
        'kind': 'policy_choice_not_statistical',
        'severity_weight': SEVERITY_WEIGHT,
        'caps': SCORE_CAPS,
        'bands': [{'min': m, 'label': l} for m, l, _ in RISK_BANDS],
        'check_weight_guide': CHECK_WEIGHT_GUIDE,
    }
