"""
cve_intel.py — real CVE intelligence for PRAWL.

Nothing here is invented. Data comes from two public sources:
  * NVD CVE API 2.0  (https://services.nvd.nist.gov/rest/json/cves/2.0)
  * CISA Known Exploited Vulnerabilities catalogue (KEV)

`refresh_snapshot()` downloads CVEs published in a date window (default: October 2026),
keeps the ones relevant to internet-facing web stacks (plus everything on CISA KEV) and
writes them to backend/data/cve_snapshot.json together with fetched_at + source URLs.

`match_software()` compares software versions detected on a target (e.g. "nginx/1.18.0")
against that snapshot using the CPE version ranges NVD publishes. A match means
"the detected version is inside a vulnerable range" — it is version-based evidence,
NOT proof of exploitation (distros back-port fixes), and the report says so.

Usage:
    python cve_intel.py refresh                       # October 2026 (default)
    python cve_intel.py refresh 2026-10-01 2026-10-31
    python cve_intel.py stats
"""

import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone

import requests

logger = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SNAPSHOT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "cve_snapshot.json")

DEFAULT_WINDOW = ("2026-10-01T00:00:00.000", "2026-10-31T23:59:59.999")

# Products an external web scan can actually fingerprint. Keyed by lower-case NVD
# CPE `product` name -> the names a banner/header might use.
WATCH_PRODUCTS = {
    "nginx": ["nginx"],
    "http_server": ["apache", "httpd"],          # apache:http_server
    "httpd": ["apache", "httpd"],
    "tomcat": ["tomcat", "coyote"],
    "lighttpd": ["lighttpd"],
    "iis": ["iis", "microsoft-iis"],
    "internet_information_services": ["iis", "microsoft-iis"],
    "php": ["php"],
    "openssl": ["openssl"],
    "openssh": ["openssh"],
    "wordpress": ["wordpress"],
    "drupal": ["drupal"],
    "joomla": ["joomla", "joomla!"],
    "jquery": ["jquery"],
    "node.js": ["node.js", "nodejs", "node"],
    "express": ["express"],
    "django": ["django"],
    "laravel": ["laravel"],
    "mysql": ["mysql"],
    "mariadb": ["mariadb"],
    "postgresql": ["postgresql", "postgres"],
    "redis": ["redis"],
    "mongodb": ["mongodb"],
    "proftpd": ["proftpd"],
    "vsftpd": ["vsftpd"],
    "exim": ["exim"],
    "postfix": ["postfix"],
}

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}


# ─────────────────────────────────────────────────────────────────────────────
# Fetch + compact
# ─────────────────────────────────────────────────────────────────────────────

def _headers():
    h = {"User-Agent": "PRAWL-CVE-Intel/1.0"}
    key = os.environ.get("NVD_API_KEY", "")
    if key:
        h["apiKey"] = key
    return h


def _cvss(cve):
    """Return (score, severity, vector) using the best available CVSS metric."""
    metrics = cve.get("metrics", {}) or {}
    for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(k, []) or []:
            d = m.get("cvssData", {})
            if d.get("baseScore") is not None:
                return float(d["baseScore"]), (d.get("baseSeverity") or "NONE").upper(), d.get("vectorString", "")
    return None, "NONE", ""


def _english(desc_list):
    for d in desc_list or []:
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def _parse_cpe(cpe):
    """cpe:2.3:a:vendor:product:version:... -> dict or None."""
    parts = cpe.split(":")
    if len(parts) < 6:
        return None
    return {"part": parts[2], "vendor": parts[3].lower(), "product": parts[4].lower(), "version": parts[5]}


def _ranges_from_configurations(cve):
    out = []
    for conf in cve.get("configurations", []) or []:
        for node in conf.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                if not m.get("vulnerable"):
                    continue
                c = _parse_cpe(m.get("criteria", ""))
                if not c or c["part"] not in ("a", "o"):
                    continue
                out.append({
                    "vendor": c["vendor"], "product": c["product"], "exact": c["version"],
                    "start_incl": m.get("versionStartIncluding"), "start_excl": m.get("versionStartExcluding"),
                    "end_incl": m.get("versionEndIncluding"), "end_excl": m.get("versionEndExcluding"),
                })
    return out


def _ranges_from_cna(cve):
    """Fallback for CVEs NVD has not analysed yet: use the CNA's own affected-version data."""
    out = []
    for aff in cve.get("affected", []) or []:
        for data in aff.get("affectedData", []) or []:
            vendor = (data.get("vendor") or "").lower()
            product = (data.get("product") or "").lower().replace(" ", "_")
            for v in data.get("versions", []) or []:
                if v.get("status") != "affected":
                    continue
                r = {"vendor": vendor, "product": product, "exact": v.get("version", "*"),
                     "start_incl": None, "start_excl": None, "end_incl": None, "end_excl": None}
                if v.get("lessThan"):
                    r.update({"start_incl": v.get("version") if v.get("version") not in ("0", "*") else None,
                              "end_excl": v["lessThan"], "exact": "*"})
                elif v.get("lessThanOrEqual"):
                    r.update({"start_incl": v.get("version") if v.get("version") not in ("0", "*") else None,
                              "end_incl": v["lessThanOrEqual"], "exact": "*"})
                out.append(r)
    return out


def _compact(item, kev_ids):
    cve = item["cve"]
    score, sev, vector = _cvss(cve)
    ranges = _ranges_from_configurations(cve) or _ranges_from_cna(cve)
    watched = [r for r in ranges if r["product"] in WATCH_PRODUCTS]
    cid = cve["id"]
    return {
        "id": cid,
        "published": cve.get("published", "")[:10],
        "score": score,
        "severity": sev,
        "vector": vector,
        "description": _english(cve.get("descriptions"))[:400],
        "kev": cid in kev_ids,
        "watched": bool(watched),
        "affects": watched[:20] if watched else ranges[:3],
    }


def fetch_kev():
    r = requests.get(KEV_URL, headers=_headers(), timeout=60)
    r.raise_for_status()
    data = r.json()
    return {v["cveID"]: v for v in data.get("vulnerabilities", [])}, data.get("catalogVersion", "")


def refresh_snapshot(start=DEFAULT_WINDOW[0], end=DEFAULT_WINDOW[1], path=SNAPSHOT_PATH, max_pages=40):
    """Download CVEs published in [start, end] from NVD and write the compact snapshot."""
    kev, kev_version = fetch_kev()
    delay = 1 if os.environ.get("NVD_API_KEY") else 7      # NVD public rate-limit: 5 req / 30 s

    records, scored_total = {}, 0
    # exact number of CVEs NVD published in the window (any severity), for the UI headline
    r0 = requests.get(NVD_URL, params={"pubStartDate": start, "pubEndDate": end, "resultsPerPage": 1},
                      headers=_headers(), timeout=60)
    r0.raise_for_status()
    total_in_window = r0.json().get("totalResults", 0)
    time.sleep(delay)

    for field, severity in (("cvssV3Severity", "CRITICAL"), ("cvssV3Severity", "HIGH")):
        index, pages = 0, 0
        while pages < max_pages:
            params = {"pubStartDate": start, "pubEndDate": end, field: severity,
                      "resultsPerPage": 2000, "startIndex": index}
            resp = None
            for attempt in range(4):
                resp = requests.get(NVD_URL, params=params, headers=_headers(), timeout=120)
                if resp.status_code in (403, 429, 503):
                    time.sleep(10 * (attempt + 1))
                    continue
                break
            resp.raise_for_status()
            body = resp.json()
            scored_total += 0 if pages else body.get("totalResults", 0)
            vulns = body.get("vulnerabilities", [])
            for item in vulns:
                rec = _compact(item, kev)
                # keep: anything on CISA KEV, everything matching a fingerprintable product,
                # and all CRITICAL CVEs (for the intel panel)
                if rec["kev"] or rec["watched"] or rec["severity"] == "CRITICAL":
                    records[rec["id"]] = rec
            index += len(vulns)
            pages += 1
            logger.info("NVD %s: %d/%d", severity, index, body.get("totalResults", 0))
            if index >= body.get("totalResults", 0) or not vulns:
                break
            time.sleep(delay)
        time.sleep(delay)

    # CISA KEV entries added in the window that NVD severity filters may have missed
    s_d, e_d = start[:10], end[:10]
    kev_in_window = [v for v in kev.values() if s_d <= v.get("dateAdded", "") <= e_d]

    snapshot = {
        "window": {"start": start, "end": end},
        "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sources": {"nvd": NVD_URL, "cisa_kev": KEV_URL, "kev_catalog_version": kev_version},
        "nvd_total_published_in_window": total_in_window,
        "nvd_cvss3_critical_high_total": scored_total,
        "kev_added_in_window": [
            {"id": v["cveID"], "vendor": v.get("vendorProject"), "product": v.get("product"),
             "name": v.get("vulnerabilityName"), "date_added": v.get("dateAdded"),
             "ransomware": v.get("knownRansomwareCampaignUse")} for v in kev_in_window
        ],
        "cves": sorted(records.values(), key=lambda r: (_SEV_ORDER.get(r["severity"], 4), -(r["score"] or 0))),
    }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(snapshot, fh, separators=(",", ":"))
    return snapshot


def load_snapshot(path=SNAPSHOT_PATH):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None
    except Exception as e:
        logger.warning("CVE snapshot unreadable: %s", e)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Version comparison + matching
# ─────────────────────────────────────────────────────────────────────────────

def _vtuple(v):
    """'1.18.0' / '8.1.2-ubuntu' / '2.4.49a' -> comparable tuple (non-numeric tails ignored)."""
    nums = re.findall(r"\d+", str(v).split("-")[0].split("+")[0])
    return tuple(int(n) for n in nums) or None


def _cmp(a, b):
    ta, tb = _vtuple(a), _vtuple(b)
    if ta is None or tb is None:
        return None
    n = max(len(ta), len(tb))
    ta, tb = ta + (0,) * (n - len(ta)), tb + (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def version_in_range(version, r):
    """True/False, or None when the range carries no usable version information."""
    if r.get("exact") not in (None, "*", "-", ""):
        c = _cmp(version, r["exact"])
        return None if c is None else c == 0
    bounds = [("start_incl", lambda c: c >= 0), ("start_excl", lambda c: c > 0),
              ("end_incl", lambda c: c <= 0), ("end_excl", lambda c: c < 0)]
    used = False
    for key, ok in bounds:
        if r.get(key):
            used = True
            c = _cmp(version, r[key])
            if c is None or not ok(c):
                return False
    return True if used else None      # "all versions" is too weak to claim a match


def parse_banner(text):
    """
    Extract (product, version) pairs from header values like
    'nginx/1.18.0 (Ubuntu)', 'Apache/2.4.49 (Unix) PHP/7.4.3', 'PHP/8.1.2'.
    Pairs with no version are dropped — we never guess a version.
    """
    found = []
    for name, ver in re.findall(r"([A-Za-z][A-Za-z0-9_.\-!]*)/(\d+(?:\.\d+)+[A-Za-z0-9]*)", text or ""):
        found.append((name.lower(), ver))
    return found


def match_software(detected, snapshot=None):
    """
    detected: list of (product_token, version) e.g. [('nginx', '1.18.0')].
    Returns list of CVE dicts (from the snapshot) whose version ranges contain the detected version.
    """
    snapshot = snapshot if snapshot is not None else load_snapshot()
    if not snapshot:
        return []
    hits, seen = [], set()
    for token, version in detected:
        for rec in snapshot.get("cves", []):
            if rec["id"] in seen or not rec.get("watched"):
                continue
            for r in rec.get("affects", []):
                names = WATCH_PRODUCTS.get(r["product"], [])
                if token not in names and token != r["product"]:
                    continue
                if version_in_range(version, r):
                    seen.add(rec["id"])
                    # NVD gave only an upper bound: other release branches may not be affected -> approximate
                    approx = not (r.get("start_incl") or r.get("start_excl")) and r.get("exact") in (None, "*", "-", "")
                    hits.append({**{k: rec[k] for k in ("id", "published", "score", "severity", "description", "kev")},
                                 "product": token, "detected_version": version, "approximate": approx})
                    break
    hits.sort(key=lambda h: (not h["kev"], _SEV_ORDER.get(h["severity"], 4), -(h["score"] or 0)))
    return hits


def summarize_snapshot(snapshot=None, limit=15):
    """Small, UI-friendly summary of the snapshot (for the 'Recent CVEs' panel)."""
    snapshot = snapshot if snapshot is not None else load_snapshot()
    if not snapshot:
        return {"available": False}
    cves = snapshot.get("cves", [])
    return {
        "available": True,
        "window": snapshot["window"],
        "fetched_at": snapshot["fetched_at"],
        "sources": snapshot["sources"],
        "nvd_total_published_in_window": snapshot.get("nvd_total_published_in_window"),
        "kev_added_in_window": snapshot.get("kev_added_in_window", []),
        "kev_count": len(snapshot.get("kev_added_in_window", [])),
        "tracked": len(cves),
        "top": [{k: c[k] for k in ("id", "published", "score", "severity", "description", "kev")}
                for c in cves[:limit]],
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    cmd = sys.argv[1] if len(sys.argv) > 1 else "stats"
    if cmd == "refresh":
        s = sys.argv[2] + "T00:00:00.000" if len(sys.argv) > 2 else DEFAULT_WINDOW[0]
        e = sys.argv[3] + "T23:59:59.999" if len(sys.argv) > 3 else DEFAULT_WINDOW[1]
        snap = refresh_snapshot(s, e)
        print(f"Saved {len(snap['cves'])} CVEs, {len(snap['kev_added_in_window'])} KEV adds -> {SNAPSHOT_PATH}")
    else:
        print(json.dumps({k: v for k, v in (summarize_snapshot() or {}).items() if k != "top"}, indent=2))
