from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
from .ct_monitor import domain_exists_in_ct, resolves

_PHISHING_KEYWORDS = frozenset(
    ["login", "pay", "secure", "offers", "verify", "official",
     "support", "help", "care", "signin", "account", "bank", "wallet"]
)

# Cap candidates before checking — dnstwist generates 1000s, we only need top ones
MAX_CANDIDATES = 80
BATCH_SIZE = 10
MAX_RESULTS = 20


def _check_candidate(real_domain, candidate):
    ct = domain_exists_in_ct(candidate)
    dns = resolves(candidate)
    if not (ct or dns):
        return None
    threat = 0
    threat += 40 if ct else 0
    threat += 30 if dns else 0
    if any(kw in candidate.lower() for kw in _PHISHING_KEYWORDS):
        threat += 30
    return {"domain": candidate, "has_cert": ct, "resolves": dns, "threat": min(100, threat)}


def score_impersonators(real_domain, candidates, total_timeout=25):
    """
    Check candidates for existence (CT or DNS) and score by threat level.
    Caps at MAX_CANDIDATES before submitting to avoid blocking shutdown.
    Returns a sorted list of up to MAX_RESULTS impersonator dicts.
    """
    results = []
    if not candidates:
        return results

    # Deduplicate, remove the real domain, and hard-cap the list
    candidates = list({c for c in candidates if c != real_domain})[:MAX_CANDIDATES]

    executor = ThreadPoolExecutor(max_workers=BATCH_SIZE)
    try:
        future_to_candidate = {
            executor.submit(_check_candidate, real_domain, c): c
            for c in candidates
        }
        try:
            for future in as_completed(future_to_candidate, timeout=total_timeout):
                try:
                    result = future.result(timeout=5)
                    if result is not None:
                        results.append(result)
                except Exception:
                    pass
        except FuturesTimeoutError:
            pass
    finally:
        # cancel_futures=True (Python 3.9+) prevents waiting for in-flight tasks
        executor.shutdown(wait=False, cancel_futures=True)

    results.sort(key=lambda x: x["threat"], reverse=True)
    return results[:MAX_RESULTS]
