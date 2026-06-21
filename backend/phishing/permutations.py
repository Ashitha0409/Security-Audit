def generate_permutations(domain):
    """
    Generate typosquat permutations using dnstwist.
    Falls back to manual permutations if dnstwist is not available.
    Returns list of candidate domain strings.
    """
    try:
        import dnstwist
        fuzz = dnstwist.Fuzzer(domain)
        fuzz.generate()
        # Cap at 100 — the scorer enforces its own cap of 80, but trim early
        candidates = [e['domain'] for e in fuzz.domains if e['domain'] != domain]
        return candidates[:100]
    except Exception:
        pass
    # Manual fallback if dnstwist not available
    return _manual_permutations(domain)


def _manual_permutations(domain):
    """
    Simple fallback: common TLD swaps and character substitutions.
    Returns a deduplicated list capped at 50 candidates.
    """
    parts = domain.rsplit('.', 1)
    if len(parts) != 2:
        return []
    name, tld = parts
    results = set()

    # TLD swaps
    for alt_tld in ['.com', '.net', '.org', '.in', '.co.in', '.info', '.biz', '.io']:
        candidate = name + alt_tld
        if candidate != domain:
            results.add(candidate)

    # Omission typos (drop one character)
    for i in range(len(name)):
        if len(name) > 2:
            candidate = name[:i] + name[i+1:] + '.' + tld
            if candidate != domain:
                results.add(candidate)

    # Transposition typos (swap adjacent characters)
    for i in range(len(name) - 1):
        swapped = name[:i] + name[i+1] + name[i] + name[i+2:] + '.' + tld
        if swapped != domain:
            results.add(swapped)

    # Insertion typos (double a character)
    for i in range(len(name)):
        doubled = name[:i] + name[i] + name[i:] + '.' + tld
        if doubled != domain:
            results.add(doubled)

    # Common homoglyph substitutions
    homoglyphs = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 'l': '1', 's': '5'}
    for i, ch in enumerate(name.lower()):
        if ch in homoglyphs:
            subst = name[:i] + homoglyphs[ch] + name[i+1:] + '.' + tld
            if subst != domain:
                results.add(subst)

    # Brand + payment/login keywords (high phishing signal)
    for kw in ['pay', 'login', 'secure', 'offers', 'verify', 'official', 'support', 'help', 'care']:
        results.add(name + '-' + kw + '.' + tld)
        results.add(kw + '-' + name + '.' + tld)
        results.add(name + kw + '.' + tld)

    return list(results)[:50]  # cap at 50
