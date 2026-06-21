import requests
import socket


def domain_exists_in_ct(candidate):
    """
    Check whether a certificate has been issued for the candidate domain via crt.sh.
    A certificate hit is strong evidence the domain is live and potentially serving HTTPS.
    Returns True if at least one certificate record exists, False otherwise.
    """
    try:
        r = requests.get(
            f"https://crt.sh/?q={candidate}&output=json",
            headers={'User-Agent': 'PRAWL-Scanner/1.0'},
            timeout=12
        )
        if r.status_code == 200:
            data = r.json()
            return isinstance(data, list) and len(data) > 0
        return False
    except Exception:
        return False


def resolves(candidate):
    """
    Check whether the candidate domain resolves via DNS.
    A domain that resolves is live and actively used.
    Returns True if DNS resolution succeeds, False otherwise.
    """
    try:
        socket.gethostbyname(candidate)
        return True
    except Exception:
        return False
