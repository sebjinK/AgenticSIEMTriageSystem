import logging

import requests

_SESSION = requests.Session()
_CACHE = {}

_PRIVATE_PREFIXES = ("10.", "172.16.", "192.168.", "127.", "::1")


def lookup(ip):
    """
    Return the country name for an IP address, or "Unknown" on failure.

    Results are cached in-process to avoid re-querying the same IP within a batch.
    Private/loopback addresses return "Internal" without a network call.

    Rate limit: ip-api.com allows 45 req/min on the free tier — well within
    the 3k/day ceiling (≈ 2 req/min average).
    """
    if not ip:
        return "Unknown"
    if any(ip.startswith(p) for p in _PRIVATE_PREFIXES):
        return "Internal"
    if ip in _CACHE:
        return _CACHE[ip]

    try:
        resp = _SESSION.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country"},
            timeout=3,
        )
        data = resp.json()
        country = data["country"] if data.get("status") == "success" else "Unknown"
    except Exception as e:
        logging.warning(f"GeoIP lookup failed for {ip}: {e}")
        country = "Unknown"

    _CACHE[ip] = country
    return country
