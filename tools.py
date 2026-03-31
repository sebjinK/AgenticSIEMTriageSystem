# Stub IP reputation list for MVP.
# Post-MVP: replace with real threat-intel API (e.g. AbuseIPDB, VirusTotal).
_REPUTATION_DB = {
    "192.168.100.1": {"reputation": "malicious", "category": "known_c2"},
    "10.0.0.99":     {"reputation": "malicious", "category": "tor_exit_node"},
    "203.0.113.5":   {"reputation": "malicious", "category": "botnet"},
}


def check_ip_reputation(ip):
    """
    Look up an IP address against the local reputation stub.

    Returns a dict with keys:
        ip         (str)
        reputation ("malicious" | "clean" | "unknown")
        category   (str | None)  — threat category if malicious
    """
    if not ip:
        return {"ip": ip, "reputation": "unknown", "category": None}

    entry = _REPUTATION_DB.get(ip)
    if entry:
        return {"ip": ip, **entry}

    # No match — reputation cannot be confirmed
    return {"ip": ip, "reputation": "unknown", "category": None}
