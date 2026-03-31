from datetime import datetime

EVENT_RISK_MODIFIERS = {
    "ConsoleLogin":     0,
    "AssumeRole":       1,
    "GetSecretValue":   2,
    "CreateUser":       2,
    "AttachUserPolicy": 3,
    "DeleteTrail":      3,
}

# Stub malicious IP list — replaced by tools.py at agent time
_MALICIOUS_IPS = {"192.168.100.1", "10.0.0.99", "203.0.113.5"}


def normalize_time(time_str):
    """Parse a time string to an integer hour (0–23). Returns None on failure."""
    if not time_str:
        return None
    for fmt in ["%H:%M", "%H:%M:%S", "%I:%M %p"]:
        try:
            return datetime.strptime(time_str, fmt).hour
        except ValueError:
            continue
    return None


def score_log(log):
    """
    Apply deterministic risk scoring to a log entry.

    Returns:
        risk_score (int)
        reasons    (list[str])
        blockers   (list[str])  — confidence blockers for the agent layer
    """
    risk = 0
    reasons = []
    blockers = []

    # --- Event modifier ---
    event = log.get("event", "Unknown")
    modifier = EVENT_RISK_MODIFIERS.get(event, 1)
    risk += modifier
    if modifier > 0:
        reasons.append(f"Event '{event}' carries baseline risk +{modifier}")

    # --- Brute force ---
    failed_attempts = log.get("failed_attempts", 0)
    if log.get("success") is False and failed_attempts > 3:
        risk += 2
        reasons.append(f"Brute force: {failed_attempts} failed attempts")

    # --- Unusual location ---
    location = log.get("location")
    if location and location not in ("USA", "Unknown"):
        risk += 2
        reasons.append(f"Unusual location: {location}")
    if not location or location == "Unknown":
        blockers.append("missing_field:location")

    # --- MFA ---
    mfa_used = log.get("mfa_used")
    if mfa_used is not True:
        risk += 2
        if mfa_used is False:
            reasons.append("MFA not used")
        else:
            reasons.append("MFA status unknown")
            blockers.append("missing_field:mfa_used")

    # --- Off-hours ---
    hour = log.get("_hour")
    if hour is None:
        blockers.append("missing_field:time")
    elif hour < 6 or hour > 22:
        risk += 1
        reasons.append(f"Off-hours access at hour {hour:02d}:00")

    # --- Missing failed_attempts ---
    if "failed_attempts" not in log:
        blockers.append("missing_field:failed_attempts")

    # --- Malicious IP (rules-level stub; agent uses tools.py at runtime) ---
    source_ip = log.get("source_ip", "")
    if source_ip in _MALICIOUS_IPS:
        risk += 3
        reasons.append(f"Source IP {source_ip} flagged as malicious")

    return risk, reasons, blockers


def classify_severity(risk_score):
    if risk_score >= 7:
        return "HIGH"
    elif risk_score >= 4:
        return "MEDIUM"
    return "LOW"
