import logging
import os
import uuid

import boto3

LEX_BOT_ID       = os.environ.get("LEX_BOT_ID")
LEX_BOT_ALIAS_ID = os.environ.get("LEX_BOT_ALIAS_ID", "TSTALIASID")
LEX_LOCALE_ID    = os.environ.get("LEX_LOCALE_ID", "en_US")

_client = boto3.client("lexv2-runtime", region_name=os.environ.get("AWS_REGION", "us-east-2"))

# Lex intent name → (risk_score, severity)
_INTENT_RISK_MAP = {
    "PrivilegeEscalation": (8, "HIGH"),
    "HighRiskEvent":       (8, "HIGH"),
    "BruteForce":          (7, "HIGH"),
    "SuspiciousLogin":     (4, "MEDIUM"),
    "UnusualAccess":       (5, "MEDIUM"),
    "NormalAccess":        (1, "LOW"),
    "FallbackIntent":      (3, "LOW"),
}


class LexError(Exception):
    pass


def _format_utterance(log):
    """Render a normalised log dict as a natural-language string for Lex."""
    hour = log.get("_hour")
    time_str = f"at hour {hour:02d}:00 UTC" if hour is not None else "at unknown time"

    parts = [
        f"User {log.get('user', 'unknown')} performed {log.get('event', 'unknown')}",
        f"from IP {log.get('source_ip', 'unknown')}",
        time_str,
    ]
    if log.get("mfa_used") is False:
        parts.append("without MFA")
    elif log.get("mfa_used") is True:
        parts.append("with MFA")
    if log.get("success") is False:
        parts.append("authentication failed")
    event_source = log.get("eventSource", "")
    if event_source:
        parts.append(f"via {event_source}")
    return ", ".join(parts)


def classify_risk(log, session_id=None):
    """
    Classify the risk of a log entry via Amazon Lex.

    Args:
        log:        Validated, normalised log dict.
        session_id: Optional Lex session ID (defaults to a fresh UUID).

    Returns:
        dict with keys: risk_score, severity, intent, lex_confidence, reasons, blockers

    Raises:
        LexError on API failure.
    """
    utterance = _format_utterance(log)
    session_id = session_id or str(uuid.uuid4())

    try:
        response = _client.recognize_text(
            botId=LEX_BOT_ID,
            botAliasId=LEX_BOT_ALIAS_ID,
            localeId=LEX_LOCALE_ID,
            sessionId=session_id,
            text=utterance,
        )
    except Exception as e:
        logging.error(f"Lex classify_risk failed: {e}")
        raise LexError(str(e)) from e

    intent_name = (
        response.get("sessionState", {})
                .get("intent", {})
                .get("name", "FallbackIntent")
    )

    interpretations = response.get("interpretations", [])
    lex_confidence = float(
        interpretations[0].get("nluConfidence", {}).get("score", 0.0)
        if interpretations else 0.0
    )

    risk_score, severity = _INTENT_RISK_MAP.get(intent_name, (3, "LOW"))

    reasons = [f"Lex intent '{intent_name}' (confidence {lex_confidence:.2f})"]

    blockers = [
        f"missing_field:{field}"
        for field in ("location", "mfa_used", "time", "failed_attempts")
        if log.get(field) is None
    ]

    return {
        "risk_score":     risk_score,
        "severity":       severity,
        "intent":         intent_name,
        "lex_confidence": lex_confidence,
        "reasons":        reasons,
        "blockers":       blockers,
    }