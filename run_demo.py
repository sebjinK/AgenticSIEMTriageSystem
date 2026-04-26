"""
End-to-end demo run — no AWS credentials required.

Mocks:
  - lex_client.classify_risk  (Lex intent classification)
  - agent.invoke              (Bedrock / Claude Haiku)

Runs every entry in logs.py through the real agent loop and prints
a formatted triage report.

Usage:  python3 run_demo.py
"""
import json
import sys
import types
from unittest.mock import MagicMock, patch

# Stub boto3 before any project module imports it
sys.modules["boto3"] = MagicMock()
sys.modules["botocore"] = MagicMock()
sys.modules["botocore.exceptions"] = MagicMock()

class _ClientError(Exception):
    pass
sys.modules["botocore.exceptions"].ClientError = _ClientError

import os
os.environ.setdefault("S3_BUCKET_NAME", "demo-bucket")
os.environ.setdefault("SNS_TOPIC_ARN",  "arn:aws:sns:us-east-2:000000000000:demo")

import logs
import rules
import agent
from lex_client import _INTENT_RISK_MAP


# ---------------------------------------------------------------------------
# Fake Lex: derive intent from the log using the same signals as rules.py
# ---------------------------------------------------------------------------

def _fake_classify_risk(log, session_id=None):
    """Heuristic intent selection that mirrors what a trained Lex bot would do."""
    event   = log.get("event", "")
    mfa     = log.get("mfa_used")
    success = log.get("success", True)
    hour    = log.get("_hour")
    ip      = log.get("source_ip", "")

    from tools import check_ip_reputation
    malicious_ip = check_ip_reputation(ip)["reputation"] == "malicious"

    off_hours  = hour is not None and (hour < 6 or hour > 22)
    failed_auth = success is False
    priv_event  = event in ("AttachUserPolicy", "DeleteTrail", "CreateUser")

    if malicious_ip and (priv_event or failed_auth):
        intent = "HighRiskEvent"
    elif malicious_ip and off_hours:
        intent = "HighRiskEvent"
    elif priv_event and off_hours:
        intent = "PrivilegeEscalation"
    elif priv_event and (mfa is False or mfa is None):
        intent = "PrivilegeEscalation"
    elif failed_auth and mfa is False:
        intent = "BruteForce"
    elif off_hours and (mfa is False or malicious_ip):
        intent = "SuspiciousLogin"
    elif mfa is None or mfa is False:
        intent = "UnusualAccess"
    else:
        intent = "NormalAccess"

    risk_score, severity = _INTENT_RISK_MAP[intent]
    reasons  = [f"Lex intent '{intent}' (confidence 0.92)"]
    blockers = [
        f"missing_field:{f}"
        for f in ("location", "mfa_used", "time", "failed_attempts")
        if log.get(f) is None
    ]
    return {
        "risk_score":     risk_score,
        "severity":       severity,
        "intent":         intent,
        "lex_confidence": 0.92,
        "reasons":        reasons,
        "blockers":       blockers,
    }


# ---------------------------------------------------------------------------
# Fake Bedrock: generate a plausible Claude response from the log context
# ---------------------------------------------------------------------------

def _fake_invoke(user_message, system_prompt):
    try:
        risk = int(user_message.split("Rule-based risk score: ")[1].split("\n")[0].strip())
    except (IndexError, ValueError):
        risk = 5
    high = risk >= 7
    return json.dumps({
        "confidence":          0.91 if high else 0.75,
        "confidence_blockers": [],
        "severity":            "HIGH" if high else ("MEDIUM" if risk >= 4 else "LOW"),
        "reasoning":           f"Risk score {risk} with indicators from the log.",
        "playbook_action":     "Disable account and alert SOC" if high else "Review and monitor",
        "escalate":            high,
        "needs_enrichment":    False,
    })


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

def main():
    print("=" * 62)
    print("  agenticSIEM — local demo run")
    print("=" * 62)

    with patch("main.fetch_events", return_value=logs.LOGS), \
         patch("main.classify_risk", side_effect=_fake_classify_risk), \
         patch("agent.invoke", side_effect=_fake_invoke):

        from main import run

        report = run()
        results = report["results"]

        for result in results:
            flag = "🔴" if result["severity"] == "HIGH" else ("🟡" if result["severity"] == "MEDIUM" else "🟢")
            print(
                f"\n{flag} {result['user']:8}  {result['event']:20}"
                f"  {result['severity']:6}  conf={result['confidence']:.2f}"
                f"  iter={result['iterations']}"
                f"{'  CAPPED' if result['capped'] else ''}"
            )
            print(f"   intent:  {result['lex_intent']}")
            print(f"   action:  {result['playbook_action']}")
            print(f"   reason:  {result['reasoning']}")
            if result["enrichment"]["context_gaps"]:
                print(f"   gaps:    {result['enrichment']['context_gaps']}")

    print("\n" + "=" * 62)
    print(f"  {len(results)} logs processed")
    escalated = [r for r in results if r["escalate"]]
    print(f"  {len(escalated)} escalated")
    print("=" * 62)


if __name__ == "__main__":
    main()
