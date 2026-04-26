import json
import logging
import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

import s3_utils
from agent import run_agent
from bedrock_client import BedrockResponseError
from cloudtrail_client import fetch_events, count_recent_failures, CloudTrailFetchError
from geo_client import lookup as geo_lookup
from lex_client import classify_risk, LexError
from rules import normalize_time

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
_sns = boto3.client("sns", region_name=os.environ.get("AWS_REGION", "us-east-1"))

REQUIRED_FIELDS = {"eventTime", "eventName", "sourceIPAddress", "userIdentity"}


# ---------------------------------------------------------------------------
# Validation & normalisation
# ---------------------------------------------------------------------------

def _validate(log, event_id):
    """Return True if the log contains all required CloudTrail fields."""
    missing = REQUIRED_FIELDS - set(log.keys())
    if missing:
        logging.warning(f"{event_id}: missing required fields {missing} — skipping")
        return False
    return True


def _normalise(raw_log):
    """
    Extract pipeline fields from a raw CloudTrail event dict and attach _hour.

    Preserves all original CloudTrail fields so the agent prompt has full context.
    """
    identity = raw_log.get("userIdentity", {})

    # IAMUser exposes userName directly; AssumedRole exposes it via sessionIssuer
    user = (
        identity.get("userName")
        or identity.get("sessionContext", {}).get("sessionIssuer", {}).get("userName")
        or identity.get("principalId", "unknown")
    )

    # ConsoleLogin stores MFA in additionalEventData; API calls store it in sessionContext
    mfa_str = raw_log.get("additionalEventData", {}).get("MFAUsed")
    if mfa_str is not None:
        mfa_used = mfa_str == "Yes"
    else:
        mfa_raw = identity.get("sessionContext", {}).get("attributes", {}).get("mfaAuthenticated")
        mfa_used = True if mfa_raw == "true" else (False if mfa_raw == "false" else None)

    # ConsoleLogin result is in responseElements; other failures set errorCode
    console_result = (raw_log.get("responseElements") or {}).get("ConsoleLogin")
    if console_result:
        success = console_result == "Success"
    else:
        success = "errorCode" not in raw_log

    log = dict(raw_log)
    log.update({
        "user":            user,
        "event":           raw_log.get("eventName", "Unknown"),
        "source_ip":       raw_log.get("sourceIPAddress", ""),
        "time":            raw_log.get("eventTime", ""),
        "success":         success,
        "mfa_used":        mfa_used,
        "location":        "Unknown",  # requires GeoIP enrichment on sourceIPAddress
        "failed_attempts": 0,          # requires aggregation across events
    })
    log["_hour"] = normalize_time(log["time"])
    return log


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------

def _enrich(log):
    """
    Populate location (GeoIP) and failed_attempts (CloudTrail history).
    Called after _normalise so the log dict already has user, source_ip, event.
    """
    log["location"] = geo_lookup(log.get("source_ip", ""))

    # Only ConsoleLogin generates repeated failure events worth aggregating
    if log.get("event") == "ConsoleLogin" and log.get("success") is False:
        log["failed_attempts"] = count_recent_failures(log["user"])

    return log


# ---------------------------------------------------------------------------
# Per-event processing
# ---------------------------------------------------------------------------

def _process_log(log, event_id):
    """
    Classify risk via Lex and run the agent loop for a single normalised event.

    Returns the result dict on success, raises on unrecoverable failure.
    """
    lex = classify_risk(log)
    logging.info(
        f"{event_id} | user={log['user']} intent={lex['intent']} "
        f"risk={lex['risk_score']} severity={lex['severity']}"
    )

    result = run_agent(
        log=log,
        risk_score=lex["risk_score"],
        reasons=lex["reasons"],
        rules_blockers=lex["blockers"],
    )

    return {
        "event_id":        event_id,
        "user":            log["user"],
        "event":           log["event"],
        "source_ip":       log["source_ip"],
        "event_time":      log["time"],
        "risk_score":      lex["risk_score"],
        "lex_intent":      lex["intent"],
        "severity":        result["severity"],
        "confidence":      result["confidence"],
        "enrichment":      result["enrichment"],
        "reasoning":       result["reasoning"],
        "playbook_action": result["playbook_action"],
        "escalate":        result["escalate"],
        "iterations":      result["iterations"],
        "capped":          result["capped"],
    }


# ---------------------------------------------------------------------------
# Batch orchestration
# ---------------------------------------------------------------------------

def run(max_events=50, hours_back=24):
    """
    Main batch entry point. Called by handler.py.

    Fetches IAM-related events directly from CloudTrail LookupEvents,
    processes each one, writes a triage report to S3 (if configured),
    and SNS-alerts on failures.
    """
    ts      = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    results = []
    failed  = []

    try:
        events = fetch_events(max_events=max_events, hours_back=hours_back)
    except CloudTrailFetchError as e:
        logging.error(f"CloudTrail fetch failed: {e}")
        return {"run_timestamp": ts, "logs_processed": 0, "logs_failed": 0,
                "error": str(e), "results": [], "failed_events": []}

    logging.info(f"Batch {ts}: {len(events)} event(s) fetched")

    for raw_event in events:
        event_id = raw_event.get("eventID", "unknown")
        if not _validate(raw_event, event_id):
            failed.append(event_id)
            continue

        log = _enrich(_normalise(dict(raw_event)))

        try:
            result = _process_log(log, event_id)
            results.append(result)
        except (BedrockResponseError, LexError, json.JSONDecodeError) as e:
            logging.error(f"Agent failed for event {event_id} user={log.get('user')}: {e}")
            failed.append(event_id)

    report = {
        "run_timestamp":  ts,
        "logs_processed": len(results),
        "logs_failed":    len(failed),
        "results":        results,
        "failed_events":  failed,
    }

    _write_report(report, ts)
    if failed:
        _send_alert(failed, ts)

    return report


# ---------------------------------------------------------------------------
# Report output
# ---------------------------------------------------------------------------

def _write_report(report, ts):
    if not os.environ.get("S3_BUCKET_NAME"):
        logging.info(f"Report (S3_BUCKET_NAME not set):\n{json.dumps(report, indent=2)}")
        return
    try:
        report_key = s3_utils.write_report(report)
        logging.info(f"Report written: {report_key}")
    except ClientError as e:
        logging.error(f"Failed to write report to S3: {e}")


# ---------------------------------------------------------------------------
# Alerting
# ---------------------------------------------------------------------------

def _send_alert(failed, ts):
    if not SNS_TOPIC_ARN:
        logging.warning("SNS_TOPIC_ARN not set — skipping failure alert")
        return
    message = (
        f"SIEM triage run {ts} completed with {len(failed)} failed event(s):\n"
        + "\n".join(f"  - {e}" for e in failed)
    )
    try:
        _sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"[SIEM] {len(failed)} event(s) failed — {ts}",
            Message=message,
        )
    except ClientError as e:
        logging.error(f"SNS publish failed: {e}")
