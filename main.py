import json
import logging
import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

import s3_utils
from agent import run_agent
from bedrock_client import BedrockResponseError
from rules import normalize_time, score_log, classify_severity

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
_sns = boto3.client("sns", region_name="us-east-2")

REQUIRED_FIELDS = {"user", "event", "source_ip", "time"}
OPTIONAL_DEFAULTS = {
    "success":         None,
    "location":        "Unknown",
    "mfa_used":        None,
    "failed_attempts": 0,
}


# ---------------------------------------------------------------------------
# Validation & normalisation
# ---------------------------------------------------------------------------

def _validate(log, file_key):
    """Return True if the log contains all required fields."""
    missing = REQUIRED_FIELDS - set(log.keys())
    if missing:
        logging.warning(f"{file_key}: log missing required fields {missing} — skipping entry")
        return False
    return True


def _normalise(log):
    """
    Apply optional-field defaults and attach _hour (normalised int | None).
    Mutates and returns the log dict.
    """
    for field, default in OPTIONAL_DEFAULTS.items():
        log.setdefault(field, default)
    log["_hour"] = normalize_time(log.get("time"))
    return log


# ---------------------------------------------------------------------------
# Per-log processing
# ---------------------------------------------------------------------------

def _process_log(log, file_key):
    """
    Score and run the agent loop for a single validated, normalised log.

    Returns the result dict on success, raises on unrecoverable failure.
    """
    risk_score, reasons, blockers = score_log(log)
    severity = classify_severity(risk_score)
    logging.info(f"{file_key} | user={log['user']} risk={risk_score} severity={severity}")

    result = run_agent(
        log=log,
        risk_score=risk_score,
        reasons=reasons,
        rules_blockers=blockers,
    )

    return {
        "user":           log["user"],
        "event":          log["event"],
        "source_ip":      log["source_ip"],
        "risk_score":     risk_score,
        "severity":       result["severity"],
        "confidence":     result["confidence"],
        "enrichment":     result["enrichment"],
        "reasoning":      result["reasoning"],
        "playbook_action": result["playbook_action"],
        "escalate":       result["escalate"],
        "iterations":     result["iterations"],
        "capped":         result["capped"],
    }


# ---------------------------------------------------------------------------
# Batch orchestration
# ---------------------------------------------------------------------------

def run():
    """
    Main batch entry point. Called by handler.py.

    Reads up to 10 log files from S3 incoming/, processes each log entry,
    assembles a triage report, writes it to S3, and SNS-alerts on failures.
    """
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    results   = []
    failed_logs = []

    keys = s3_utils.list_incoming(max_keys=10)
    logging.info(f"Batch {ts}: {len(keys)} file(s) found in incoming/")

    for key in keys:
        file_ok = True
        try:
            entries = s3_utils.read_log(key)
        except (ValueError, ClientError) as e:
            logging.error(f"Cannot read {key}: {e}")
            failed_key = s3_utils.move_to_failed(key)
            failed_logs.append(failed_key)
            continue

        for raw_log in entries:
            if not _validate(raw_log, key):
                file_ok = False
                continue

            log = _normalise(dict(raw_log))

            try:
                result = _process_log(log, key)
                results.append(result)
            except (BedrockResponseError, json.JSONDecodeError) as e:
                logging.error(f"Agent failed for {key} user={log.get('user')}: {e}")
                file_ok = False

        if file_ok:
            s3_utils.move_to_processed(key)
        else:
            failed_key = s3_utils.move_to_failed(key)
            failed_logs.append(failed_key)

    report = {
        "run_timestamp":  ts,
        "logs_processed": len(results),
        "logs_failed":    len(failed_logs),
        "results":        results,
        "failed_logs":    failed_logs,
    }

    report_key = s3_utils.write_report(report)
    logging.info(f"Report: {report_key}")

    if failed_logs:
        _send_alert(failed_logs, ts)

    return report


# ---------------------------------------------------------------------------
# Alerting
# ---------------------------------------------------------------------------

def _send_alert(failed_logs, ts):
    if not SNS_TOPIC_ARN:
        logging.warning("SNS_TOPIC_ARN not set — skipping failure alert")
        return
    message = (
        f"SIEM triage run {ts} completed with {len(failed_logs)} failed log(s):\n"
        + "\n".join(f"  - {k}" for k in failed_logs)
    )
    try:
        _sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"[SIEM] {len(failed_logs)} log(s) failed — {ts}",
            Message=message,
        )
    except ClientError as e:
        logging.error(f"SNS publish failed: {e}")
