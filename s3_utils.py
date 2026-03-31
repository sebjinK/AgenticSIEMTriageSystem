import json
import logging
import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

BUCKET = os.environ["S3_BUCKET_NAME"]

_s3 = boto3.client("s3")

INCOMING_PREFIX  = "logs/incoming/"
PROCESSED_PREFIX = "logs/processed/"
FAILED_PREFIX    = "logs/failed/"
REPORTS_PREFIX   = "reports/"


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------

def list_incoming(max_keys=10):
    """
    Return up to max_keys object keys from logs/incoming/, sorted by
    LastModified descending (newest first).
    """
    response = _s3.list_objects_v2(Bucket=BUCKET, Prefix=INCOMING_PREFIX)
    objects  = response.get("Contents", [])
    objects.sort(key=lambda o: o["LastModified"], reverse=True)
    return [o["Key"] for o in objects[:max_keys]]


def read_log(key):
    """
    Download and parse a JSON log file from S3.

    Returns a list of log dicts (supports both single-object and array files).
    Raises ValueError if the file cannot be parsed as JSON.
    """
    response = _s3.get_object(Bucket=BUCKET, Key=key)
    raw = response["Body"].read().decode("utf-8")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Cannot parse {key} as JSON: {e}") from e
    return data if isinstance(data, list) else [data]


# ---------------------------------------------------------------------------
# File movement
# ---------------------------------------------------------------------------

def _move(src_key, dst_key):
    """Non-atomic copy-then-delete. Deferred concern per D3."""
    _s3.copy_object(
        Bucket=BUCKET,
        CopySource={"Bucket": BUCKET, "Key": src_key},
        Key=dst_key,
    )
    _s3.delete_object(Bucket=BUCKET, Key=src_key)


def move_to_processed(key):
    filename = key.split("/")[-1]
    _move(key, PROCESSED_PREFIX + filename)


def move_to_failed(key):
    filename = key.split("/")[-1]
    _move(key, FAILED_PREFIX + filename)
    return FAILED_PREFIX + filename


# ---------------------------------------------------------------------------
# Report output
# ---------------------------------------------------------------------------

def write_report(report):
    """
    Serialise report to S3 under reports/.
    Retries once on failure; writes a minimal error report on second failure.

    Returns the S3 key written.
    """
    ts  = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    key = f"{REPORTS_PREFIX}triage_{ts}.json"
    body = json.dumps(report, indent=2)

    for attempt in range(1, 3):
        try:
            _s3.put_object(Bucket=BUCKET, Key=key, Body=body, ContentType="application/json")
            logging.info(f"Report written to s3://{BUCKET}/{key}")
            return key
        except ClientError as e:
            logging.error(f"S3 write attempt {attempt} failed: {e}")
            if attempt == 2:
                _write_error_report(key, str(e))
                return key
    return key  # unreachable, satisfies type checkers


def _write_error_report(key, error_msg):
    minimal = json.dumps({"error": "report write failed", "detail": error_msg})
    try:
        _s3.put_object(Bucket=BUCKET, Key=key, Body=minimal, ContentType="application/json")
    except ClientError:
        logging.critical(f"Both S3 write attempts failed for {key}. Report lost.")
