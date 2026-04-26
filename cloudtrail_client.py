import json
import logging
import os
from datetime import datetime, timedelta, timezone

import boto3

_client = boto3.client("cloudtrail", region_name=os.environ.get("AWS_REGION", "us-east-1"))

# IAM-relevant event sources
_DEFAULT_SOURCES = [
    "iam.amazonaws.com",
    "sts.amazonaws.com",
    "signin.amazonaws.com",
]


class CloudTrailFetchError(Exception):
    pass


def count_recent_failures(username, minutes_back=60):
    """
    Count ConsoleLogin failures for a user in the last `minutes_back` minutes.

    Uses a single LookupEvents call filtered by Username, then counts
    client-side. Returns 0 on API error so scoring degrades gracefully.
    """
    end_time   = datetime.now(timezone.utc)
    start_time = end_time - timedelta(minutes=minutes_back)
    count = 0
    try:
        paginator = _client.get_paginator("lookup_events")
        pages = paginator.paginate(
            LookupAttributes=[{"AttributeKey": "Username", "AttributeValue": username}],
            StartTime=start_time,
            EndTime=end_time,
            PaginationConfig={"MaxItems": 50},
        )
        for page in pages:
            for entry in page.get("Events", []):
                if entry.get("EventName") != "ConsoleLogin":
                    continue
                try:
                    parsed = json.loads(entry.get("CloudTrailEvent", "{}"))
                    result = (parsed.get("responseElements") or {}).get("ConsoleLogin")
                    if result == "Failure" or parsed.get("errorCode"):
                        count += 1
                except json.JSONDecodeError:
                    pass
    except Exception as e:
        logging.warning(f"count_recent_failures failed for {username}: {e}")
    return count


def fetch_events(max_events=50, hours_back=24, event_sources=None):
    """
    Pull CloudTrail management events via LookupEvents.

    Args:
        max_events:    Total cap across all sources.
        hours_back:    How far back to look (max 90 days).
        event_sources: List of eventSource strings to query. Defaults to IAM sources.

    Returns:
        List of parsed CloudTrail event dicts.

    Raises:
        CloudTrailFetchError on API failure.
    """
    sources   = event_sources or _DEFAULT_SOURCES
    end_time  = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=hours_back)
    per_source = max(1, max_events // len(sources))

    events = []
    for source in sources:
        try:
            paginator = _client.get_paginator("lookup_events")
            pages = paginator.paginate(
                LookupAttributes=[{"AttributeKey": "EventSource", "AttributeValue": source}],
                StartTime=start_time,
                EndTime=end_time,
                PaginationConfig={"MaxItems": per_source},
            )
            for page in pages:
                for entry in page.get("Events", []):
                    raw_json = entry.get("CloudTrailEvent", "{}")
                    try:
                        events.append(json.loads(raw_json))
                    except json.JSONDecodeError as e:
                        logging.warning(f"Skipping malformed event {entry.get('EventId')}: {e}")
        except Exception as e:
            raise CloudTrailFetchError(f"LookupEvents failed for {source}: {e}") from e

    logging.info(f"Fetched {len(events)} event(s) from CloudTrail ({hours_back}h window)")
    return events[:max_events]
