import json
import logging
import os
import time

import boto3

import main

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

_lambda = boto3.client("lambda", region_name="us-east-2")
ENRICHMENT_FUNCTION = os.environ.get("ENRICHMENT_FUNCTION_NAME", "enrichment-lambda")


def _prewarm_enrichment():
    """
    Fire an async ping to the enrichment Lambda to reduce cold-start latency
    before the main batch begins. InvocationType=Event means we don't wait
    for a response.
    """
    try:
        _lambda.invoke(
            FunctionName=ENRICHMENT_FUNCTION,
            InvocationType="Event",
            Payload=json.dumps({"action": "ping"}),
        )
        logging.info(f"Pre-warm ping sent to {ENRICHMENT_FUNCTION}")
    except Exception as e:
        # Non-fatal: enrichment failures are handled inside the agent loop
        logging.warning(f"Pre-warm ping failed (non-fatal): {e}")

    time.sleep(1)  # give the Lambda container a moment to initialise


def lambda_handler(event, context):
    """
    AWS Lambda entry point. Invoked by EventBridge on schedule.

    Returns the triage report dict (serialisable, visible in Lambda test console).
    """
    logging.info("Handler invoked — pre-warming enrichment Lambda")
    _prewarm_enrichment()

    logging.info("Starting triage batch")
    report = main.run()

    logging.info(
        f"Batch complete: {report['logs_processed']} processed, "
        f"{report['logs_failed']} failed"
    )
    return report
