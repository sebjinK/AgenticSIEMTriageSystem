# Agentic SIEM

An AWS Lambda-based security triage system that uses an agentic LLM loop (via Amazon Bedrock) to automatically analyze and score IAM log events.

## How it works

1. **EventBridge** triggers the Lambda on a schedule
2. **S3 ingestion** — up to 10 JSON log files are read from `logs/incoming/`
3. **Rule-based scoring** — each log entry is scored deterministically (brute force, off-hours, unusual location, MFA status, risky events)
4. **Agentic loop** — an LLM (Bedrock) iterates up to 3 times per log, enriching context and building confidence. Stops early once confidence ≥ 0.8
5. **IP reputation check** — source IPs are checked against a reputation stub (post-MVP: AbuseIPDB / VirusTotal)
6. **Playbook selection** — a recommended response action is returned per severity (LOW / MEDIUM / HIGH)
7. **Report written** to `reports/` in S3; failed logs moved to `logs/failed/`; SNS alert sent on failures

## Architecture

```
EventBridge → Lambda (handler.py)
                ├── Pre-warm enrichment Lambda
                └── main.py (batch loop)
                      ├── s3_utils.py   — S3 read/write/move
                      ├── rules.py      — deterministic scoring
                      ├── agent.py      — Bedrock agentic loop
                      │     ├── bedrock_client.py
                      │     └── tools.py (IP reputation)
                      └── playbooks.py  — response actions
```

## Log entry format

```json
{
  "user": "alice",
  "event": "GetSecretValue",
  "source_ip": "1.2.3.4",
  "time": "03:15",
  "success": false,
  "location": "Russia",
  "mfa_used": false,
  "failed_attempts": 7
}
```

Required fields: `user`, `event`, `source_ip`, `time`

## Severity thresholds

| Score | Severity | Playbook action |
|-------|----------|-----------------|
| ≥ 7   | HIGH     | Disable account and alert SOC |
| 4–6   | MEDIUM   | Alert security team and monitor |
| < 4   | LOW      | Log and monitor |

## Environment variables

| Variable | Description |
|----------|-------------|
| `S3_BUCKET_NAME` | S3 bucket for logs and reports (required) |
| `SNS_TOPIC_ARN` | SNS topic ARN for failure alerts (optional) |
| `ENRICHMENT_FUNCTION_NAME` | Enrichment Lambda name (default: `enrichment-lambda`) |

## Deployment

```bash
# Build and push container image
docker build -t agentic-siem .

# Deploy via deploy.sh or push to ECR and update the Lambda function
./deploy.sh
```

## Local testing

```bash
python test_local.py
```

## S3 bucket structure

```
<bucket>/
  logs/
    incoming/    ← drop log files here
    processed/   ← moved here on success
    failed/      ← moved here on error
  reports/       ← triage_YYYY-MM-DD_HHMMSS.json
```
