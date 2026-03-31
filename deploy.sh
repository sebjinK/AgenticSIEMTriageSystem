#!/usr/bin/env bash
# deploy.sh — build, push, and wire the agenticSIEM stack
# Usage: ./deploy.sh [--update]   (first run creates; --update redeploys image only)
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration — edit these before first run
# ---------------------------------------------------------------------------
REGION="us-east-2"
BUCKET_NAME="your-siem-bucket"          # must be globally unique
FUNCTION_NAME="siem-triage"
ENRICHMENT_FUNCTION_NAME="enrichment-lambda"
ECR_REPO="siem-triage"
SNS_TOPIC_NAME="siem-triage-alerts"
ALERT_EMAIL="you@example.com"           # SNS subscription email
SCHEDULE="rate(1 hour)"                 # EventBridge schedule expression
HANDLER_ROLE_NAME="siem-handler-role"
ENRICHMENT_ROLE_NAME="siem-enrichment-role"

UPDATE_ONLY=false
if [[ "${1:-}" == "--update" ]]; then UPDATE_ONLY=true; fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info()    { echo "[INFO]  $*" >&2; }
success() { echo "[OK]    $*" >&2; }
warn()    { echo "[WARN]  $*" >&2; }
die()     { echo "[ERROR] $*" >&2; exit 1; }

require() {
    for cmd in "$@"; do
        command -v "$cmd" &>/dev/null || die "'$cmd' not found — install it first"
    done
}

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
require aws docker

info "Resolving AWS account ID..."
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text --region "$REGION")
ECR_URI="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${ECR_REPO}"
info "Account: $ACCOUNT_ID | Region: $REGION"

# ---------------------------------------------------------------------------
# S3 bucket + prefix scaffold
# ---------------------------------------------------------------------------
setup_s3() {
    info "Checking S3 bucket: $BUCKET_NAME"
    if aws s3api head-bucket --bucket "$BUCKET_NAME" --region "$REGION" 2>/dev/null; then
        success "Bucket already exists"
    else
        info "Creating bucket..."
        aws s3api create-bucket \
            --bucket "$BUCKET_NAME" \
            --region "$REGION" \
            --create-bucket-configuration LocationConstraint="$REGION"
        # Block all public access
        aws s3api put-public-access-block \
            --bucket "$BUCKET_NAME" \
            --public-access-block-configuration \
              "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
        success "Bucket created and public access blocked"
    fi

    # Create logical prefixes via empty placeholder objects
    for prefix in logs/incoming/ logs/processed/ logs/failed/ reports/; do
        aws s3api put-object --bucket "$BUCKET_NAME" --key "$prefix" --content-length 0 \
            --region "$REGION" > /dev/null
    done
    success "S3 prefixes scaffolded"
}

# ---------------------------------------------------------------------------
# IAM roles
# ---------------------------------------------------------------------------
create_role_if_missing() {
    local role_name="$1" trust_policy="$2"
    if aws iam get-role --role-name "$role_name" &>/dev/null; then
        success "Role $role_name already exists"
    else
        aws iam create-role \
            --role-name "$role_name" \
            --assume-role-policy-document "$trust_policy" > /dev/null
        info "Created role $role_name"
    fi
}

LAMBDA_TRUST='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}'

setup_iam() {
    info "Setting up IAM roles..."

    create_role_if_missing "$HANDLER_ROLE_NAME"    "$LAMBDA_TRUST"
    create_role_if_missing "$ENRICHMENT_ROLE_NAME" "$LAMBDA_TRUST"

    # Attach basic Lambda execution policy to both roles
    aws iam attach-role-policy \
        --role-name "$HANDLER_ROLE_NAME" \
        --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole 2>/dev/null || true
    aws iam attach-role-policy \
        --role-name "$ENRICHMENT_ROLE_NAME" \
        --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole 2>/dev/null || true

    # Inline policy for the handler role
    aws iam put-role-policy \
        --role-name "$HANDLER_ROLE_NAME" \
        --policy-name "siem-handler-policy" \
        --policy-document "{
  \"Version\": \"2012-10-17\",
  \"Statement\": [
    {
      \"Effect\": \"Allow\",
      \"Action\": [\"bedrock:InvokeModel\"],
      \"Resource\": \"arn:aws:bedrock:${REGION}::foundation-model/anthropic.claude-haiku-4-5\"
    },
    {
      \"Effect\": \"Allow\",
      \"Action\": [\"s3:ListBucket\"],
      \"Resource\": \"arn:aws:s3:::${BUCKET_NAME}\",
      \"Condition\": {\"StringLike\": {\"s3:prefix\": [\"logs/incoming/*\"]}}
    },
    {
      \"Effect\": \"Allow\",
      \"Action\": [\"s3:GetObject\", \"s3:DeleteObject\"],
      \"Resource\": \"arn:aws:s3:::${BUCKET_NAME}/logs/incoming/*\"
    },
    {
      \"Effect\": \"Allow\",
      \"Action\": [\"s3:PutObject\"],
      \"Resource\": [
        \"arn:aws:s3:::${BUCKET_NAME}/logs/processed/*\",
        \"arn:aws:s3:::${BUCKET_NAME}/logs/failed/*\",
        \"arn:aws:s3:::${BUCKET_NAME}/reports/*\"
      ]
    },
    {
      \"Effect\": \"Allow\",
      \"Action\": [\"lambda:InvokeFunction\"],
      \"Resource\": \"arn:aws:lambda:${REGION}:${ACCOUNT_ID}:function:${ENRICHMENT_FUNCTION_NAME}\"
    },
    {
      \"Effect\": \"Allow\",
      \"Action\": [\"sns:Publish\"],
      \"Resource\": \"arn:aws:sns:${REGION}:${ACCOUNT_ID}:${SNS_TOPIC_NAME}\"
    }
  ]
}"
    success "IAM roles and policies configured"
}

# ---------------------------------------------------------------------------
# ECR + Docker
# ---------------------------------------------------------------------------
setup_ecr() {
    info "Checking ECR repository: $ECR_REPO"
    if aws ecr describe-repositories --repository-names "$ECR_REPO" --region "$REGION" &>/dev/null; then
        success "ECR repository already exists"
    else
        aws ecr create-repository --repository-name "$ECR_REPO" --region "$REGION" > /dev/null
        success "ECR repository created"
    fi
}

build_and_push() {
    info "Logging in to ECR..."
    aws ecr get-login-password --region "$REGION" \
        | docker login --username AWS --password-stdin "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

    info "Building Docker image..."
    docker build --platform linux/amd64 -t "${ECR_REPO}:latest" .

    info "Tagging and pushing..."
    docker tag "${ECR_REPO}:latest" "${ECR_URI}:latest"
    docker push "${ECR_URI}:latest"
    success "Image pushed to $ECR_URI:latest"
}

# ---------------------------------------------------------------------------
# SNS
# ---------------------------------------------------------------------------
setup_sns() {
    info "Setting up SNS topic: $SNS_TOPIC_NAME"
    SNS_TOPIC_ARN=$(aws sns create-topic \
        --name "$SNS_TOPIC_NAME" \
        --region "$REGION" \
        --query TopicArn --output text)

    # Subscribe email (idempotent — re-subscribing the same address is safe)
    aws sns subscribe \
        --topic-arn "$SNS_TOPIC_ARN" \
        --protocol email \
        --notification-endpoint "$ALERT_EMAIL" \
        --region "$REGION" > /dev/null

    success "SNS topic ready: $SNS_TOPIC_ARN"
    warn "Check $ALERT_EMAIL for a subscription confirmation email and confirm it before first run"
    echo "$SNS_TOPIC_ARN"
}

# ---------------------------------------------------------------------------
# Lambda
# ---------------------------------------------------------------------------
HANDLER_ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${HANDLER_ROLE_NAME}"

create_or_update_lambda() {
    local sns_topic_arn="$1"

    local env_vars="Variables={S3_BUCKET_NAME=${BUCKET_NAME},SNS_TOPIC_ARN=${sns_topic_arn},ENRICHMENT_FUNCTION_NAME=${ENRICHMENT_FUNCTION_NAME}}"

    if aws lambda get-function --function-name "$FUNCTION_NAME" --region "$REGION" &>/dev/null; then
        info "Updating Lambda image..."
        aws lambda update-function-code \
            --function-name "$FUNCTION_NAME" \
            --image-uri "${ECR_URI}:latest" \
            --region "$REGION" > /dev/null
        aws lambda wait function-updated \
            --function-name "$FUNCTION_NAME" \
            --region "$REGION"
        aws lambda update-function-configuration \
            --function-name "$FUNCTION_NAME" \
            --environment "$env_vars" \
            --region "$REGION" > /dev/null
        success "Lambda updated"
    else
        info "Creating Lambda function (waiting for IAM role to propagate)..."
        sleep 10   # IAM role propagation delay
        aws lambda create-function \
            --function-name "$FUNCTION_NAME" \
            --package-type Image \
            --code "ImageUri=${ECR_URI}:latest" \
            --role "$HANDLER_ROLE_ARN" \
            --timeout 180 \
            --memory-size 256 \
            --environment "$env_vars" \
            --region "$REGION" > /dev/null
        aws lambda wait function-active \
            --function-name "$FUNCTION_NAME" \
            --region "$REGION"
        success "Lambda created"
    fi
}

# ---------------------------------------------------------------------------
# EventBridge
# ---------------------------------------------------------------------------
setup_eventbridge() {
    local rule_name="${FUNCTION_NAME}-schedule"
    info "Setting up EventBridge rule: $rule_name ($SCHEDULE)"

    aws events put-rule \
        --name "$rule_name" \
        --schedule-expression "$SCHEDULE" \
        --state ENABLED \
        --region "$REGION" > /dev/null

    local function_arn
    function_arn=$(aws lambda get-function \
        --function-name "$FUNCTION_NAME" \
        --region "$REGION" \
        --query Configuration.FunctionArn --output text)

    # Allow EventBridge to invoke the Lambda
    aws lambda add-permission \
        --function-name "$FUNCTION_NAME" \
        --statement-id "eventbridge-${rule_name}" \
        --action lambda:InvokeFunction \
        --principal events.amazonaws.com \
        --source-arn "arn:aws:events:${REGION}:${ACCOUNT_ID}:rule/${rule_name}" \
        --region "$REGION" 2>/dev/null || true   # ignore if permission already exists

    aws events put-targets \
        --rule "$rule_name" \
        --targets "Id=1,Arn=${function_arn}" \
        --region "$REGION" > /dev/null

    success "EventBridge rule configured"
}

# ---------------------------------------------------------------------------
# CloudWatch alarm
# ---------------------------------------------------------------------------
setup_cloudwatch_alarm() {
    local sns_topic_arn="$1"
    info "Setting up CloudWatch alarm for Lambda errors..."
    aws cloudwatch put-metric-alarm \
        --alarm-name "${FUNCTION_NAME}-errors" \
        --alarm-description "Fires when siem-triage Lambda errors exceed threshold" \
        --metric-name Errors \
        --namespace AWS/Lambda \
        --dimensions "Name=FunctionName,Value=${FUNCTION_NAME}" \
        --statistic Sum \
        --period 300 \
        --evaluation-periods 1 \
        --threshold 1 \
        --comparison-operator GreaterThanOrEqualToThreshold \
        --alarm-actions "$sns_topic_arn" \
        --treat-missing-data notBreaching \
        --region "$REGION"
    success "CloudWatch alarm configured"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if $UPDATE_ONLY; then
    info "--- Update mode: rebuilding and redeploying image only ---"
    setup_ecr
    build_and_push
    SNS_TOPIC_ARN=$(aws sns list-topics --region "$REGION" \
        --query "Topics[?contains(TopicArn, '${SNS_TOPIC_NAME}')].TopicArn" \
        --output text)
    create_or_update_lambda "$SNS_TOPIC_ARN"
else
    info "--- Full deployment ---"
    setup_s3
    setup_iam
    setup_ecr
    build_and_push
    SNS_TOPIC_ARN=$(setup_sns)
    create_or_update_lambda "$SNS_TOPIC_ARN"
    setup_eventbridge
    setup_cloudwatch_alarm "$SNS_TOPIC_ARN"
fi

echo ""
echo "====================================================="
echo " Deployment complete"
echo "====================================================="
echo "  Lambda:      $FUNCTION_NAME"
echo "  Image:       $ECR_URI:latest"
echo "  Bucket:      s3://$BUCKET_NAME"
echo "  Schedule:    $SCHEDULE"
echo "  Alerts:      $ALERT_EMAIL"
echo ""
echo "  Drop test logs into:  s3://$BUCKET_NAME/logs/incoming/"
echo "  Reports appear in:    s3://$BUCKET_NAME/reports/"
echo "====================================================="