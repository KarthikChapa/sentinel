#!/bin/bash
# Sentinel-IAM AWS Deployment Script
# Usage: ./deploy.sh [region] [environment]
# Example: ./deploy.sh us-east-1 production

set -euo pipefail

REGION="${1:-us-east-1}"
ENV="${2:-staging}"
APP_NAME="sentinel-iam"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

echo "════════════════════════════════════════════════════════"
echo "  Sentinel-IAM AWS Deployment"
echo "  Region:  $REGION"
echo "  Env:     $ENV"
echo "  Account: $ACCOUNT_ID"
echo "════════════════════════════════════════════════════════"

# ── Step 1: Create ECR Repository ─────────────────────────────
echo ""
echo "[1/6] Creating ECR repository..."
aws ecr describe-repositories --repository-names "$APP_NAME" --region "$REGION" 2>/dev/null || \
  aws ecr create-repository \
    --repository-name "$APP_NAME" \
    --region "$REGION" \
    --image-scanning-configuration scanOnPush=true

ECR_URI="$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$APP_NAME"
echo "  ECR URI: $ECR_URI"

# ── Step 2: Build and Push Docker Image ───────────────────────
echo ""
echo "[2/6] Building and pushing Docker image..."

# Login to ECR
aws ecr get-login-password --region "$REGION" | \
  docker login --username AWS --password-stdin "$ECR_URI"

# Build from the sentinel directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

docker build -t "$APP_NAME:latest" "$PROJECT_DIR"
docker tag "$APP_NAME:latest" "$ECR_URI:latest"
docker tag "$APP_NAME:latest" "$ECR_URI:$ENV"

docker push "$ECR_URI:latest"
docker push "$ECR_URI:$ENV"

echo "  Image pushed: $ECR_URI:$ENV"

# ── Step 3: Create IAM Roles ─────────────────────────────────
echo ""
echo "[3/6] Creating IAM roles..."

# Task execution role (for ECS agent)
EXECUTION_ROLE_NAME="sentinel-ecs-execution-role"
TASK_ROLE_NAME="sentinel-ecs-task-role"

# Create execution role if not exists
if ! aws iam get-role --role-name "$EXECUTION_ROLE_NAME" 2>/dev/null; then
  aws iam create-role \
    --role-name "$EXECUTION_ROLE_NAME" \
    --assume-role-policy-document file://"$SCRIPT_DIR/ecs-trust-policy.json"

  aws iam attach-role-policy \
    --role-name "$EXECUTION_ROLE_NAME" \
    --policy-arn "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"

  # Attach SecretsManager read for execution role
  aws iam put-role-policy \
    --role-name "$EXECUTION_ROLE_NAME" \
    --policy-name "SecretsManagerRead" \
    --policy-document '{
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Action": ["secretsmanager:GetSecretValue"],
        "Resource": "arn:aws:secretsmanager:'$REGION':'$ACCOUNT_ID':secret:sentinel/*"
      }]
    }'

  echo "  Created execution role: $EXECUTION_ROLE_NAME"
else
  echo "  Execution role exists: $EXECUTION_ROLE_NAME"
fi

# Create task role if not exists
if ! aws iam get-role --role-name "$TASK_ROLE_NAME" 2>/dev/null; then
  aws iam create-role \
    --role-name "$TASK_ROLE_NAME" \
    --assume-role-policy-document file://"$SCRIPT_DIR/ecs-trust-policy.json"

  aws iam put-role-policy \
    --role-name "$TASK_ROLE_NAME" \
    --policy-name "SentinelIAMTaskPolicy" \
    --policy-document file://"$SCRIPT_DIR/iam-policy.json"

  echo "  Created task role: $TASK_ROLE_NAME"
else
  echo "  Task role exists: $TASK_ROLE_NAME"
  # Update the policy
  aws iam put-role-policy \
    --role-name "$TASK_ROLE_NAME" \
    --policy-name "SentinelIAMTaskPolicy" \
    --policy-document file://"$SCRIPT_DIR/iam-policy.json"
  echo "  Updated task role policy"
fi

# ── Step 4: Create Secrets in Secrets Manager ────────────────
echo ""
echo "[4/6] Setting up AWS Secrets Manager..."

# Create secret for OpenAI API key (placeholder — update manually)
aws secretsmanager describe-secret --secret-id "sentinel/openai-api-key" --region "$REGION" 2>/dev/null || {
  aws secretsmanager create-secret \
    --name "sentinel/openai-api-key" \
    --description "OpenRouter/OpenAI API key for Sentinel-IAM" \
    --secret-string '{"OPENAI_API_KEY":"REPLACE_ME"}' \
    --region "$REGION"
  echo "  Created secret: sentinel/openai-api-key"
  echo "  WARNING: Update the secret value with your actual API key!"
}
echo "  Secret: sentinel/openai-api-key"

# ── Step 5: Create S3 Results Bucket ─────────────────────────
echo ""
echo "[5/6] Creating S3 results bucket..."
RESULTS_BUCKET="sentinel-results-$ACCOUNT_ID-$REGION"

if ! aws s3api head-bucket --bucket "$RESULTS_BUCKET" --region "$REGION" 2>/dev/null; then
  if [ "$REGION" = "us-east-1" ]; then
    aws s3api create-bucket --bucket "$RESULTS_BUCKET" --region "$REGION"
  else
    aws s3api create-bucket \
      --bucket "$RESULTS_BUCKET" \
      --region "$REGION" \
      --create-bucket-configuration LocationConstraint="$REGION"
  fi

  # Enable versioning for audit trail
  aws s3api put-bucket-versioning \
    --bucket "$RESULTS_BUCKET" \
    --versioning-configuration Status=Enabled

  # Block public access
  aws s3api put-public-access-block \
    --bucket "$RESULTS_BUCKET" \
    --public-access-block-configuration \
      BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

  echo "  Created bucket: $RESULTS_BUCKET"
else
  echo "  Bucket exists: $RESULTS_BUCKET"
fi

# ── Step 6: Create CloudWatch Log Group ──────────────────────
echo ""
echo "[6/6] Creating CloudWatch log group..."
aws logs create-log-group \
  --log-group-name "/ecs/sentinel-iam" \
  --region "$REGION" 2>/dev/null || echo "  Log group already exists"

echo ""
echo "════════════════════════════════════════════════════════"
echo "  Deployment Complete!"
echo "════════════════════════════════════════════════════════"
echo ""
echo "Next steps:"
echo ""
echo "1. Update secrets with your actual API keys:"
echo "   aws secretsmanager update-secret \\"
echo "     --secret-id sentinel/openai-api-key \\"
echo "     --secret-string '{\"OPENAI_API_KEY\":\"your-actual-key\"}' \\"
echo "     --region $REGION"
echo ""
echo "2. Update ecs-task-definition.json with your account details:"
echo "   - Replace YOUR_ACCOUNT_ID with $ACCOUNT_ID"
echo "   - Replace YOUR_REGION with $REGION"
echo ""
echo "3. Register the ECS task definition:"
echo "   aws ecs register-task-definition \\"
echo "     --cli-input-json file://deploy/ecs-task-definition.json \\"
echo "     --region $REGION"
echo ""
echo "4. Run the task (one-time evaluation):"
echo "   aws ecs run-task \\"
echo "     --cluster default \\"
echo "     --task-definition sentinel-iam \\"
echo "     --launch-type FARGATE \\"
echo "     --network-configuration 'awsvpcConfiguration={subnets=[subnet-xxx],securityGroups=[sg-xxx],assignPublicIp=ENABLED}' \\"
echo "     --region $REGION"
echo ""
echo "5. For scheduled runs (e.g., weekly), create EventBridge rule:"
echo "   See deploy/eventbridge-schedule.json"
echo ""
echo "Results will be written to CloudWatch Logs: /ecs/sentinel-iam"
echo "and S3 bucket: s3://$RESULTS_BUCKET/results/"
