# Sentinel-IAM — AWS Deployment Guide

Complete step-by-step guide to deploying Sentinel-IAM on AWS.

## Project Overview

**What it is:** A Python 3.11 application that performs Cloud IAM least-privilege
auto-remediation with a Human-in-the-Loop (HITL) gateway. It analyzes IAM roles/users,
generates least-privilege policies using LLM-powered reasoning (or deterministic mock),
runs it through a verifier loop, computes risk scores, and routes to HITL approval.

**Tech stack:**
| Component | Details |
|-----------|---------|
| Runtime | Python 3.11 |
| Entry points | `evaluator.py` (batch), `demo.py` (TUI), `lambda_handler.py` (API) |
| Docker | Multi-command image, currently set to run evaluator |
| Optional deps | openai, boto3, rich, slack_sdk, tabulate, python-dotenv |
| Data | `data/scenarios.json` (11 synthetic IAM scenarios) |
| Outputs | `results/metrics.json`, `results/trajectories.jsonl`, `results/memory.json` |

**Deployment modes:**
- `mock` mode — fully offline, no API keys, deterministic (best for CI/evaluation)
- `live` mode — real LLM calls via OpenRouter/OpenAI-compatible endpoint
- `SENTINEL_BACKEND=aws` — queries real AWS (CloudTrail, IAM, Access Analyzer)

## Recommended Architecture

```
EventBridge (schedule)        API Gateway (on-demand)
        \                         /
         \                       /
          v                     v
            Lambda (FARGATE-capable) or ECS Fargate
              |
              +-- CloudTrail (read)
              +-- IAM (read + simulate)
              +-- Access Analyzer (read)
              +-- Secrets Manager (API keys)
              +-- S3 (results bucket)
              +-- CloudWatch Logs (observability)
```

**Two deployment options:**

### Option A: ECS Fargate (Recommended for full runs)
- Run the full evaluator as a container
- 1 vCPU / 2 GB memory
- Results to S3, logs to CloudWatch
- Good for: scheduled full-suite runs, longer evaluations

### Option B: Lambda (Recommended for on-demand)
- `lambda_handler.py` is the entry point
- Pack the project + deps into a .zip
- Good for: API-triggered single scenarios, lightweight runs
- Limits: 15 min max duration (enough for mock-mode runs)

---

## PHASE 1: AWS Account Setup

### Step 1 — Install AWS CLI

```powershell
# Windows (via Chocolatey)
choco install awscli

# Or via pip
pip install awscli

# Verify
aws --version
```

### Step 2 — Configure AWS Credentials

```powershell
# Run in the directory (NOT C:\ — avoid credentials leaking to system paths incorrectly)
aws configure
# AWS Access Key ID:     <your-access-key>
# AWS Secret Access Key: <your-secret-key>
# Default region name:   us-east-1
# Default output format: json
```

Or use an IAM user with the policies from Phase 2.

### Step 3 — Verify Identity

```powershell
aws sts get-caller-identity
# Should print your account ID, ARN, and user ID
```

Set the account ID variable used below:
```powershell
$ACCOUNT_ID = (aws sts get-caller-identity --query Account --output text)
$REGION = "us-east-1"
```

---

## PHASE 2: Create IAM Roles and Policies

### Step 4 — Create the Task/Execution Role Trust Policy

```powershell
New-Item -ItemType Directory -Path "deploy" -Force

# Create roles (from deploy/ folder)
aws iam create-role `
  --role-name sentinel-ecs-execution-role `
  --assume-role-policy-document file://deploy/ecs-trust-policy.json

aws iam create-role `
  --role-name sentinel-ecs-task-role `
  --assume-role-policy-document file://deploy/ecs-trust-policy.json
```

### Step 5 — Attach AWS Managed Policies (Execution Role)

```powershell
aws iam attach-role-policy `
  --role-name sentinel-ecs-execution-role `
  --policy-arn "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
```

This lets ECS pull your image from ECR and read Secrets Manager.

### Step 6 — Attach Custom Task Policy

The task role only gets **read + simulate** permissions — never write. This is the
least-privilege design of the application itself.

```powershell
aws iam put-role-policy `
  --role-name sentinel-ecs-task-role `
  --policy-name SentinelIAMTaskPolicy `
  --policy-document file://deploy/iam-policy.json
```

**Key permissions granted (read-only):**
- `cloudtrail:LookupEvents`, `GetTrail`, `ListTrails`
- `iam:GetRole`, `GetPolicy`, `ListRoles`, `SimulateCustomPolicy`,
  `GenerateServiceLastAccessedDetails`
- `access-analyzer:ListFindings`, `ListAnalyzers`
- `s3:GetObject`/`PutObject` on the results bucket only
- `secretsmanager:GetSecretValue` on `sentinel/*` secrets only
- `logs:PutLogEvents` on `/ecs/sentinel-iam` only

> **Note:** If you later want the agent to actually *apply* policies in a live account,
> add `iam:PutRolePolicy` / `iam:DetachRolePolicy` scoped to specific ARNs — only after
> you've verified the verifier + HITL flow against real data.

---

## PHASE 3: Container Registry (ECR)

### Step 7 — Create ECR Repository

```powershell
aws ecr create-repository `
  --repository-name sentinel-iam `
  --image-scanning-configuration scanOnPush=true `
  --region $REGION
```

### Step 8 — Build and Push the Docker Image

```powershell
$ECR_URI = "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/sentinel-iam"

# Login (Windows PowerShell)
$pass = aws ecr get-login-password --region $REGION
docker login --username AWS --password-stdin "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

# Build from the sentinel directory
cd sentinel
docker build -t sentinel-iam:latest .
docker tag sentinel-iam:latest ${ECR_URI}:latest
docker tag sentinel-iam:latest ${ECR_URI}:production
docker push ${ECR_URI}:latest
docker push ${ECR_URI}:production
```

> **Tip:** The current `Dockerfile` runs `python scripts/generate_data.py` at build time
> and sets `CMD ["python", "evaluator.py"]`. For a reusable image, change the CMD to
> `tail -f /dev/null` and pass commands per-task, or keep as-is for one-shot runs.

---

## PHASE 4: Secrets Manager (API Keys)

### Step 9 — Store LLM API Keys

```powershell
aws secretsmanager create-secret `
  --name "sentinel/openai-api-key" `
  --description "OpenRouter API key for Sentinel-IAM live mode" `
  --secret-string '{"OPENAI_API_KEY":"sk-or-v1-your-actual-key"}' `
  --region $REGION

# HITL HMAC secret (used to sign approval tokens)
aws secretsmanager create-secret `
  --name "sentinel/hitl-secret" `
  --secret-string '{"SENTINEL_HITL_SECRET":"generate-a-long-random-string"}' `
  --region $REGION
```

> **Security:** Never commit these to git. Rotate quarterly via
> `aws secretsmanager rotate-secret`.

---

## PHASE 5: S3 Results Bucket

### Step 10 — Create Results Bucket

```powershell
$BUCKET = "sentinel-results-${ACCOUNT_ID}-${REGION}"

aws s3 mb "s3://$BUCKET" --region $REGION

# Versioning (audit trail of every run's artifacts)
aws s3api put-bucket-versioning `
  --bucket $BUCKET `
  --versioning-configuration Status=Enabled

# Block all public access
aws s3api put-public-access-block `
  --bucket $BUCKET `
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Lifecycle: move old results to Glacier after 90 days
aws s3api put-bucket-lifecycle-configuration `
  --bucket $BUCKET `
  --lifecycle-configuration '{"Rules":[{"ID":"ArchiveOldResults","Status":"Enabled","Filter":{"Prefix":"results/"},"Transitions":[{"Days":90,"StorageClass":"GLACIER"}]}]}'
```

---

## PHASE 6: Deployment Option A — ECS Fargate

### Step 11 — Create ECS Cluster (if needed)

```powershell
aws ecs create-cluster --cluster-name sentinel-iam --region $REGION
```

### Step 12 — Fill in the Task Definition

Open `deploy/ecs-task-definition.json` and replace:
- `YOUR_ACCOUNT_ID` → your account ID
- `YOUR_REGION` → your region

```powershell
aws ecs register-task-definition `
  --cli-input-json file://deploy/ecs-task-definition.json `
  --region $REGION
```

### Step 13 — Network Prerequisites

For Fargate you need a VPC with subnets. Use the default VPC or create one:

```powershell
# Check existing VPCs
aws ec2 describe-vpcs --query 'Vpcs[].[VpcId,CidrBlock,IsDefault]' --output table

# If using default VPC, get a subnet + security group
$SUBNET = (aws ec2 describe-subnets --region $REGION --query 'Subnets[0].SubnetId' --output text)
$SG = (aws ec2 describe-security-groups --filters "Name=is-default,Values=true" `
  --query 'SecurityGroups[0].GroupId' --output text)
```

### Step 14 — Run the Task

```powershell
aws ecs run-task `
  --cluster sentinel-iam `
  --task-definition sentinel-iam `
  --launch-type FARGATE `
  --network-configuration "awsvpcConfiguration={subnets=[$SUBNET],securityGroups=[$SG],assignPublicIp=ENABLED}" `
  --region $REGION
```

### Step 15 — Watch Logs

```powershell
aws logs tail "/ecs/sentinel-iam" --follow --region $REGION
```

### Step 16 — Fetch Results

```powershell
aws s3 ls "s3://$BUCKET/results/"
aws s3 sync "s3://$BUCKET/results/" ./aws-results/
```

---

## PHASE 7: Deployment Option B — Lambda

### Step 17 — Package the Project

```powershell
# Install Lambda Build Tool
pip install aws-lambda-builders

# Create the package
New-Item -ItemType Directory -Path lambda-build -Force
Copy-Item -Path "sentinel\*" -Destination "lambda-build\" -Recurse

# Build layers / dependencies
cd lambda-build
python -m venv .venv
.\.venv\Scripts\pip.exe install -r requirements.txt
.\.venv\Scripts\pip.exe install boto3 -t .

# Zip the package
Compress-Archive -Path * -DestinationPath sentinel-iam-lambda.zip -Force
```

### Step 18 — Create Lambda Function

```powershell
# Upload to S3
aws s3 cp sentinel-iam-lambda.zip "s3://$BUCKET/packaging/sentinel-iam-lambda.zip"

# Create the function
aws lambda create-function `
  --function-name sentinel-iam `
  --runtime python3.11 `
  --role "arn:aws:iam::${ACCOUNT_ID}:role/sentinel-ecs-task-role" `
  --handler lambda_handler.handler `
  --zip-file fileb://sentinel-iam-lambda.zip `
  --timeout 900 `
  --memory-size 1024 `
  --region $REGION
```

### Step 19 — Attach Lambda Policy

```powershell
aws iam put-role-policy `
  --role-name sentinel-ecs-task-role `
  --policy-name LambdaPolicy `
  --policy-document file://deploy/lambda-policy.json
```

### Step 20 — Test Invocation

```powershell
# Run full evaluation
aws lambda invoke `
  --function-name sentinel-iam `
  --payload '{"scenario_id": "sc-01"}' `
  response.json
Get-Content response.json
```

---

## PHASE 8: Scheduling (EventBridge)

### Step 21 — Weekly Scheduled Run

```powershell
# Create the events role
aws iam create-role `
  --role-name sentinel-events-role `
  --assume-role-policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sts:AssumeRole"}]
  }'

aws iam put-role-policy `
  --role-name sentinel-events-role `
  --policy-name AllowECSRun `
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Allow","Action":"ecs:RunTask","Resource":"arn:aws:ecs:*:*:task/*"}]
  }'

# Create the scheduled rule
aws events put-rule `
  --name sentinel-iam-weekly-eval `
  --schedule-expression "rate(7 days)" `
  --state ENABLED `
  --region $REGION

aws events put-targets `
  --rule sentinel-iam-weekly-eval `
  --targets 'file://deploy/eventbridge-target.json'
```

Or use Lambda + EventBridge schedule for simpler on-demand runs:
```powershell
aws lambda create-event-source-mapping `
  --event-source-name "arn:aws:events:$REGION:$ACCOUNT_ID:rule/sentinel-iam-weekly" `
  --target-arn "arn:aws:lambda:$REGION:$ACCOUNT_ID:function:sentinel-iam"
```

---

## PHASE 9: Monitoring & Alerts (Optional but Recommended)

### Step 22 — CloudWatch Alarms

```powershell
# Alarm on task failures
aws cloudwatch put-metric-alarm `
  --alarm-name "Sentinel-IAM-TaskFailures" `
  --namespace AWS/ECS `
  --metric-name ContainerInsufficientMemory `
  --statistic Sum `
  --period 300 `
  --evaluation-periods 1 `
  --threshold 1 `
  --comparison-operator GreaterThanOrEqualToThreshold `
  --alarm-actions "arn:aws:snss:$REGION:$ACCOUNT_ID:your-alert-topic"
```

### Step 23 — CloudTrail (audit the agent itself)

Since Sentinel-IAM touches IAM/CloudTrail APIs, enable CloudTrail on your account
(if not already) to log its own AWS API calls:

```powershell
trail_arn=$(aws cloudtrail create-trail --name sentinel-audit --enable-logs --region $REGION --query 'Trail.Arn' --output text)
aws cloudtrail start-logging --name sentinel-audit --region $REGION
```

---

## Environment Variables Reference

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `SENTINEL_MODE` | `mock` | No | `mock` (offline) or `live` (real LLM) |
| `SENTINEL_BACKEND` | `mock` | No | `mock`, `localstack`, or `aws` |
| `SENTINEL_AUTO_APPROVE` | `true` | No | Skip HITL for low-risk |
| `SENTINEL_MAX_RETRIES` | `3` | No | Verifier retry limit |
| `SENTINEL_LOOKBACK_DAYS` | `90` | No | CloudTrail lookback window |
| `SENTINEL_HITL_CHANNEL` | `auto` | No | `auto`, `tui`, `cli`, or `slack` |
| `SENTINEL_HITL_SECRET` | `dev-secret` | **Yes (prod)** | HMAC key for approval tokens |
| `OPENAI_API_KEY` | — | For live mode | OpenRouter/OpenAI key |
| `OPENAI_BASE_URL` | OpenRouter | No | Override LLM endpoint |
| `SENTINEL_MODEL` | Llama 3.1 8B | No | Primary model |
| `SENTINEL_FAST_MODEL` | Llama 3.1 8B | No | Lightweight model |
| `AWS_DEFAULT_REGION` | — | **Yes (prod)** | AWS region |
| `RESULTS_BUCKET` | — | For Lambda S3 | S3 results bucket name |

## Estimated Monthly Cost

| Resource | Config | Est. Cost |
|----------|--------|-----------|
| ECS Fargate | 1 vCPU / 2 GB, ~4h/week | ~$5–10 |
| S3 | 1 GB versioned | <$1 |
| CloudWatch Logs | ~100 MB | <$1 |
| ECR | 1 GB | <$1 |
| API Gateway + Lambda | 100k invocations | ~$5 |
| OpenRouter (live mode) | 1M tokens/week | $5–20 (varies by model) |
| **Total (ECS + mock mode)** | | **~$10–15/mo** |

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| `boto3 not installed` | Lambda package missing | Rebuild zip with `-t .` flag |
| `No IAM permission for cloudtrail:LookupEvents` | Task role missing policy | Re-attach `SentinelIAMTaskPolicy` |
| `Circuit breaker OPEN` | LLM endpoint down | Check `OPENAI_API_KEY` + base URL |
| `Token budget exhausted` | Run too large | Increase `TokenBudget.max_tokens_per_run` |
| Container `Insufficient CPU` | Fargate under-provisioned | Bump to 2 vCPU in task def |
| `No credential` error | Role not attached | Verify `taskRoleArn` in task def |

---

## Cleanup

```powershell
aws s3 rb "s3://$BUCKET" --force
aws ecs delete-cluster --cluster-name sentinel-iam
aws ecr delete-repository --repository-name sentinel-iam --force
aws iam delete-role --role-name sentinel-ecs-task-role
aws iam delete-role --role-name sentinel-ecs-execution-role
aws secretsmanager delete-secret --secret-id sentinel/openai-api-key
```

---

*Guide generated for `D:\d-sentinel\sentinel` — verify all role/policy names against
your actual account before running production workloads.*
