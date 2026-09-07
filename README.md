<div align="center">

# Sentinel-IAM

### Evidence-driven IAM least-privilege remediation with deterministic verification and human approval

`AWS Lambda` · `CloudTrail` · `IAM Access Analyzer` · `Amazon S3` · `Slack HITL`

</div>

## Architecture

```mermaid
flowchart LR
    A[EventBridge / Alert] --> B[AWS Lambda]
    B --> C[Planner]
    C --> D[Evidence Workers]
    D --> E[CloudTrail]
    D --> F[IAM Last Accessed]
    D --> G[Access Analyzer]
    D --> H[Terraform State]
    D --> I[Actor]
    I --> J[Policy Simulator + Verifier]
    J -->|retry| I
    J --> K[Risk Engine]
    K --> L[Slack HITL]
    L --> M[S3 Results + CloudWatch Logs]
```

Sentinel-IAM collects real usage and policy evidence from AWS, then uses an agent workflow to propose a least-privilege IAM policy. Every proposal is checked by a deterministic policy simulator and verifier; failed checks are returned to the actor for correction.

Verified changes are risk-scored before execution. Sensitive remediations require human approval through Slack, while run metrics, audit traces, and remediation memory are stored in Amazon S3 and execution logs are captured in CloudWatch.

## Results

| Metric | Baseline | Sentinel-IAM |
|---|---:|---:|
| Broken-access rate | 46.06% | **0%** |
| Escalation paths remaining | 10 | **1** |
| Classification accuracy | 0% | **100%** |
| Average permission reduction | 54.2% | **55.6%** |

Evaluation: **11 IAM scenarios**. Full artifacts: [`metrics.json`](metrics.json), [`memory.json`](memory.json), and [`trajectories.jsonl`](trajectories.jsonl).

## AWS Deployment

Sentinel-IAM runs on AWS Lambda, stores evaluation artifacts in Amazon S3, emits execution logs to CloudWatch, and is scheduled through EventBridge.

![AWS Lambda deployment](docs/images/aws-lambda.png)

![AWS Lambda evaluation result](docs/images/aws-lambda-test.png)

![Amazon S3 evaluation artifacts](docs/images/aws-s3-results.png)

<p align="center">
  <img src="docs/images/aws-eventbridge.png" alt="EventBridge weekly schedule" width="49%" />
  <img src="docs/images/aws-cloudwatch.png" alt="CloudWatch Lambda logs" width="49%" />
</p>

## Human Approval

Risk-scored remediation summaries are delivered from AWS to Slack for review and approval.

![Slack remediation notification](docs/images/slack-notification.png)

## Local Evaluation

```bash
python scripts/generate_data.py
python evaluator.py
```

<p align="center">
  <img src="docs/images/terminal-evaluation.png" alt="Local evaluation output" width="49%" />
  <img src="docs/images/terminal-trace.png" alt="Agent trajectory output" width="49%" />
</p>
