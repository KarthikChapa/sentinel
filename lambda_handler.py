# AWS Lambda Handler for Sentinel-IAM
# Deploy with: serverless deploy (see serverless.yml)
# Or manually: aws lambda create-function ...

import json
import os
import sys

# Add the app directory to Python path (Lambda package includes /var/task)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import Settings
from agent_system.logger import TrajectoryLogger
from agent_system.memory import RemediationMemory
from agent_system.orchestrator import investigate
from baseline import run_baseline
from evaluator import score_run, aggregate_metrics

SLACK_BOT_SECRET_ID = "sentinel/slack/BOT_TOKEN"


def _load_slack_config():
    """
    Load Slack credentials. Token comes from Secrets Manager (never in env);
    channel comes from the SLACK_CHANNEL environment variable.
    Returns {"token": ..., "channel": ...} or None if not configured.
    """
    channel = os.environ.get("SLACK_CHANNEL", "").strip()
    if not channel:
        return None
    try:
        import boto3

        sm = boto3.client("secretsmanager")
        secret = sm.get_secret_value(SecretId=SLACK_BOT_SECRET_ID)
        token = json.loads(secret["SecretString"]).get("SLACK_BOT_TOKEN", "").strip()
        if not token or token.startswith("PENDING"):
            return None
        return {"token": token, "channel": channel}
    except Exception:
        return None


def _post_slack_summary(slack_cfg, bl_agg, adv_agg, n_scenarios, bucket) -> dict:
    """Post the final comparison summary to the configured Slack channel."""
    if not slack_cfg:
        return {"slack": "skipped (not configured)"}
    try:
        from slack_sdk import WebClient

        client = WebClient(token=slack_cfg["token"])
        improvement = bl_agg["avg_broken_access_rate"] - adv_agg["avg_broken_access_rate"]
        esc_closed = (
            bl_agg["total_escalation_remaining"] - adv_agg["total_escalation_remaining"]
        )
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": ":shield: Sentinel-IAM Results"}},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"Evaluated *{n_scenarios}* scenarios\n\n"
                        f":dart: *Broken-Access Rate*\n"
                        f"  Baseline: `{bl_agg['avg_broken_access_rate']:.1%}` | "
                        f"Advanced: `{adv_agg['avg_broken_access_rate']:.1%}` | "
                        f"Improvement: `{improvement:+.1%}`\n\n"
                        f":lock: *Escalation Paths* — baseline `{bl_agg['total_escalation_remaining']}`, "
                        f"advanced `{adv_agg['total_escalation_remaining']}` (closed: `{esc_closed}`)\n\n"
                        f":scissors: *Avg Reduction* — `{adv_agg['avg_reduction_pct']:.1f}%\n\n"
                        f":robot_face: *Retries:* `{adv_agg['total_retries']}` | "
                        f":white_check_mark: *Classification:* `{adv_agg['classification_accuracy']:.0%}`"
                    ),
                },
            },
        ]
        if bucket:
            blocks.append({
                "type": "divider",
            },)
            blocks.append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"Artifacts: `s3://{bucket}/results/`"}],
            })
        resp = client.chat_postMessage(channel=slack_cfg["channel"], text="Sentinel-IAM evaluation results", blocks=blocks)
        return {"slack": "posted", "ts": resp.get("ts")}
    except Exception as exc:
        return {"slack": f"post failed: {exc}"}


def handler(event, context):
    """
    AWS Lambda entry point for Sentinel-IAM evaluation.

    Trigger events:
    - EventBridge scheduled rule (weekly evaluation)
    - API Gateway (on-demand single scenario)
    - Direct invocation with {"scenario_id": "sc-01-unused-role"}

    Environment variables expected:
    - SENTINEL_MODE: mock|live
    - SENTINEL_BACKEND: mock|aws
    - SENTINEL_AUTO_APPROVE: true|false
    - AWS_DEFAULT_REGION: region for boto3 clients
    - RESULTS_BUCKET: S3 bucket for results
    """
    import time
    from pathlib import Path

    # Parse input
    scenario_filter = event.get("scenario_id") or event.get("scenario")
    out_dir = "/tmp/results"  # Lambda writable directory

    # Load scenarios
    scenarios_path = os.path.join(os.path.dirname(__file__), "data", "scenarios.json")
    if not os.path.exists(scenarios_path):
        from scripts.generate_data import main as gen
        gen()

    with open(scenarios_path) as f:
        scenarios = json.load(f)

    if scenario_filter:
        scenarios = [s for s in scenarios if s["id"].startswith(scenario_filter)]
        if not scenarios:
            return {
                "statusCode": 404,
                "body": json.dumps({"error": f"No scenario matching '{scenario_filter}'"}),
            }

    # Initialize
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    # chdir so relative paths (e.g. results/tf_state.json in mock_terraform_apply)
    # resolve into the writable /tmp area instead of /var/task (read-only)
    os.chdir(out_dir)
    settings = Settings()
    tracer = TrajectoryLogger(
        path=os.path.join(out_dir, "trajectories.jsonl"), append=False
    )
    memory = RemediationMemory(path=os.path.join(out_dir, "memory.json"))

    baseline_scores = []
    advanced_scores = []

    # Run evaluation
    for scenario in scenarios:
        sid = scenario["id"]
        oracle = scenario.get("_oracle", {})
        fixtures = scenario.get("fixtures", {})

        all_granted = []
        for stmt in fixtures.get("current_policy", {}).get("Statement", []):
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            all_granted.extend(actions)

        bl_result = run_baseline(scenario, settings, tracer)
        bl_score = score_run(bl_result, oracle, all_granted)
        baseline_scores.append(bl_score)

        adv_result = investigate(scenario, settings, tracer, memory)
        adv_score = score_run(adv_result, oracle, all_granted)
        advanced_scores.append(adv_score)

    bl_agg = aggregate_metrics(baseline_scores)
    adv_agg = aggregate_metrics(advanced_scores)

    # Build results
    results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": settings.mode,
        "scenarios_count": len(scenarios),
        "baseline": {"aggregate": bl_agg, "per_scenario": baseline_scores},
        "advanced": {"aggregate": adv_agg, "per_scenario": advanced_scores},
    }

    # Write metrics
    metrics_path = os.path.join(out_dir, "metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(results, f, indent=2, default=str)

    bucket = os.environ.get("RESULTS_BUCKET", "")

    # Post summary to Slack (notification, not interactive approval)
    slack_cfg = _load_slack_config()
    slack_result = _post_slack_summary(slack_cfg, bl_agg, adv_agg, len(scenarios), bucket)
    results["slack"] = slack_result

    # Write metrics JSON again so the slack status is persisted too
    with open(metrics_path, "w") as f:
        json.dump(results, f, indent=2, default=str)

    # Optionally upload to S3
    if bucket:
        try:
            import boto3

            s3 = boto3.client("s3")
            timestamp = time.strftime("%Y-%m-%d/%H-%M-%S")
            for filename in ["metrics.json", "trajectories.jsonl", "memory.json"]:
                filepath = os.path.join(out_dir, filename)
                if os.path.exists(filepath):
                    s3.upload_file(
                        filepath, bucket, f"results/{timestamp}/{filename}"
                    )
            results["s3_results"] = f"s3://{bucket}/results/{timestamp}/"
        except Exception as exc:
            results["s3_error"] = str(exc)

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "message": "Evaluation complete",
                "scenarios": len(scenarios),
                "avg_broken_access_baseline": bl_agg["avg_broken_access_rate"],
                "avg_broken_access_advanced": adv_agg["avg_broken_access_rate"],
                "escalation_paths_baseline": bl_agg["total_escalation_remaining"],
                "escalation_paths_advanced": adv_agg["total_escalation_remaining"],
                "classification_accuracy": adv_agg["classification_accuracy"],
                "slack": slack_result.get("slack"),
            }
        ),
    }
