#!/usr/bin/env python3
"""
Generate the 11 synthetic benchmark scenarios for Sentinel-IAM.

Each scenario includes:
  - alert: the finding that triggers the pipeline
  - fixtures: cloudtrail events, current policy/HCL, terraform state, etc.
  - _oracle: expected class, safe actions, must_escalate, expected metrics

Fixed seed → byte-for-byte reproducible output.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def _make_policy(actions: list, resource: str = "*") -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": actions, "Resource": resource}],
    }


def _make_cloudtrail(used_actions: list) -> list:
    return [
        {"action": a, "count": 50 + i * 10, "last_used": f"2026-08-{28 - i:02d}"}
        for i, a in enumerate(used_actions)
    ]


def generate_scenarios() -> list:
    scenarios = []

    # ── sc-01: unused role dormant 90+ days ─────────────────────────
    scenarios.append({
        "id": "sc-01-unused-role",
        "description": "IAM role completely dormant for 90+ days",
        "alert": {
            "id": "alert-01", "title": "Unused IAM Role: data-pipeline-legacy",
            "category": "unused_role", "severity": "MEDIUM",
            "principal": "arn:aws:iam::123456789012:role/data-pipeline-legacy",
            "service": "data-pipeline-legacy",
        },
        "fixtures": {
            "cloudtrail": [],  # no usage at all
            "last_accessed": [],
            "analyzer_findings": [{"finding": "UnusedRole", "days_unused": 120}],
            "current_policy": _make_policy(["s3:GetObject", "s3:PutObject", "logs:CreateLogGroup"]),
            "current_hcl": 'resource "aws_iam_role" "data_pipeline_legacy" {\n  # dormant 120 days\n}',
            "terraform_state": {"name": "data-pipeline-legacy"},
        },
        "_oracle": {
            "expected_class": "unused_role",
            "safe_actions": [],
            "must_escalate": False,
        },
    })

    # ── sc-02: s3:* wildcard, only Get/PutObject used ───────────────
    scenarios.append({
        "id": "sc-02-s3-wildcard",
        "description": "S3 wildcard but only GetObject and PutObject actually used",
        "alert": {
            "id": "alert-02", "title": "Overly broad S3 permissions: upload-service",
            "category": "wildcard_action", "severity": "HIGH",
            "principal": "arn:aws:iam::123456789012:role/upload-service",
            "service": "upload-service",
        },
        "fixtures": {
            "cloudtrail": _make_cloudtrail(["s3:GetObject", "s3:PutObject"]),
            "last_accessed": [{"service": "s3", "last_accessed": "2026-08-28"}],
            "analyzer_findings": [{"finding": "UnusedActions", "unused": ["s3:DeleteObject", "s3:DeleteBucket", "s3:PutBucketPolicy"]}],
            "current_policy": _make_policy(["s3:*"]),
            "current_hcl": 'resource "aws_iam_role_policy" "upload" {\n  policy = jsonencode({ Action = ["s3:*"] })\n}',
            "terraform_state": {"name": "upload-service"},
        },
        "_oracle": {
            "expected_class": "wildcard_action",
            "safe_actions": ["s3:GetObject", "s3:PutObject"],
            "must_escalate": False,
        },
    })

    # ── sc-03: iam:PassRole with Resource:"*" ───────────────────────
    scenarios.append({
        "id": "sc-03-passrole-escalation",
        "description": "iam:PassRole granted on Resource:* — privilege escalation path",
        "alert": {
            "id": "alert-03", "title": "Unscoped PassRole: deploy-role",
            "category": "passrole_escalation", "severity": "CRITICAL",
            "principal": "arn:aws:iam::123456789012:role/deploy-role",
            "service": "deploy-role",
        },
        "fixtures": {
            "cloudtrail": _make_cloudtrail(["lambda:CreateFunction", "lambda:InvokeFunction", "iam:PassRole"]),
            "last_accessed": [{"service": "lambda", "last_accessed": "2026-08-28"}, {"service": "iam", "last_accessed": "2026-08-25"}],
            "analyzer_findings": [],
            "current_policy": _make_policy(["lambda:*", "iam:PassRole", "logs:*"]),
            "current_hcl": 'resource "aws_iam_role_policy" "deploy" {\n  policy = jsonencode({ Action = ["lambda:*", "iam:PassRole"] })\n}',
            "terraform_state": {"name": "deploy-role"},
        },
        "_oracle": {
            "expected_class": "passrole_escalation",
            "safe_actions": ["lambda:CreateFunction", "lambda:InvokeFunction", "iam:PassRole"],
            "must_escalate": False,
            "resource_arns": ["arn:aws:iam::123456789012:role/deploy-role-execution-role"],
        },
    })

    # ── sc-04: iam:CreateAccessKey never used ───────────────────────
    scenarios.append({
        "id": "sc-04-createaccesskey",
        "description": "CreateAccessKey granted but never used — credential management risk",
        "alert": {
            "id": "alert-04", "title": "Unused credential actions: ci-bot",
            "category": "wildcard_action", "severity": "HIGH",
            "principal": "arn:aws:iam::123456789012:user/ci-bot",
            "service": "ci-bot",
        },
        "fixtures": {
            "cloudtrail": _make_cloudtrail(["s3:GetObject", "ecr:GetAuthorizationToken"]),
            "last_accessed": [{"service": "s3", "last_accessed": "2026-08-28"}, {"service": "ecr", "last_accessed": "2026-08-27"}],
            "analyzer_findings": [{"finding": "UnusedActions", "unused": ["iam:CreateAccessKey", "iam:DeleteAccessKey"]}],
            "current_policy": _make_policy(["s3:GetObject", "ecr:GetAuthorizationToken", "iam:CreateAccessKey", "iam:DeleteAccessKey"]),
            "current_hcl": 'resource "aws_iam_user_policy" "ci_bot" {}',
            "terraform_state": {"name": "ci-bot"},
        },
        "_oracle": {
            "expected_class": "wildcard_action",
            "safe_actions": ["s3:GetObject", "ecr:GetAuthorizationToken"],
            "must_escalate": False,
        },
    })

    # ── sc-05: *:* admin on CI/CD deploy role ───────────────────────
    scenarios.append({
        "id": "sc-05-cicd-admin-star",
        "description": "Full admin (*:*) on a CI/CD deploy role",
        "alert": {
            "id": "alert-05", "title": "Admin access: cicd-deployer",
            "category": "admin_star", "severity": "CRITICAL",
            "principal": "arn:aws:iam::123456789012:role/cicd-deployer",
            "service": "cicd-deployer",
        },
        "fixtures": {
            "cloudtrail": _make_cloudtrail(["s3:PutObject", "ecr:PushImage", "ecs:UpdateService", "logs:PutLogEvents"]),
            "last_accessed": [{"service": "s3", "last_accessed": "2026-08-28"}, {"service": "ecs", "last_accessed": "2026-08-27"}],
            "analyzer_findings": [{"finding": "AdminAccess", "note": "Action:* granted"}],
            "current_policy": _make_policy(["*"]),
            "current_hcl": 'resource "aws_iam_role_policy_attachment" "admin" {\n  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"\n}',
            "terraform_state": {"name": "cicd-deployer"},
        },
        "_oracle": {
            "expected_class": "admin_star",
            "safe_actions": ["s3:PutObject", "ecr:PushImage", "ecs:UpdateService", "logs:PutLogEvents"],
            "must_escalate": False,
        },
    })

    # ── sc-06: over-broad cross-account trust ───────────────────────
    scenarios.append({
        "id": "sc-06-cross-account",
        "description": "Trust policy allows any principal from partner account",
        "alert": {
            "id": "alert-06", "title": "Broad cross-account trust: shared-data-reader",
            "category": "cross_account_trust", "severity": "HIGH",
            "principal": "arn:aws:iam::123456789012:role/shared-data-reader",
            "service": "shared-data-reader",
        },
        "fixtures": {
            "cloudtrail": _make_cloudtrail(["s3:GetObject", "s3:ListBucket"]),
            "last_accessed": [{"service": "s3", "last_accessed": "2026-08-28"}],
            "analyzer_findings": [{"finding": "BroadTrust", "external_account": "987654321098"}],
            "current_policy": _make_policy(["s3:GetObject", "s3:ListBucket", "s3:PutObject"]),
            "current_hcl": 'resource "aws_iam_role" "shared_data_reader" {\n  assume_role_policy = "arn:aws:iam::987654321098:root"\n}',
            "terraform_state": {"name": "shared-data-reader", "trust_policy": {"Principal": {"AWS": "arn:aws:iam::987654321098:root"}}},
        },
        "_oracle": {
            "expected_class": "cross_account_trust",
            "safe_actions": ["s3:GetObject", "s3:ListBucket"],
            "must_escalate": False,
        },
    })

    # ── sc-07: KMS decrypt on all keys ──────────────────────────────
    scenarios.append({
        "id": "sc-07-kms-decrypt-all",
        "description": "KMS Decrypt on all keys but only one key actually used",
        "alert": {
            "id": "alert-07", "title": "Broad KMS access: encryption-service",
            "category": "sensitive_wildcard", "severity": "HIGH",
            "principal": "arn:aws:iam::123456789012:role/encryption-service",
            "service": "encryption-service",
        },
        "fixtures": {
            "cloudtrail": [
                {"action": "kms:Decrypt", "count": 200, "last_used": "2026-08-28",
                 "resource": "arn:aws:kms:us-east-1:123456789012:key/abc-123"},
            ],
            "last_accessed": [{"service": "kms", "last_accessed": "2026-08-28"}],
            "analyzer_findings": [{"finding": "BroadKMS", "note": "kms:* on Resource:*"}],
            "current_policy": _make_policy(["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]),
            "current_hcl": 'resource "aws_iam_role_policy" "enc" {\n  # kms:* on all keys\n}',
            "terraform_state": {"name": "encryption-service"},
        },
        "_oracle": {
            "expected_class": "sensitive_wildcard",
            "safe_actions": ["kms:Decrypt"],
            "must_escalate": False,
            "resource_arns": ["arn:aws:kms:us-east-1:123456789012:key/abc-123"],
        },
    })

    # ── sc-08: machine identity ~90k entitlements, ~2% used ─────────
    used_8 = [f"s3:GetObject", f"sqs:SendMessage", f"sqs:ReceiveMessage",
              f"logs:PutLogEvents", f"logs:CreateLogStream"]
    granted_8 = used_8 + [f"ec2:Action{i}" for i in range(95)]  # simulate ~100 total
    scenarios.append({
        "id": "sc-08-machine-90k",
        "description": "Machine identity with massive entitlements, ~5% used",
        "alert": {
            "id": "alert-08", "title": "Over-entitled machine identity: batch-processor",
            "category": "wildcard_action", "severity": "HIGH",
            "principal": "arn:aws:iam::123456789012:role/batch-processor",
            "service": "batch-processor",
        },
        "fixtures": {
            "cloudtrail": _make_cloudtrail(used_8),
            "last_accessed": [{"service": "s3", "last_accessed": "2026-08-28"}, {"service": "sqs", "last_accessed": "2026-08-27"}],
            "analyzer_findings": [{"finding": "MassiveUnused", "unused_count": len(granted_8) - len(used_8)}],
            "current_policy": _make_policy(granted_8),
            "current_hcl": f'# {len(granted_8)} actions granted',
            "terraform_state": {"name": "batch-processor"},
        },
        "_oracle": {
            "expected_class": "wildcard_action",
            "safe_actions": used_8,
            "must_escalate": False,
        },
    })

    # ── sc-09: human role over-permissioned after team change ───────
    scenarios.append({
        "id": "sc-09-human-team-change",
        "description": "Developer moved teams, old permissions lingering",
        "alert": {
            "id": "alert-09", "title": "Stale permissions: dev-alice",
            "category": "wildcard_action", "severity": "MEDIUM",
            "principal": "arn:aws:iam::123456789012:user/dev-alice",
            "service": "dev-alice",
        },
        "fixtures": {
            "cloudtrail": _make_cloudtrail(["codecommit:GitPull", "codecommit:GitPush", "s3:GetObject"]),
            "last_accessed": [{"service": "codecommit", "last_accessed": "2026-08-28"}, {"service": "s3", "last_accessed": "2026-08-26"}],
            "analyzer_findings": [{"finding": "UnusedActions", "unused": ["ec2:RunInstances", "ec2:TerminateInstances", "rds:CreateDBInstance"]}],
            "current_policy": _make_policy(["codecommit:*", "s3:GetObject", "ec2:RunInstances", "ec2:TerminateInstances", "rds:CreateDBInstance"]),
            "current_hcl": 'resource "aws_iam_user_policy" "dev_alice" {}',
            "terraform_state": {"name": "dev-alice"},
        },
        "_oracle": {
            "expected_class": "wildcard_action",
            "safe_actions": ["codecommit:GitPull", "codecommit:GitPush", "s3:GetObject"],
            "must_escalate": False,
        },
    })

    # ── sc-10: Secrets Manager wildcard read ─────────────────────────
    scenarios.append({
        "id": "sc-10-secrets-wildcard",
        "description": "SecretsManager:* but only reads one specific secret",
        "alert": {
            "id": "alert-10", "title": "Broad secrets access: app-backend",
            "category": "sensitive_wildcard", "severity": "HIGH",
            "principal": "arn:aws:iam::123456789012:role/app-backend",
            "service": "app-backend",
        },
        "fixtures": {
            "cloudtrail": [
                {"action": "secretsmanager:GetSecretValue", "count": 300, "last_used": "2026-08-28",
                 "resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:db-creds-abc123"},
            ],
            "last_accessed": [{"service": "secretsmanager", "last_accessed": "2026-08-28"}],
            "analyzer_findings": [{"finding": "BroadSecrets"}],
            "current_policy": _make_policy(["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret", "secretsmanager:ListSecrets"]),
            "current_hcl": 'resource "aws_iam_role_policy" "backend" {}',
            "terraform_state": {"name": "app-backend"},
        },
        "_oracle": {
            "expected_class": "sensitive_wildcard",
            "safe_actions": ["secretsmanager:GetSecretValue"],
            "must_escalate": False,
            "resource_arns": ["arn:aws:secretsmanager:us-east-1:123456789012:secret:db-creds-abc123"],
        },
    })

    # ── sc-11: CONTRADICTORY — sensitive action at lookback boundary ──
    scenarios.append({
        "id": "sc-11-contradictory-boundary",
        "description": "Sensitive action used exactly once 89 days ago at lookback boundary",
        "alert": {
            "id": "alert-11", "title": "Ambiguous usage: security-audit-role",
            "category": "contradictory", "severity": "HIGH",
            "principal": "arn:aws:iam::123456789012:role/security-audit-role",
            "service": "security-audit-role",
        },
        "fixtures": {
            "cloudtrail": [
                {"action": "iam:GetAccountAuthorizationDetails", "count": 1, "last_used": "2026-06-02"},  # 89 days ago
                {"action": "s3:GetObject", "count": 50, "last_used": "2026-08-28"},
            ],
            "last_accessed": [
                {"service": "iam", "last_accessed": "2026-06-02"},
                {"service": "s3", "last_accessed": "2026-08-28"},
            ],
            "analyzer_findings": [
                {"finding": "UnusedAction", "action": "iam:GetAccountAuthorizationDetails",
                 "note": "Used once, 89 days ago — at lookback boundary"},
            ],
            "current_policy": _make_policy([
                "iam:GetAccountAuthorizationDetails", "iam:GetAccountSummary",
                "s3:GetObject", "s3:ListBucket",
            ]),
            "current_hcl": 'resource "aws_iam_role_policy" "audit" {}',
            "terraform_state": {"name": "security-audit-role"},
        },
        "_oracle": {
            "expected_class": "contradictory",
            "safe_actions": ["s3:GetObject", "iam:GetAccountAuthorizationDetails"],
            "must_escalate": True,  # MUST force HITL, not auto-remove
        },
    })

    return scenarios


def main():
    output_path = Path(__file__).parent.parent / "data" / "scenarios.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    scenarios = generate_scenarios()
    output_path.write_text(
        json.dumps(scenarios, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"Generated {len(scenarios)} scenarios → {output_path}")


if __name__ == "__main__":
    main()
