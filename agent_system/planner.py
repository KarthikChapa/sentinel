"""
Planner / Semantic Router — classifies findings and builds the investigation DAG.

Routes each finding into one of 7 classes, each with a tailored remediation
strategy, then constructs a topologically-ordered DAG of parallel audit workers
feeding a synthesis step.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple

from .schemas import Alert, Task

# ---------------------------------------------------------------------------
# Finding classification (deterministic rules + LLM fallback)
# ---------------------------------------------------------------------------

# Keywords that drive deterministic classification before LLM is consulted
_CLASSIFICATION_RULES: List[Tuple[str, List[str]]] = [
    ("unused_role", ["unused", "dormant", "inactive", "no usage", "0 actions"]),
    ("passrole_escalation", ["passrole", "pass role", "iam:passrole"]),
    ("admin_star", ["*:*", "action:*", "administratoraccess", "admin"]),
    ("cross_account_trust", ["cross-account", "cross account", "trust policy", "external principal"]),
    ("sensitive_wildcard", ["kms:*", "secretsmanager:*", "kms:decrypt", "secrets"]),
    ("contradictory", ["contradict", "boundary", "conflicting", "ambiguous"]),
    ("wildcard_action", ["s3:*", ":*", "wildcard"]),
]

VALID_CLASSES = [
    "unused_role",
    "wildcard_action",
    "passrole_escalation",
    "admin_star",
    "cross_account_trust",
    "sensitive_wildcard",
    "contradictory",
]

# Strategy descriptions per class
STRATEGIES: Dict[str, str] = {
    "unused_role": "Propose detach/disable; retain self-management + DR permissions.",
    "wildcard_action": "Replace service:* with exact used action list from evidence.",
    "passrole_escalation": "Scope PassRole to specific role ARNs + condition.",
    "admin_star": "Replace *:* with per-service scoped actions from usage.",
    "cross_account_trust": "Scope trust to specific account/role + external-id.",
    "sensitive_wildcard": "Scope to specific resource ARNs; deny broad access.",
    "contradictory": "Lower confidence; force HITL escalation, no auto-remove.",
}


def classify_finding(alert: Alert) -> str:
    """
    Classify a finding into one of 7 routing classes.

    Uses deterministic keyword matching first, falls back to category field.
    Returns one of VALID_CLASSES.
    """
    # Check alert category directly
    cat = alert.category.lower().strip()
    if cat in VALID_CLASSES:
        return cat

    # Check title + category + payload for keyword matches
    searchable = f"{alert.title} {alert.category} {json.dumps(alert.payload)}".lower()

    for cls, keywords in _CLASSIFICATION_RULES:
        for kw in keywords:
            if kw in searchable:
                return cls

    # Default fallback
    return "wildcard_action"


def choose_strategy(route: str) -> str:
    """Return the remediation strategy description for a route class."""
    return STRATEGIES.get(route, STRATEGIES["wildcard_action"])


# ---------------------------------------------------------------------------
# DAG construction
# ---------------------------------------------------------------------------

def build_dag(alert: Alert, route: str) -> List[Task]:
    """
    Build a topologically-ordered DAG of investigative subtasks.

    Leaf tasks (audit workers) run in parallel; they have no dependencies.
    The structure is the same for all routes — the Actor uses the route/strategy
    to shape its remediation, not to skip evidence gathering.
    """
    principal = alert.principal or alert.service

    # Base parallel evidence-gathering tasks (no dependencies)
    tasks = [
        Task(
            id="t_cloudtrail",
            tool="cloudtrail_usage",
            args={"principal": principal, "days": 90},
            depends_on=[],
            rationale="Pull 90-day actual API usage from CloudTrail.",
        ),
        Task(
            id="t_last_accessed",
            tool="last_accessed",
            args={"principal": principal},
            depends_on=[],
            rationale="Get IAM Access Advisor last-accessed timestamps.",
        ),
        Task(
            id="t_analyzer",
            tool="analyzer_findings",
            args={"principal": principal},
            depends_on=[],
            rationale="Pull unused-access findings from IAM Access Analyzer.",
        ),
        Task(
            id="t_terraform",
            tool="terraform_state",
            args={"principal": principal},
            depends_on=[],
            rationale="Read the current Terraform HCL and live policy document.",
        ),
    ]

    # Route-specific augmentation
    if route == "passrole_escalation":
        tasks.append(Task(
            id="t_passrole_targets",
            tool="cloudtrail_usage",
            args={"principal": principal, "days": 90, "filter_action": "iam:PassRole"},
            depends_on=[],
            rationale="Identify specific roles passed to, for scoping PassRole.",
        ))

    if route == "cross_account_trust":
        tasks.append(Task(
            id="t_trust_policy",
            tool="terraform_state",
            args={"principal": principal, "include_trust": True},
            depends_on=[],
            rationale="Extract the trust policy to identify external principals.",
        ))

    return tasks


def plan(alert: Alert) -> Dict[str, Any]:
    """
    Full planning step: classify → build DAG → choose strategy.

    Returns a dict suitable for trace logging.
    """
    route = classify_finding(alert)
    strategy = choose_strategy(route)
    tasks = build_dag(alert, route)

    return {
        "route": route,
        "strategy": strategy,
        "tasks": [t.to_json() for t in tasks],
    }
