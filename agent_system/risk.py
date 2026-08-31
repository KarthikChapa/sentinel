"""
Deterministic Risk Engine — scores the remediation risk BEFORE HITL.

Computes a risk score from observable signals to decide the automation boundary:
  LOW    (< 0.3): auto-apply eligible
  MEDIUM (0.3-0.6): HITL recommended
  HIGH   (> 0.6): mandatory HITL, no auto-apply regardless of config

The risk score is deterministic and auditable — never LLM-generated.
"""

from __future__ import annotations

from typing import Any, Dict, List, Set

from .schemas import Hypothesis


# ---------------------------------------------------------------------------
# Action sensitivity tiers
# ---------------------------------------------------------------------------

CRITICAL_ACTIONS: Set[str] = {
    "iam:CreatePolicy",
    "iam:AttachRolePolicy",
    "iam:AttachUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutUserPolicy",
    "iam:PassRole",
    "iam:CreateRole",
    "iam:UpdateAssumeRolePolicy",
    "sts:AssumeRole",
    "organizations:*",
}

HIGH_ACTIONS: Set[str] = {
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateAccessKey",
    "kms:Decrypt",
    "kms:Encrypt",
    "kms:CreateGrant",
    "secretsmanager:GetSecretValue",
    "secretsmanager:PutSecretValue",
    "secretsmanager:DeleteSecret",
}

MEDIUM_ACTIONS: Set[str] = {
    "s3:DeleteObject",
    "s3:DeleteBucket",
    "s3:PutBucketPolicy",
    "ec2:RunInstances",
    "ec2:TerminateInstances",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
}

# Sensitive service prefixes
SENSITIVE_SERVICES: Set[str] = {
    "iam:", "kms:", "secretsmanager:", "organizations:",
    "ram:", "sso:", "identitystore:",
}


# ---------------------------------------------------------------------------
# Scoring functions
# ---------------------------------------------------------------------------

def _action_sensitivity(hypothesis: Hypothesis) -> float:
    """
    Score based on the most sensitive action being changed.

    0.0 = all low-sensitivity actions
    0.4 = critical actions involved
    """
    all_actions: Set[str] = set()
    for stmt in hypothesis.new_policy.get("Statement", []):
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        all_actions.update(actions)

    # Also check removed actions — removing critical actions is high-impact
    all_actions.update(hypothesis.removed)

    # Check from most to least sensitive
    for action in all_actions:
        if action in CRITICAL_ACTIONS or action == "*" or action.endswith(":*"):
            for svc in SENSITIVE_SERVICES:
                if action.startswith(svc) or action == "*":
                    return 0.4
        if action in CRITICAL_ACTIONS:
            return 0.4

    for action in all_actions:
        if action in HIGH_ACTIONS:
            return 0.3
        for svc in SENSITIVE_SERVICES:
            if action.startswith(svc):
                return 0.3

    for action in all_actions:
        if action in MEDIUM_ACTIONS:
            return 0.2

    return 0.1  # all low-sensitivity


def _scope_breadth(hypothesis: Hypothesis) -> float:
    """
    Score based on resource breadth.

    0.0 = all specific ARNs
    0.2 = wildcards present
    """
    for stmt in hypothesis.new_policy.get("Statement", []):
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        for r in resources:
            if r == "*":
                return 0.2
            if r.endswith(":*"):
                return 0.15

    return 0.0


def _blast_radius(hypothesis: Hypothesis) -> float:
    """
    Score based on the number of permissions being changed.

    More changes = higher blast radius.
    """
    total_changes = len(hypothesis.removed) + len(hypothesis.kept)
    if total_changes == 0:
        return 0.0
    removed_ratio = len(hypothesis.removed) / max(1, total_changes)

    if len(hypothesis.removed) > 50:
        return 0.2
    elif len(hypothesis.removed) > 20:
        return 0.15
    elif len(hypothesis.removed) > 5:
        return 0.1
    return 0.05


def _confidence_inverse(confidence_score: float) -> float:
    """
    Lower confidence = higher risk.

    Maps confidence 0-1 to risk contribution 0-0.2.
    """
    return round((1.0 - confidence_score) * 0.2, 2)


# ---------------------------------------------------------------------------
# Main scoring
# ---------------------------------------------------------------------------

RISK_TIERS = {
    "LOW": (0.0, 0.3),
    "MEDIUM": (0.3, 0.6),
    "HIGH": (0.6, 1.0),
}


def compute_risk(
    hypothesis: Hypothesis,
    confidence_score: float = 0.5,
) -> Dict[str, Any]:
    """
    Compute a deterministic risk score for a remediation proposal.

    Returns:
    {
        "score": 0.45,
        "tier": "MEDIUM",
        "components": {
            "action_sensitivity": 0.3,
            "scope_breadth": 0.0,
            "blast_radius": 0.1,
            "confidence_inverse": 0.05
        },
        "auto_apply_eligible": false,
        "mandatory_hitl": false
    }
    """
    components = {
        "action_sensitivity": _action_sensitivity(hypothesis),
        "scope_breadth": _scope_breadth(hypothesis),
        "blast_radius": _blast_radius(hypothesis),
        "confidence_inverse": _confidence_inverse(confidence_score),
    }

    score = round(sum(components.values()), 2)
    score = min(1.0, score)

    # Determine tier
    tier = "LOW"
    for tier_name, (low, high) in RISK_TIERS.items():
        if low <= score < high:
            tier = tier_name
            break
    if score >= 0.6:
        tier = "HIGH"

    return {
        "score": score,
        "tier": tier,
        "components": components,
        "auto_apply_eligible": tier == "LOW",
        "mandatory_hitl": tier == "HIGH",
    }
