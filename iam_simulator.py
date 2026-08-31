"""
Local deterministic IAM Policy Simulator.

Evaluates a single (action, resource, context) against an IAM policy document
using AWS-style precedence:
  1. Explicit Deny wins
  2. Matching Allow (with satisfied Condition) grants access
  3. Implicit Deny (default)

Supports:
  - Action / NotAction matching with glob wildcards (* and ?)
  - Resource matching with glob wildcards
  - Basic Condition operators: StringEquals, DateLessThan, DateGreaterThan

This mirrors AWS SimulateCustomPolicy closely enough for no-regression and
escalation checks, while remaining transparent and reproducible.
"""

from __future__ import annotations

import fnmatch
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class Decision(str, Enum):
    """IAM policy evaluation outcome."""
    ALLOWED = "allowed"
    EXPLICIT_DENY = "explicitDeny"
    IMPLICIT_DENY = "implicitDeny"


def simulate(
    policy: Dict[str, Any],
    action: str,
    resource: str = "*",
    context: Optional[Dict[str, Any]] = None,
) -> Decision:
    """
    Evaluate one action against a policy document.

    Args:
        policy: IAM policy document with "Version" and "Statement" list.
        action: The API action to test, e.g. "s3:GetObject".
        resource: The resource ARN to test against, default "*".
        context: Optional context keys for Condition evaluation,
                 e.g. {"aws:CurrentTime": "2026-08-01T00:00:00Z",
                        "aws:PrincipalTag/team": "platform"}.

    Returns:
        Decision.ALLOWED, Decision.EXPLICIT_DENY, or Decision.IMPLICIT_DENY.
    """
    context = context or {}
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    has_allow = False

    for stmt in statements:
        effect = stmt.get("Effect", "").lower()
        if not _action_matches(stmt, action):
            continue
        if not _resource_matches(stmt, resource):
            continue

        if effect == "deny":
            # Explicit deny — check condition
            if _condition_satisfied(stmt.get("Condition"), context):
                return Decision.EXPLICIT_DENY

        elif effect == "allow":
            if _condition_satisfied(stmt.get("Condition"), context):
                has_allow = True

    return Decision.ALLOWED if has_allow else Decision.IMPLICIT_DENY


# ---------------------------------------------------------------------------
# Action matching
# ---------------------------------------------------------------------------

def _action_matches(stmt: Dict[str, Any], action: str) -> bool:
    """Check if a statement's Action/NotAction matches the given action."""
    action_lower = action.lower()

    # NotAction — matches if the action is NOT in the list
    not_actions = stmt.get("NotAction")
    if not_actions is not None:
        if isinstance(not_actions, str):
            not_actions = [not_actions]
        for pattern in not_actions:
            if _glob_match(action_lower, pattern.lower()):
                return False
        return True

    # Action — matches if the action IS in the list
    actions = stmt.get("Action")
    if actions is None:
        return False
    if isinstance(actions, str):
        actions = [actions]
    for pattern in actions:
        if _glob_match(action_lower, pattern.lower()):
            return True
    return False


# ---------------------------------------------------------------------------
# Resource matching
# ---------------------------------------------------------------------------

def _resource_matches(stmt: Dict[str, Any], resource: str) -> bool:
    """Check if a statement's Resource matches the given resource."""
    resources = stmt.get("Resource")
    if resources is None:
        return True  # no resource constraint = matches all
    if isinstance(resources, str):
        resources = [resources]

    # If the request resource is "*", it means "any resource" — match any policy pattern
    if resource == "*":
        return True

    for pattern in resources:
        if _glob_match(resource, pattern):
            return True
    return False


# ---------------------------------------------------------------------------
# Condition evaluation
# ---------------------------------------------------------------------------

def _condition_satisfied(
    condition: Optional[Dict[str, Any]],
    context: Dict[str, Any],
) -> bool:
    """
    Evaluate IAM Condition block against context.
    
    Supported operators:
      - StringEquals / StringNotEquals
      - DateLessThan / DateGreaterThan
    
    Unsupported operators are treated as satisfied (permissive fallback)
    to avoid false negatives in the mock simulator.
    """
    if not condition:
        return True

    for operator, condition_block in condition.items():
        op = operator.lower().replace(":", "")
        for key, expected_value in condition_block.items():
            actual = context.get(key)

            if op == "stringequals":
                if actual is None:
                    return False
                expected_list = expected_value if isinstance(expected_value, list) else [expected_value]
                if str(actual) not in [str(v) for v in expected_list]:
                    return False

            elif op == "stringnotequals":
                if actual is not None:
                    expected_list = expected_value if isinstance(expected_value, list) else [expected_value]
                    if str(actual) in [str(v) for v in expected_list]:
                        return False

            elif op == "datelessthan":
                if actual is None:
                    return False
                try:
                    actual_dt = _parse_datetime(str(actual))
                    expected_dt = _parse_datetime(str(expected_value))
                    if not (actual_dt < expected_dt):
                        return False
                except (ValueError, TypeError):
                    pass  # permissive fallback

            elif op == "dategreaterthan":
                if actual is None:
                    return False
                try:
                    actual_dt = _parse_datetime(str(actual))
                    expected_dt = _parse_datetime(str(expected_value))
                    if not (actual_dt > expected_dt):
                        return False
                except (ValueError, TypeError):
                    pass

            # Unsupported operators: permissive fallback (treat as satisfied)

    return True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _glob_match(value: str, pattern: str) -> bool:
    """
    Match a value against a glob pattern.
    Supports * (any chars) and ? (single char).
    """
    return fnmatch.fnmatch(value, pattern)


def _parse_datetime(s: str) -> datetime:
    """Parse ISO-8601 datetime string."""
    # Handle common formats
    for fmt in (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    raise ValueError(f"Cannot parse datetime: {s}")


# ---------------------------------------------------------------------------
# Batch evaluation helper
# ---------------------------------------------------------------------------

def simulate_all(
    policy: Dict[str, Any],
    actions: List[str],
    resource: str = "*",
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Decision]:
    """
    Evaluate multiple actions against a policy.
    Returns {action: Decision} mapping.
    """
    return {
        action: simulate(policy, action, resource, context)
        for action in actions
    }


def find_denied_used_actions(
    policy: Dict[str, Any],
    used_actions: List[str],
    resource: str = "*",
    context: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """
    Return the subset of used_actions that the policy does NOT allow.
    These are regressions — actions that would break if the policy is applied.
    """
    denied = []
    for action in used_actions:
        decision = simulate(policy, action, resource, context)
        if decision != Decision.ALLOWED:
            denied.append(action)
    return denied
