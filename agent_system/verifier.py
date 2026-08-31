"""
Deterministic Verifier — 9 safety checks that gate every proposal.

This is the core safety engine. Every check is rule-based and deterministic:
no LLM involvement in the accept/reject decision.

Checks (run in order, fail on first blocking):
  V1: No-regression      — every used action still ALLOWED by new policy
  V2: No PassRole escal. — iam:PassRole with Resource:"*" blocked
  V3: No admin star      — *:* or Action:"*" blocked
  V4: No credential mgmt — CreateAccessKey etc blocked
  V5: Sensitive scoping  — wildcards on IAM/KMS/RAM/Orgs/Secrets blocked
  V6: s3 admin-equiv     — s3:* treated as admin-equivalent
  V7: Syntax/structure   — Effect/Action/Resource present, service code, NotAction rules
  V8: DR permissions     — disaster-recovery-critical not stripped
  V9: ABAC tags          — required tag conditions preserved
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from iam_simulator import Decision, simulate
from .schemas import Check, Hypothesis, UsageEvidence, VerificationResult


# ---------------------------------------------------------------------------
# Sensitive action / service sets
# ---------------------------------------------------------------------------

PASSROLE_ACTIONS: Set[str] = {"iam:passrole"}

CREDENTIAL_ACTIONS: Set[str] = {
    "iam:createaccesskey",
    "iam:createloginprofile",
    "iam:updateaccesskey",
    "iam:deleteaccesskey",
    "iam:resyncmfadevice",
}

SENSITIVE_SERVICES: Set[str] = {
    "iam", "kms", "ram", "sso", "identitystore",
    "organizations", "secretsmanager",
}

DR_CRITICAL_ACTIONS: Set[str] = {
    "iam:getaccountauthorizationdetails",
    "iam:getaccountsummary",
    "s3:getbucketversioning",
    "backup:startbackupjob",
}


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _check_no_regression(
    hypothesis: Hypothesis,
    evidence: UsageEvidence,
) -> Check:
    """V1: Every used action must still be ALLOWED by the new policy."""
    used = evidence.used_action_names
    if not used:
        return Check(name="V1_no_regression", passed=True,
                     detail="No used actions to check (empty evidence).")

    policy = hypothesis.new_policy
    if not policy or not policy.get("Statement"):
        return Check(name="V1_no_regression", passed=False,
                     detail="regression: new policy has no statements, all used actions would be denied.")

    denied = []
    for action in used:
        decision = simulate(policy, action)
        if decision != Decision.ALLOWED:
            denied.append(action)

    if denied:
        first = denied[0]
        return Check(
            name="V1_no_regression",
            passed=False,
            detail=f"regression: action '{first}' was used but new policy denies it "
                   f"({len(denied)} total denied: {', '.join(denied[:5])})",
        )

    return Check(name="V1_no_regression", passed=True,
                 detail=f"All {len(used)} used actions still ALLOWED.")


def _check_no_passrole_escalation(hypothesis: Hypothesis) -> Check:
    """V2: No iam:PassRole with Resource:'*' and no scoping condition."""
    for stmt in hypothesis.new_policy.get("Statement", []):
        if stmt.get("Effect", "").lower() != "allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        has_passrole = any(a.lower() in PASSROLE_ACTIONS for a in actions)
        if not has_passrole:
            continue

        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]

        has_wildcard_resource = any(r == "*" for r in resources)
        has_condition = bool(stmt.get("Condition"))

        if has_wildcard_resource and not has_condition:
            return Check(
                name="V2_no_passrole_escalation",
                passed=False,
                detail="escalation: iam:PassRole with Resource:'*' survived without scoping condition.",
            )

    return Check(name="V2_no_passrole_escalation", passed=True,
                 detail="No unscoped iam:PassRole found.")


def _check_no_admin_star(hypothesis: Hypothesis) -> Check:
    """V3: No Action:'*' or '*:*' in an Allow statement."""
    for stmt in hypothesis.new_policy.get("Statement", []):
        if stmt.get("Effect", "").lower() != "allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        for a in actions:
            if a == "*" or a == "*:*":
                return Check(
                    name="V3_no_admin_star",
                    passed=False,
                    detail=f"escalation: wildcard admin action '{a}' present in Allow.",
                )

    return Check(name="V3_no_admin_star", passed=True,
                 detail="No wildcard admin actions found.")


def _check_no_credential_mgmt(hypothesis: Hypothesis) -> Check:
    """V4: No credential-management actions in Allow."""
    for stmt in hypothesis.new_policy.get("Statement", []):
        if stmt.get("Effect", "").lower() != "allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        for a in actions:
            if a.lower() in CREDENTIAL_ACTIONS:
                return Check(
                    name="V4_no_credential_mgmt",
                    passed=False,
                    detail=f"escalation: credential-management action '{a}' present.",
                )

    return Check(name="V4_no_credential_mgmt", passed=True,
                 detail="No credential-management actions found.")


def _check_sensitive_service_scoping(hypothesis: Hypothesis) -> Check:
    """V5: No wildcard action or Resource:'*' on sensitive services."""
    for stmt in hypothesis.new_policy.get("Statement", []):
        if stmt.get("Effect", "").lower() != "allow":
            continue

        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]

        has_wildcard_resource = any(r == "*" for r in resources)

        for a in actions:
            parts = a.split(":")
            if len(parts) >= 1:
                svc = parts[0].lower()
                action_part = parts[1].lower() if len(parts) > 1 else ""

                if svc in SENSITIVE_SERVICES:
                    if action_part == "*" or a.endswith(":*"):
                        return Check(
                            name="V5_sensitive_service_scoping",
                            passed=False,
                            detail=f"scope: sensitive service '{svc}' has wildcard action '{a}'.",
                        )
                    if has_wildcard_resource:
                        return Check(
                            name="V5_sensitive_service_scoping",
                            passed=False,
                            detail=f"scope: sensitive service '{svc}' action '{a}' with Resource:'*'.",
                        )

    return Check(name="V5_sensitive_service_scoping", passed=True,
                 detail="Sensitive services properly scoped.")


def _check_s3_admin_equivalent(hypothesis: Hypothesis) -> Check:
    """V6: s3:* is treated as admin-equivalent (bundles Delete/PutBucketPolicy)."""
    for stmt in hypothesis.new_policy.get("Statement", []):
        if stmt.get("Effect", "").lower() != "allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        for a in actions:
            if a.lower() == "s3:*":
                return Check(
                    name="V6_s3_admin_equivalent",
                    passed=False,
                    detail="scope: s3:* is admin-equivalent; enumerate used s3 actions instead.",
                )

    return Check(name="V6_s3_admin_equivalent", passed=True,
                 detail="No s3:* wildcard found.")


def _check_syntax_structure(hypothesis: Hypothesis) -> Check:
    """V7: Basic policy syntax validation."""
    statements = hypothesis.new_policy.get("Statement", [])

    if not statements:
        return Check(name="V7_syntax_structure", passed=False,
                     detail="syntax: policy has no Statement array.")

    for i, stmt in enumerate(statements):
        # Must have Effect
        if "Effect" not in stmt:
            return Check(name="V7_syntax_structure", passed=False,
                         detail=f"syntax: statement {i} missing Effect.")

        # Must have Action or NotAction
        if "Action" not in stmt and "NotAction" not in stmt:
            return Check(name="V7_syntax_structure", passed=False,
                         detail=f"syntax: statement {i} missing Action/NotAction.")

        # Must have Resource
        if "Resource" not in stmt:
            return Check(name="V7_syntax_structure", passed=False,
                         detail=f"syntax: statement {i} missing Resource.")

        # NotAction only in Deny
        if "NotAction" in stmt and stmt.get("Effect", "").lower() != "deny":
            return Check(name="V7_syntax_structure", passed=False,
                         detail=f"syntax: statement {i} uses NotAction in Allow (only valid in Deny).")

        # Actions must have service code (contain ':')
        actions = stmt.get("Action", stmt.get("NotAction", []))
        if isinstance(actions, str):
            actions = [actions]
        for a in actions:
            if a != "*" and ":" not in a:
                return Check(name="V7_syntax_structure", passed=False,
                             detail=f"syntax: action '{a}' lacks service code (missing ':').")

    return Check(name="V7_syntax_structure", passed=True,
                 detail="Policy syntax is valid.")


def _check_dr_permissions(
    hypothesis: Hypothesis,
    evidence: UsageEvidence,
) -> Check:
    """V8: Disaster-recovery-critical actions not stripped."""
    # Check if any DR actions were in granted but not in kept
    granted_lower = {a.lower() for a in evidence.granted_actions}
    kept_lower = {a.lower() for a in hypothesis.kept}

    stripped_dr = []
    for dr_action in DR_CRITICAL_ACTIONS:
        if dr_action in granted_lower and dr_action not in kept_lower:
            # Check if it's actually allowed by the new policy
            decision = simulate(hypothesis.new_policy, dr_action)
            if decision != Decision.ALLOWED:
                stripped_dr.append(dr_action)

    if stripped_dr:
        return Check(
            name="V8_dr_permissions",
            passed=False,
            detail=f"dr: removed critical DR permission '{stripped_dr[0]}'.",
        )

    return Check(name="V8_dr_permissions", passed=True,
                 detail="DR permissions preserved.")


def _check_abac_tags(
    hypothesis: Hypothesis,
    evidence: UsageEvidence,
) -> Check:
    """V9: Required ABAC tag conditions preserved."""
    # Check if original policy had tag conditions that are missing in new policy
    original_conditions = set()
    for stmt in evidence.current_policy.get("Statement", []):
        cond = stmt.get("Condition", {})
        for op_block in cond.values():
            if isinstance(op_block, dict):
                for key in op_block:
                    if "tag" in key.lower() or "Tag" in key:
                        original_conditions.add(key)

    if not original_conditions:
        return Check(name="V9_abac_tags", passed=True,
                     detail="No ABAC tag conditions to preserve.")

    new_conditions = set()
    for stmt in hypothesis.new_policy.get("Statement", []):
        cond = stmt.get("Condition", {})
        for op_block in cond.values():
            if isinstance(op_block, dict):
                for key in op_block:
                    if "tag" in key.lower() or "Tag" in key:
                        new_conditions.add(key)

    missing = original_conditions - new_conditions
    if missing:
        return Check(
            name="V9_abac_tags",
            passed=False,
            detail=f"abac: required tag condition '{next(iter(missing))}' dropped.",
        )

    return Check(name="V9_abac_tags", passed=True,
                 detail="ABAC tag conditions preserved.")


# ---------------------------------------------------------------------------
# Main verify function
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    ("V1", _check_no_regression),
    ("V2", _check_no_passrole_escalation),
    ("V3", _check_no_admin_star),
    ("V4", _check_no_credential_mgmt),
    ("V5", _check_sensitive_service_scoping),
    ("V6", _check_s3_admin_equivalent),
    ("V7", _check_syntax_structure),
    ("V8", _check_dr_permissions),
    ("V9", _check_abac_tags),
]


def verify(
    hypothesis: Hypothesis,
    evidence: UsageEvidence,
) -> VerificationResult:
    """
    Run all 9 deterministic checks against a remediation proposal.

    Returns VerificationResult with:
    - passed: True only if ALL checks pass
    - checks: list of all Check results
    - feedback: the first blocking failure's detail (for self-correction)
    """
    checks: List[Check] = []
    first_failure: Optional[str] = None

    for name, check_fn in ALL_CHECKS:
        # V1, V8, V9 need evidence; V2-V7 need only hypothesis
        if name in ("V1", "V8", "V9"):
            result = check_fn(hypothesis, evidence)
        else:
            result = check_fn(hypothesis)

        checks.append(result)

        if not result.passed and first_failure is None:
            first_failure = result.detail

    all_passed = all(c.passed for c in checks)

    return VerificationResult(
        passed=all_passed,
        checks=checks,
        feedback=first_failure or "",
    )
