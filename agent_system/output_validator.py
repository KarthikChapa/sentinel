"""
Output Validation Layer — validates LLM responses before acceptance.

Runs on every LLM response. Catches hallucinations, schema violations,
grounding failures, and inconsistencies BEFORE the output reaches the
verifier or HITL gateway.

This is distinct from the Verifier (verifier.py):
  - Verifier checks the POLICY for safety (V1-V9 IAM rules)
  - OutputValidator checks the LLM OUTPUT for correctness (schema, grounding)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


# ═══════════════════════════════════════════════════════════════════════════
#  VALIDATION RESULT
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ValidationIssue:
    """A single validation issue."""
    check: str           # e.g. "schema", "grounding", "consistency"
    severity: str        # "error", "warning"
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return {"check": self.check, "severity": self.severity, "detail": self.detail}


@dataclass
class ValidationResult:
    """Result of validating an LLM output."""
    valid: bool
    issues: List[ValidationIssue] = field(default_factory=list)
    corrected_output: Optional[Dict[str, Any]] = None  # Auto-corrected version if possible

    @property
    def errors(self) -> List[ValidationIssue]:
        return [i for i in self.issues if i.severity == "error"]

    @property
    def warnings(self) -> List[ValidationIssue]:
        return [i for i in self.issues if i.severity == "warning"]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": len(self.errors),
            "warnings": len(self.warnings),
            "issues": [i.to_dict() for i in self.issues],
        }


# ═══════════════════════════════════════════════════════════════════════════
#  SCHEMA VALIDATION
# ═══════════════════════════════════════════════════════════════════════════

# Valid AWS action format: service:ActionName
_RE_ACTION = re.compile(r"^[a-zA-Z0-9-]+:[a-zA-Z0-9*]+$")


def validate_schema(output: Dict[str, Any]) -> List[ValidationIssue]:
    """
    Validate that LLM output matches the expected Hypothesis schema.

    Expected:
      {
        "new_policy": {"Version": "...", "Statement": [...]},
        "removed": ["service:Action", ...],
        "kept": ["service:Action", ...],
        "confidence": 0.0-1.0,
        "requires_hitl": bool,
        "rationale": "string"
      }
    """
    issues: List[ValidationIssue] = []

    # Required top-level keys
    required = ["new_policy", "removed", "kept"]
    for key in required:
        if key not in output:
            issues.append(ValidationIssue(
                check="schema", severity="error",
                detail=f"Missing required key: '{key}'",
            ))

    # new_policy structure
    policy = output.get("new_policy")
    if policy is not None:
        if not isinstance(policy, dict):
            issues.append(ValidationIssue(
                check="schema", severity="error",
                detail="'new_policy' must be a dict",
            ))
        else:
            stmts = policy.get("Statement")
            if stmts is not None and not isinstance(stmts, list):
                issues.append(ValidationIssue(
                    check="schema", severity="error",
                    detail="'new_policy.Statement' must be a list",
                ))
            elif isinstance(stmts, list):
                for i, stmt in enumerate(stmts):
                    if not isinstance(stmt, dict):
                        issues.append(ValidationIssue(
                            check="schema", severity="error",
                            detail=f"Statement[{i}] must be a dict",
                        ))
                        continue
                    if "Effect" not in stmt:
                        issues.append(ValidationIssue(
                            check="schema", severity="error",
                            detail=f"Statement[{i}] missing 'Effect'",
                        ))
                    elif stmt["Effect"] not in ("Allow", "Deny"):
                        issues.append(ValidationIssue(
                            check="schema", severity="error",
                            detail=f"Statement[{i}] Effect must be 'Allow' or 'Deny', got '{stmt['Effect']}'",
                        ))
                    if "Action" not in stmt:
                        issues.append(ValidationIssue(
                            check="schema", severity="error",
                            detail=f"Statement[{i}] missing 'Action'",
                        ))
                    if "Resource" not in stmt:
                        issues.append(ValidationIssue(
                            check="schema", severity="warning",
                            detail=f"Statement[{i}] missing 'Resource' (defaults to '*')",
                        ))

    # removed / kept must be lists of strings
    for key in ("removed", "kept"):
        val = output.get(key)
        if val is not None:
            if not isinstance(val, list):
                issues.append(ValidationIssue(
                    check="schema", severity="error",
                    detail=f"'{key}' must be a list, got {type(val).__name__}",
                ))
            else:
                for i, item in enumerate(val):
                    if not isinstance(item, str):
                        issues.append(ValidationIssue(
                            check="schema", severity="warning",
                            detail=f"'{key}[{i}]' should be a string, got {type(item).__name__}",
                        ))

    # confidence range
    conf = output.get("confidence")
    if conf is not None:
        try:
            conf_val = float(conf)
            if not (0.0 <= conf_val <= 1.0):
                issues.append(ValidationIssue(
                    check="schema", severity="warning",
                    detail=f"'confidence' should be 0-1, got {conf_val}",
                ))
        except (TypeError, ValueError):
            issues.append(ValidationIssue(
                check="schema", severity="warning",
                detail=f"'confidence' not a valid number: {conf}",
            ))

    return issues


# ═══════════════════════════════════════════════════════════════════════════
#  GROUNDING CHECKS
# ═══════════════════════════════════════════════════════════════════════════

def validate_grounding(
    output: Dict[str, Any],
    granted_actions: List[str],
    used_actions: List[str],
) -> List[ValidationIssue]:
    """
    Verify LLM output is grounded in evidence, not hallucinated.

    Checks:
    - Every action in 'removed' exists in granted_actions or is a wildcard expansion
    - Every action in 'kept' exists in evidence (used_actions or granted_actions)
    - No hallucinated service namespaces
    """
    issues: List[ValidationIssue] = []

    # Normalize to sets for lookup
    granted_set = set(a.lower() for a in granted_actions)
    used_set = set(a.lower() for a in used_actions)
    all_known = granted_set | used_set

    # Extract service namespaces from known actions
    known_services: Set[str] = set()
    for a in granted_actions + used_actions:
        if ":" in a:
            known_services.add(a.split(":")[0].lower())

    # Check removed actions
    removed = output.get("removed", [])
    if isinstance(removed, list):
        hallucinated_removed = []
        for action in removed:
            if not isinstance(action, str):
                continue
            a_lower = action.lower()
            # Check if action or its service is known
            if a_lower not in all_known:
                svc = a_lower.split(":")[0] if ":" in a_lower else ""
                # Allow if it's a wildcard expansion of a known service
                if svc not in known_services and not any(
                    g.endswith(":*") or g == "*" for g in granted_set
                ):
                    hallucinated_removed.append(action)

        if hallucinated_removed:
            issues.append(ValidationIssue(
                check="grounding", severity="warning",
                detail=f"Potentially hallucinated removed actions: "
                       f"{', '.join(hallucinated_removed[:5])}"
                       f"{' (and more)' if len(hallucinated_removed) > 5 else ''}",
            ))

    # Check kept actions
    kept = output.get("kept", [])
    if isinstance(kept, list):
        hallucinated_kept = []
        for action in kept:
            if not isinstance(action, str):
                continue
            a_lower = action.lower()
            if a_lower not in all_known:
                svc = a_lower.split(":")[0] if ":" in a_lower else ""
                if svc not in known_services and not any(
                    g.endswith(":*") or g == "*" for g in granted_set
                ):
                    hallucinated_kept.append(action)

        if hallucinated_kept:
            issues.append(ValidationIssue(
                check="grounding", severity="error",
                detail=f"Hallucinated kept actions (not in evidence): "
                       f"{', '.join(hallucinated_kept[:5])}",
            ))

    return issues


# ═══════════════════════════════════════════════════════════════════════════
#  CONSISTENCY CHECKS
# ═══════════════════════════════════════════════════════════════════════════

def validate_consistency(output: Dict[str, Any]) -> List[ValidationIssue]:
    """
    Check internal consistency of the LLM output.

    - removed and kept must not overlap
    - new_policy.Statement.Action should match kept (approximately)
    - If removed is empty but policy changed, that's suspicious
    """
    issues: List[ValidationIssue] = []

    removed = set(output.get("removed", []))
    kept = set(output.get("kept", []))

    # Overlap check
    overlap = removed & kept
    if overlap:
        issues.append(ValidationIssue(
            check="consistency", severity="error",
            detail=f"Actions appear in both 'removed' and 'kept': "
                   f"{', '.join(list(overlap)[:5])}",
        ))

    # Policy actions should align with kept
    policy = output.get("new_policy", {})
    if isinstance(policy, dict):
        policy_actions: Set[str] = set()
        for stmt in policy.get("Statement", []):
            if not isinstance(stmt, dict):
                continue
            if stmt.get("Effect", "").lower() != "allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            policy_actions.update(actions)

        # Actions in policy but not in kept — possible inconsistency
        if kept and policy_actions:
            in_policy_not_kept = policy_actions - kept
            if in_policy_not_kept and len(in_policy_not_kept) > 2:
                issues.append(ValidationIssue(
                    check="consistency", severity="warning",
                    detail=f"{len(in_policy_not_kept)} actions in new_policy "
                           f"not listed in 'kept': "
                           f"{', '.join(list(in_policy_not_kept)[:3])}...",
                ))

    # Empty removal check
    if not removed and kept:
        issues.append(ValidationIssue(
            check="consistency", severity="warning",
            detail="'removed' is empty but 'kept' has actions — no reduction achieved?",
        ))

    return issues


# ═══════════════════════════════════════════════════════════════════════════
#  ACTION FORMAT VALIDATION
# ═══════════════════════════════════════════════════════════════════════════

def validate_action_format(output: Dict[str, Any]) -> List[ValidationIssue]:
    """Validate that action strings follow AWS service:Action format."""
    issues: List[ValidationIssue] = []

    for key in ("removed", "kept"):
        actions = output.get(key, [])
        if not isinstance(actions, list):
            continue
        for action in actions:
            if not isinstance(action, str):
                continue
            # Skip wildcards
            if action in ("*", "*:*"):
                continue
            if not _RE_ACTION.match(action):
                issues.append(ValidationIssue(
                    check="action_format", severity="warning",
                    detail=f"Invalid action format in '{key}': '{action}' "
                           f"(expected 'service:Action')",
                ))

    return issues


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN VALIDATION FUNCTION
# ═══════════════════════════════════════════════════════════════════════════

def validate_llm_output(
    raw_text: str,
    granted_actions: Optional[List[str]] = None,
    used_actions: Optional[List[str]] = None,
) -> ValidationResult:
    """
    Full validation pipeline for an LLM output string.

    1. Parse JSON
    2. Schema validation
    3. Action format validation
    4. Grounding checks (if evidence provided)
    5. Consistency checks
    6. Auto-correction for minor issues

    Returns ValidationResult with issues and optional corrected output.
    """
    issues: List[ValidationIssue] = []

    # Step 1: Parse JSON
    try:
        output = json.loads(raw_text)
    except json.JSONDecodeError as e:
        return ValidationResult(
            valid=False,
            issues=[ValidationIssue(
                check="parse", severity="error",
                detail=f"Invalid JSON: {str(e)[:100]}",
            )],
        )

    if not isinstance(output, dict):
        return ValidationResult(
            valid=False,
            issues=[ValidationIssue(
                check="parse", severity="error",
                detail=f"Expected JSON object, got {type(output).__name__}",
            )],
        )

    # Step 2-5: Run all checks
    issues.extend(validate_schema(output))
    issues.extend(validate_action_format(output))

    if granted_actions is not None:
        issues.extend(validate_grounding(
            output,
            granted_actions=granted_actions or [],
            used_actions=used_actions or [],
        ))

    issues.extend(validate_consistency(output))

    # Step 6: Auto-correction for minor issues
    corrected = None
    errors = [i for i in issues if i.severity == "error"]
    if not errors and issues:
        # Only warnings — output is usable but annotated
        corrected = _auto_correct(output)

    has_errors = len(errors) > 0
    return ValidationResult(
        valid=not has_errors,
        issues=issues,
        corrected_output=corrected,
    )


def _auto_correct(output: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply minor auto-corrections to a valid-but-imperfect output.

    - Clamp confidence to 0-1 range
    - Default missing requires_hitl to True (safe default)
    - Default missing rationale to empty string
    """
    corrected = dict(output)

    # Clamp confidence
    conf = corrected.get("confidence")
    if conf is not None:
        try:
            corrected["confidence"] = max(0.0, min(1.0, float(conf)))
        except (TypeError, ValueError):
            corrected["confidence"] = 0.5

    # Safe defaults
    if "requires_hitl" not in corrected:
        corrected["requires_hitl"] = True
    if "rationale" not in corrected:
        corrected["rationale"] = ""

    return corrected
