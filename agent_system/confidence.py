"""
Computed Confidence — derived from observable signals, never from LLM self-assessment.

Five weighted signals:
  1. evidence_coverage  (0.30) — fraction of granted actions with usage data
  2. verification_pass  (0.25) — 1.0 if V1-V9 all passed, 0.0 otherwise
  3. historical_consistency (0.15) — matches previous human-approved decisions
  4. scope_quality      (0.15) — specific ARNs vs wildcards in the new policy
  5. ambiguity          (0.15) — clear-cut usage vs boundary/contradictory data
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .schemas import Hypothesis, UsageEvidence, VerificationResult


# ---------------------------------------------------------------------------
# Signal computation
# ---------------------------------------------------------------------------

def _evidence_coverage(evidence: UsageEvidence) -> float:
    """
    Fraction of granted actions that have CloudTrail usage data.

    High = we know what's used. Low = flying blind.
    """
    if not evidence.granted_actions:
        return 0.5  # no grants = neutral

    used_names = set(evidence.used_action_names)
    covered = sum(1 for a in evidence.granted_actions if a in used_names or a == "*")
    return min(1.0, covered / max(1, len(evidence.granted_actions)))


def _verification_pass(verification: Optional[VerificationResult]) -> float:
    """1.0 if all checks passed, 0.0 otherwise."""
    if verification is None:
        return 0.0
    return 1.0 if verification.passed else 0.0


def _historical_consistency(
    hypothesis: Hypothesis,
    memory_history: List[Dict[str, Any]],
) -> float:
    """
    How consistent is this remediation with previous human-approved decisions?

    1.0 = fully consistent (same kept/removed as before)
    0.5 = no history (neutral)
    lower = contradicts previous approvals
    """
    if not memory_history:
        return 0.5  # no history = neutral

    approved = [h for h in memory_history if h.get("human_decision") == "APPROVE"]
    if not approved:
        return 0.5

    # Check overlap between current kept and previously kept
    prev_kept = set()
    prev_removed = set()
    for entry in approved:
        prev_kept.update(entry.get("kept", []))
        prev_removed.update(entry.get("removed", []))

    current_kept = set(hypothesis.kept)
    current_removed = set(hypothesis.removed)

    # Penalize if we're removing something previously kept
    conflicts = current_removed & prev_kept
    agreements = (current_kept & prev_kept) | (current_removed & prev_removed)

    total = len(conflicts) + len(agreements)
    if total == 0:
        return 0.5

    return round(len(agreements) / total, 2)


def _scope_quality(hypothesis: Hypothesis) -> float:
    """
    How specific are the Resources in the new policy?

    1.0 = all specific ARNs
    lower for wildcards
    """
    statements = hypothesis.new_policy.get("Statement", [])
    if not statements:
        return 0.5

    total_resources = 0
    specific_resources = 0

    for stmt in statements:
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        for r in resources:
            total_resources += 1
            if r != "*" and not r.endswith(":*"):
                specific_resources += 1

    if total_resources == 0:
        return 0.5

    return round(specific_resources / total_resources, 2)


def _ambiguity_factor(evidence: UsageEvidence) -> float:
    """
    How clear-cut is the usage data?

    1.0 = actions are clearly used/unused
    lower = boundary cases (used once long ago), contradictory signals, partial data
    """
    if evidence.errors:
        # Partial data = more ambiguity
        error_penalty = min(0.3, len(evidence.errors) * 0.1)
    else:
        error_penalty = 0.0

    # Check for boundary usage (actions used very few times)
    boundary_count = 0
    for action in evidence.used_actions:
        count = action.get("count", 0)
        if isinstance(count, int) and count <= 2:
            boundary_count += 1

    if evidence.used_actions:
        boundary_ratio = boundary_count / len(evidence.used_actions)
    else:
        boundary_ratio = 0.0

    # Check for analyzer findings that conflict with usage
    conflict_penalty = 0.0
    if evidence.analyzer_findings:
        used_names = set(evidence.used_action_names)
        for finding in evidence.analyzer_findings:
            action = finding.get("action", "")
            if action in used_names:
                conflict_penalty += 0.1  # analyzer says unused but we see usage
        conflict_penalty = min(0.3, conflict_penalty)

    score = 1.0 - error_penalty - (boundary_ratio * 0.3) - conflict_penalty
    return round(max(0.0, min(1.0, score)), 2)


# ---------------------------------------------------------------------------
# Main computation
# ---------------------------------------------------------------------------

# Weights sum to 1.0
WEIGHTS = {
    "evidence_coverage": 0.30,
    "verification_pass": 0.25,
    "historical_consistency": 0.15,
    "scope_quality": 0.15,
    "ambiguity": 0.15,
}


def compute_confidence(
    evidence: UsageEvidence,
    hypothesis: Hypothesis,
    verification: Optional[VerificationResult] = None,
    memory_history: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Compute confidence from observable, auditable signals.

    Returns a dict with the overall score and each component for tracing:
    {
        "score": 0.82,
        "components": {
            "evidence_coverage": 0.98,
            "verification_pass": 1.0,
            "historical_consistency": 0.90,
            "scope_quality": 0.75,
            "ambiguity": 0.60
        }
    }
    """
    memory_history = memory_history or []

    components = {
        "evidence_coverage": _evidence_coverage(evidence),
        "verification_pass": _verification_pass(verification),
        "historical_consistency": _historical_consistency(hypothesis, memory_history),
        "scope_quality": _scope_quality(hypothesis),
        "ambiguity": _ambiguity_factor(evidence),
    }

    score = round(sum(components[k] * WEIGHTS[k] for k in components), 2)

    return {
        "score": score,
        "components": components,
    }
