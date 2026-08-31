"""
Context Window Manager — intelligent context packing for LLM calls.

Manages what goes into the LLM prompt when evidence is large:
  1. Evidence ranking by relevance to the finding class
  2. Context window packing with priority-based truncation
  3. Memory integration with recency weighting
  4. Retry context optimization (delta-only on retry)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .schemas import UsageEvidence


# ═══════════════════════════════════════════════════════════════════════════
#  EVIDENCE PRIORITY
# ═══════════════════════════════════════════════════════════════════════════

# Relevance weights by finding class → evidence type
# Higher = more relevant, packed first
EVIDENCE_PRIORITY: Dict[str, Dict[str, float]] = {
    "unused_role": {
        "cloudtrail_usage": 1.0,     # Usage is the proof
        "last_accessed": 0.9,        # Confirms dormancy
        "analyzer_findings": 0.5,
        "terraform_state": 0.3,
    },
    "wildcard_action": {
        "cloudtrail_usage": 1.0,     # Which specific actions were used
        "last_accessed": 0.6,
        "analyzer_findings": 0.7,
        "terraform_state": 0.5,
    },
    "passrole_escalation": {
        "cloudtrail_usage": 0.8,
        "last_accessed": 0.5,
        "analyzer_findings": 1.0,    # Analyzer flags escalation risk
        "terraform_state": 0.9,      # Need trust policy context
    },
    "admin_star": {
        "cloudtrail_usage": 1.0,     # Must know exactly what's used
        "last_accessed": 0.7,
        "analyzer_findings": 0.8,
        "terraform_state": 0.6,
    },
    "cross_account_trust": {
        "cloudtrail_usage": 0.6,
        "last_accessed": 0.5,
        "analyzer_findings": 0.9,
        "terraform_state": 1.0,      # Trust policy is critical
    },
    "sensitive_wildcard": {
        "cloudtrail_usage": 1.0,
        "last_accessed": 0.8,
        "analyzer_findings": 0.9,
        "terraform_state": 0.5,
    },
    "contradictory": {
        "cloudtrail_usage": 1.0,     # All evidence matters for edge cases
        "last_accessed": 0.9,
        "analyzer_findings": 0.9,
        "terraform_state": 0.8,
    },
}

# Default priority if route is unknown
_DEFAULT_PRIORITY = {
    "cloudtrail_usage": 1.0,
    "last_accessed": 0.7,
    "analyzer_findings": 0.6,
    "terraform_state": 0.5,
}


@dataclass
class ContextBudget:
    """Token budget for context window packing."""
    max_tokens: int = 6000           # Leave ~2k for system prompt + completion
    chars_per_token: int = 4         # Rough estimate
    reserved_for_system: int = 500   # Tokens reserved for system prompt
    reserved_for_memory: int = 500   # Tokens reserved for episodic memory
    reserved_for_retry: int = 300    # Tokens reserved for retry feedback

    @property
    def evidence_budget(self) -> int:
        """Available tokens for evidence."""
        return self.max_tokens - self.reserved_for_system - self.reserved_for_memory

    @property
    def evidence_chars(self) -> int:
        """Available characters for evidence."""
        return self.evidence_budget * self.chars_per_token


# ═══════════════════════════════════════════════════════════════════════════
#  EVIDENCE RANKING
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class RankedEvidence:
    """A piece of evidence with its priority score."""
    source: str          # e.g. "cloudtrail_usage"
    priority: float      # 0.0 - 1.0
    data: Any
    estimated_tokens: int

    @property
    def value_density(self) -> float:
        """Priority per token — prefer high-priority, small items."""
        return self.priority / max(1, self.estimated_tokens)


def rank_evidence(
    evidence: UsageEvidence,
    route: str,
) -> List[RankedEvidence]:
    """
    Rank evidence items by relevance to the finding class.

    Returns sorted list (highest priority first) with token estimates.
    """
    priorities = EVIDENCE_PRIORITY.get(route, _DEFAULT_PRIORITY)
    ranked: List[RankedEvidence] = []

    # CloudTrail usage
    if evidence.used_actions:
        data = evidence.used_actions
        text = json.dumps(data, default=str)
        ranked.append(RankedEvidence(
            source="cloudtrail_usage",
            priority=priorities.get("cloudtrail_usage", 0.5),
            data=data,
            estimated_tokens=len(text) // 4,
        ))

    # Last accessed
    if evidence.last_accessed:
        data = evidence.last_accessed
        text = json.dumps(data, default=str)
        ranked.append(RankedEvidence(
            source="last_accessed",
            priority=priorities.get("last_accessed", 0.5),
            data=data,
            estimated_tokens=len(text) // 4,
        ))

    # Analyzer findings
    if evidence.analyzer_findings:
        data = evidence.analyzer_findings
        text = json.dumps(data, default=str)
        ranked.append(RankedEvidence(
            source="analyzer_findings",
            priority=priorities.get("analyzer_findings", 0.5),
            data=data,
            estimated_tokens=len(text) // 4,
        ))

    # Terraform state / current policy
    if evidence.current_policy:
        data = {
            "current_policy": evidence.current_policy,
            "granted_actions": evidence.granted_actions,
        }
        text = json.dumps(data, default=str)
        ranked.append(RankedEvidence(
            source="terraform_state",
            priority=priorities.get("terraform_state", 0.5),
            data=data,
            estimated_tokens=len(text) // 4,
        ))

    # Sort by priority (highest first)
    ranked.sort(key=lambda r: r.priority, reverse=True)
    return ranked


# ═══════════════════════════════════════════════════════════════════════════
#  CONTEXT PACKING
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class PackedContext:
    """Result of context packing."""
    evidence_json: str           # JSON string ready for the LLM prompt
    included_sources: List[str]  # Which evidence sources were included
    excluded_sources: List[str]  # Which were dropped due to budget
    total_tokens: int            # Estimated total tokens
    truncated: bool              # Whether any evidence was truncated


def pack_context(
    evidence: UsageEvidence,
    route: str,
    memory_history: Optional[List[Dict[str, Any]]] = None,
    retry_feedback: Optional[str] = None,
    budget: Optional[ContextBudget] = None,
) -> PackedContext:
    """
    Pack evidence into the context window with priority-based truncation.

    Strategy:
    1. Rank evidence by relevance to finding class
    2. Include items in priority order until budget is exhausted
    3. If a high-priority item is too large, truncate it (keep top N entries)
    4. Add memory and retry feedback from reserved budgets
    """
    budget = budget or ContextBudget()
    ranked = rank_evidence(evidence, route)

    # Build context dict
    context: Dict[str, Any] = {}
    included: List[str] = []
    excluded: List[str] = []
    tokens_used = 0
    truncated = False
    available = budget.evidence_chars

    for item in ranked:
        item_text = json.dumps(item.data, default=str)
        item_chars = len(item_text)

        if item_chars <= available:
            # Fits entirely
            context[item.source] = item.data
            included.append(item.source)
            tokens_used += item.estimated_tokens
            available -= item_chars
        elif available > 200:
            # Partially fits — truncate
            if isinstance(item.data, list) and len(item.data) > 1:
                # Keep top N items that fit
                truncated_data = []
                chars = 50  # overhead for brackets
                for entry in item.data:
                    entry_text = json.dumps(entry, default=str)
                    if chars + len(entry_text) + 2 <= available:
                        truncated_data.append(entry)
                        chars += len(entry_text) + 2
                    else:
                        break

                if truncated_data:
                    context[item.source] = truncated_data
                    context[f"_{item.source}_note"] = (
                        f"Truncated: showing {len(truncated_data)}/{len(item.data)} entries"
                    )
                    included.append(f"{item.source} (truncated)")
                    tokens_used += chars // 4
                    available -= chars
                    truncated = True
                else:
                    excluded.append(item.source)
            else:
                excluded.append(item.source)
        else:
            excluded.append(item.source)

    # Add memory from reserved budget
    if memory_history:
        # Include last 3 decisions (most recent first)
        recent = memory_history[-3:]
        context["memory_history"] = recent
        mem_tokens = len(json.dumps(recent, default=str)) // 4
        tokens_used += mem_tokens

    # Add retry feedback from reserved budget
    if retry_feedback:
        context["retry_feedback"] = retry_feedback
        tokens_used += len(retry_feedback) // 4

    result_json = json.dumps(context, indent=1, default=str)

    return PackedContext(
        evidence_json=result_json,
        included_sources=included,
        excluded_sources=excluded,
        total_tokens=tokens_used,
        truncated=truncated,
    )


# ═══════════════════════════════════════════════════════════════════════════
#  RETRY CONTEXT OPTIMIZATION
# ═══════════════════════════════════════════════════════════════════════════

def build_retry_context(
    evidence: UsageEvidence,
    route: str,
    retry_feedback: str,
    failed_check: str,
    attempt: int,
    memory_history: Optional[List[Dict[str, Any]]] = None,
) -> PackedContext:
    """
    Build an optimized context for retry attempts.

    On retry, we don't resend ALL evidence. Instead:
    1. Send only the specific evidence relevant to the failed check
    2. Include the verifier feedback prominently
    3. Include the previous attempt number for context
    4. Use a tighter token budget (less evidence needed)
    """
    retry_budget = ContextBudget(
        max_tokens=4000,             # Tighter budget for retries
        reserved_for_system=400,
        reserved_for_memory=200,
        reserved_for_retry=500,      # More room for feedback
    )

    # Map failed checks to relevant evidence sources
    check_evidence_map: Dict[str, List[str]] = {
        "V1_no_regression": ["cloudtrail_usage", "terraform_state"],
        "V2_no_passrole_escalation": ["terraform_state", "analyzer_findings"],
        "V3_no_admin_star": ["cloudtrail_usage", "terraform_state"],
        "V4_no_credential_mgmt": ["cloudtrail_usage"],
        "V5_sensitive_service_scoping": ["cloudtrail_usage", "analyzer_findings"],
        "V6_s3_admin_equivalent": ["cloudtrail_usage"],
        "V7_syntax_structure": ["terraform_state"],
        "V8_dr_preserved": ["terraform_state"],
        "V9_abac_tags": ["terraform_state"],
    }

    # Add retry-specific context
    enhanced_feedback = (
        f"RETRY ATTEMPT {attempt}. The verifier rejected your previous proposal.\n"
        f"Failed check: {failed_check}\n"
        f"Feedback: {retry_feedback}\n"
        f"Fix ONLY the issue described above. Do not change parts that were correct."
    )

    return pack_context(
        evidence=evidence,
        route=route,
        memory_history=memory_history,
        retry_feedback=enhanced_feedback,
        budget=retry_budget,
    )
