"""
Typed data structures shared across the agent system.

Includes the Agent Trajectory Trace schema required for submission.
Every field name matches the challenge spec exactly:
  agent_role, system_instructions, step_number, action_taken,
  tool_response, intermediate_thought, feedback_and_retries, hitl_checkpoint.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Domain objects
# ---------------------------------------------------------------------------

@dataclass
class Alert:
    """A raw finding / trigger ingested by the planner."""
    id: str
    title: str
    category: str          # e.g. "wildcard_action", "passrole_escalation"
    severity: str          # HIGH / CRITICAL / MEDIUM
    principal: str         # role ARN or service account
    service: str           # short name for display
    payload: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_scenario(cls, scenario: Dict[str, Any]) -> Alert:
        a = scenario["alert"]
        return cls(
            id=a["id"],
            title=a["title"],
            category=a["category"],
            severity=a["severity"],
            principal=a.get("principal", a.get("service", "")),
            service=a.get("service", ""),
            payload=a.get("payload", {}),
        )

    def to_json(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> Alert:
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class Task:
    """A node in the investigation DAG."""
    id: str
    tool: str
    args: Dict[str, Any]
    depends_on: List[str] = field(default_factory=list)
    rationale: str = ""

    def to_json(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> Task:
        return cls(
            id=d["id"],
            tool=d["tool"],
            args=d.get("args", {}),
            depends_on=d.get("depends_on", []),
            rationale=d.get("rationale", ""),
        )


@dataclass
class UsageEvidence:
    """Merged output from all audit workers."""
    used_actions: List[Dict[str, Any]] = field(default_factory=list)
    # Each: {"action": "s3:GetObject", "last_used": "2026-07-15", "count": 42}
    granted_actions: List[str] = field(default_factory=list)
    resource_scope: str = ""              # account | org | folder | project
    last_accessed: List[Dict[str, Any]] = field(default_factory=list)
    analyzer_findings: List[Dict[str, Any]] = field(default_factory=list)
    current_policy: Dict[str, Any] = field(default_factory=dict)
    current_hcl: str = ""
    terraform_state: Dict[str, Any] = field(default_factory=dict)
    errors: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def used_action_names(self) -> List[str]:
        """Flat list of action strings that were actually used."""
        return [a["action"] for a in self.used_actions if "action" in a]

    def to_json(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> UsageEvidence:
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class Hypothesis:
    """The Actor's synthesized remediation proposal."""
    new_policy: Dict[str, Any] = field(default_factory=dict)
    removed: List[str] = field(default_factory=list)
    kept: List[str] = field(default_factory=list)
    added_conditions: List[Dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.0
    requires_hitl: bool = True
    git_diff: str = ""
    rationale: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> Hypothesis:
        return cls(
            new_policy=d.get("new_policy", {}),
            removed=d.get("removed", []),
            kept=d.get("kept", []),
            added_conditions=d.get("added_conditions", []),
            confidence=float(d.get("confidence", 0.0)),
            requires_hitl=bool(d.get("requires_hitl", True)),
            git_diff=d.get("git_diff", ""),
            rationale=d.get("rationale", ""),
        )

    def to_json(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Check:
    """A single verifier check result."""
    name: str
    passed: bool
    detail: str = ""

    def to_json(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationResult:
    """Deterministic verdict from the Verifier."""
    passed: bool
    checks: List[Check] = field(default_factory=list)
    feedback: str = ""

    def to_json(self) -> Dict[str, Any]:
        d = asdict(self)
        d["checks"] = [c.to_json() if isinstance(c, Check) else c for c in self.checks]
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> VerificationResult:
        checks = [
            Check(**c) if isinstance(c, dict) else c
            for c in d.get("checks", [])
        ]
        return cls(
            passed=d.get("passed", False),
            checks=checks,
            feedback=d.get("feedback", ""),
        )


# ---------------------------------------------------------------------------
# Agent Trajectory Trace (submission artifact)
# ---------------------------------------------------------------------------

@dataclass
class TraceStep:
    """
    One step in an agent's trajectory. Serialized as a single JSONL line.
    
    Field names match the challenge-required schema exactly.
    """
    run_id: str
    scenario_id: str
    step_number: int
    agent_id: str
    agent_role: str        # Planner | Worker | Actor | Verifier | Sandbox | Orchestrator

    system_instructions: str
    intermediate_thought: str
    action_taken: Dict[str, Any]       # {"tool": name, "args": {...}}
    tool_response: Any

    feedback_and_retries: Optional[Dict[str, Any]] = None
    hitl_checkpoint: Optional[Dict[str, Any]] = None
    tokens: Dict[str, int] = field(default_factory=lambda: {"prompt": 0, "completion": 0})
    timestamp: float = field(default_factory=time.time)
    step_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_json(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> TraceStep:
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ---------------------------------------------------------------------------
# Run result (returned by orchestrator and baseline)
# ---------------------------------------------------------------------------

@dataclass
class RunResult:
    """Aggregate result of one scenario run (baseline or advanced)."""
    scenario_id: str
    system: str                    # "baseline" | "advanced"
    hypothesis: Optional[Hypothesis] = None
    verification: Optional[VerificationResult] = None
    approval_decision: Optional[str] = None    # "APPROVE" | "REJECT" | None
    applied: bool = False
    route: str = ""
    retries: int = 0
    tokens: Dict[str, int] = field(default_factory=lambda: {"prompt": 0, "completion": 0})
    wall_time_s: float = 0.0

    def to_json(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.hypothesis:
            d["hypothesis"] = self.hypothesis.to_json()
        if self.verification:
            d["verification"] = self.verification.to_json()
        return d
