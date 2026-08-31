"""
HITL Sandbox Gateway — human approval before any state change.

Abstracts the approval surface behind ApprovalChannel protocol:
  AutoChannel  — auto-issues tokens (evaluator/CI)
  CliChannel   — plain text prompt
  TuiChannel   — Rich terminal card (optional, loaded lazily)
  SlackChannel — Slack buttons (optional, loaded lazily)

All channels produce the same HMAC-signed ApprovalToken verified by verify_token().
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Protocol

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ---------------------------------------------------------------------------
# ApprovalToken
# ---------------------------------------------------------------------------

@dataclass
class ApprovalToken:
    token: str
    approver: str
    decision: str        # "APPROVE" or "REJECT"
    issued_at: float
    signature: str
    run_id: str = ""
    scenario_id: str = ""

    def to_json(self) -> Dict[str, Any]:
        return asdict(self)


def _sign_token(run_id: str, scenario_id: str, decision: str, secret: str) -> str:
    """HMAC-SHA256 signature binding (run_id, scenario_id, decision)."""
    msg = f"{run_id}:{scenario_id}:{decision}".encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def mint_token(
    run_id: str, scenario_id: str, decision: str, approver: str, secret: str
) -> ApprovalToken:
    """Create a signed approval token."""
    sig = _sign_token(run_id, scenario_id, decision, secret)
    return ApprovalToken(
        token=str(uuid.uuid4()),
        approver=approver,
        decision=decision,
        issued_at=time.time(),
        signature=sig,
        run_id=run_id,
        scenario_id=scenario_id,
    )


def verify_token(token: ApprovalToken, secret: str) -> bool:
    """Verify the HMAC signature of an approval token."""
    expected = _sign_token(token.run_id, token.scenario_id, token.decision, secret)
    return hmac.compare_digest(token.signature, expected)


# ---------------------------------------------------------------------------
# ApprovalChannel Protocol
# ---------------------------------------------------------------------------

class ApprovalChannel(Protocol):
    def present(self, rationale: str, diff: str, blast_radius: Dict[str, Any],
                risk: Dict[str, Any]) -> None: ...
    def collect(self, run_id: str, scenario_id: str, secret: str) -> ApprovalToken: ...


# ---------------------------------------------------------------------------
# AutoChannel — non-interactive (evaluator/CI)
# ---------------------------------------------------------------------------

class AutoChannel:
    def present(self, rationale: str, diff: str, blast_radius: Dict[str, Any],
                risk: Dict[str, Any]) -> None:
        pass  # silent

    def collect(self, run_id: str, scenario_id: str, secret: str) -> ApprovalToken:
        return mint_token(run_id, scenario_id, "APPROVE", "evaluator:auto", secret)


# ---------------------------------------------------------------------------
# CliChannel — plain text prompt
# ---------------------------------------------------------------------------

class CliChannel:
    def present(self, rationale: str, diff: str, blast_radius: Dict[str, Any],
                risk: Dict[str, Any]) -> None:
        print("\n" + "=" * 60)
        print("HITL APPROVAL REQUIRED")
        print("=" * 60)
        print(f"\nRisk: {risk.get('tier', '?')} (score {risk.get('score', '?')})")
        print(f"\n{rationale}")
        print(f"\n--- Policy Diff ---\n{diff[:500]}")
        if blast_radius:
            print(f"\nBlast radius: {json.dumps(blast_radius, indent=2)[:300]}")
        print("=" * 60)

    def collect(self, run_id: str, scenario_id: str, secret: str) -> ApprovalToken:
        while True:
            choice = input("\nAPPROVE or REJECT? ").strip().upper()
            if choice in ("APPROVE", "REJECT"):
                return mint_token(run_id, scenario_id, choice, "human:cli", secret)
            print("Please type APPROVE or REJECT.")


# ---------------------------------------------------------------------------
# Channel factory
# ---------------------------------------------------------------------------

def get_channel(channel_name: str, auto_approve: bool = True) -> ApprovalChannel:
    """Return the appropriate approval channel."""
    if channel_name == "auto":
        return AutoChannel()
    if channel_name == "tui":
        try:
            from agent_system._tui_channel import TuiChannel
            return TuiChannel()
        except ImportError:
            print("[sandbox] Rich not available, falling back to CLI")
            return CliChannel()
    if channel_name == "slack":
        try:
            from agent_system._slack_channel import SlackChannel
            return SlackChannel()
        except (ImportError, ValueError) as exc:
            print(f"[sandbox] Slack unavailable ({exc}), falling back to CLI")
            return CliChannel()
    return CliChannel() if not auto_approve else AutoChannel()


# ---------------------------------------------------------------------------
# Rationale builder
# ---------------------------------------------------------------------------

def build_rationale(
    kept: list, removed: list, principal: str = "",
    lookback_days: int = 90, confidence: float = 0.0,
) -> str:
    """Build a plain-language rationale for the human reviewer."""
    parts = []
    parts.append(
        f"Removing {len(removed)} unnecessary permissions "
        f"based on {lookback_days}-day CloudTrail usage analysis."
    )
    parts.append(f"Retaining {len(kept)} actions that were actually called.")
    if principal:
        parts.append(f"Principal: {principal}")
    parts.append(f"Computed confidence: {confidence:.0%}")

    # Highlight escalation paths closed
    escalation_closed = [a for a in removed if any(
        kw in a.lower() for kw in ["passrole", "createpolicy", "attachpolicy", "*"]
    )]
    if escalation_closed:
        parts.append(
            f"Escalation paths closed: {', '.join(escalation_closed[:5])}"
        )

    return " ".join(parts)


# ---------------------------------------------------------------------------
# Mock Terraform apply
# ---------------------------------------------------------------------------

def mock_terraform_apply(
    new_policy: Dict[str, Any],
    prior_policy: Dict[str, Any],
    state_path: str = "results/tf_state.json",
) -> Dict[str, Any]:
    """
    Mock terraform plan + apply against a local state file.
    Stores prior policy for rollback. Idempotent (no-op if current == target).
    """
    state_file = Path(state_path)
    state_file.parent.mkdir(parents=True, exist_ok=True)

    # Idempotency check
    if state_file.exists():
        try:
            current = json.loads(state_file.read_text())
            if current.get("policy") == new_policy:
                return {"applied": False, "reason": "idempotent: already at target state"}
        except (json.JSONDecodeError, IOError):
            pass

    # Store rollback
    rollback_path = state_file.with_suffix(".rollback.json")
    rollback_data = {"prior_policy": prior_policy, "timestamp": time.time()}
    rollback_path.write_text(json.dumps(rollback_data, indent=2), encoding="utf-8")

    # Apply
    state_data = {
        "policy": new_policy,
        "applied_at": time.time(),
    }
    state_file.write_text(json.dumps(state_data, indent=2), encoding="utf-8")

    return {
        "applied": True,
        "state_path": str(state_file),
        "rollback_path": str(rollback_path),
    }


def rollback(state_path: str = "results/tf_state.json") -> Dict[str, Any]:
    """Restore the prior policy from the rollback file."""
    rollback_path = Path(state_path).with_suffix(".rollback.json")
    if not rollback_path.exists():
        return {"rolled_back": False, "reason": "no rollback file found"}

    rollback_data = json.loads(rollback_path.read_text())
    prior = rollback_data.get("prior_policy", {})

    state_file = Path(state_path)
    state_data = {"policy": prior, "applied_at": time.time(), "is_rollback": True}
    state_file.write_text(json.dumps(state_data, indent=2), encoding="utf-8")

    return {"rolled_back": True, "restored_policy": prior}
