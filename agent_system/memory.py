"""
Episodic Remediation Memory — stores previous decisions per principal.

NOT generic chat memory. This is security-specific institutional knowledge:
what was removed, what was kept, what the human decided, and why.

Used by the Actor to recognize previously-reviewed permissions and avoid
re-removing actions a human explicitly retained.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


class RemediationMemory:
    """
    Simple JSON-backed episodic memory keyed by principal ARN.

    In production this maps to DynamoDB or S3. No vector database needed —
    retrieval is by exact key lookup.
    """

    def __init__(self, path: str = "results/memory.json") -> None:
        self._path = Path(path)
        self._data: Dict[str, List[Dict[str, Any]]] = {}
        self._load()

    def _load(self) -> None:
        """Load existing memory from disk."""
        if self._path.exists():
            try:
                self._data = json.loads(self._path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, IOError):
                self._data = {}

    def _save(self) -> None:
        """Persist memory to disk."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps(self._data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )

    def get_history(self, principal: str) -> List[Dict[str, Any]]:
        """
        Get all previous remediation decisions for a principal.

        Returns empty list if no history exists.
        """
        return self._data.get(principal, [])

    def record_decision(
        self,
        principal: str,
        run_id: str,
        finding_class: str,
        removed: List[str],
        kept: List[str],
        human_decision: str,
        confidence: float,
        verification_passed: bool = True,
        human_note: str = "",
    ) -> None:
        """
        Record a remediation decision for a principal.

        Called after HITL approval/rejection to build institutional knowledge.
        """
        entry = {
            "run_id": run_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "finding_class": finding_class,
            "removed": removed,
            "kept": kept,
            "human_decision": human_decision,
            "confidence": confidence,
            "verification_passed": verification_passed,
            "human_note": human_note,
        }

        if principal not in self._data:
            self._data[principal] = []
        self._data[principal].append(entry)
        self._save()

    def get_previously_retained(self, principal: str) -> List[str]:
        """
        Get actions that a human previously approved to KEEP.

        Useful for the Actor: don't re-remove something a human explicitly retained.
        """
        retained: set = set()
        for entry in self.get_history(principal):
            if entry.get("human_decision") == "APPROVE":
                retained.update(entry.get("kept", []))
        return sorted(retained)

    def get_previously_removed(self, principal: str) -> List[str]:
        """
        Get actions that were previously removed and approved.

        Useful for consistency: if we removed it before and it was approved,
        it's safe to remove again.
        """
        removed: set = set()
        for entry in self.get_history(principal):
            if entry.get("human_decision") == "APPROVE":
                removed.update(entry.get("removed", []))
        return sorted(removed)

    def has_history(self, principal: str) -> bool:
        """Check if we have any previous decisions for this principal."""
        return bool(self._data.get(principal))

    def clear(self) -> None:
        """Clear all memory (for testing)."""
        self._data = {}
        if self._path.exists():
            self._path.unlink()
