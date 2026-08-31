"""
Agent Trajectory Tracer — the Traces Engine.

Emits one JSON object per agent step to trajectories.jsonl. Thread-safe,
append-only, with monotonically increasing step_number per logger instance.

The JSONL format is chosen deliberately: append-only, stream-friendly,
diff-able, and trivially parsed by evaluation harnesses.
"""

from __future__ import annotations

import json
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from .schemas import TraceStep


class TrajectoryLogger:
    """
    Logs agent trajectory steps to a JSONL file.
    
    Thread-safe. One instance is threaded through the entire orchestrator
    so every planner decision, worker call, actor hypothesis, verifier
    verdict, retry, and HITL checkpoint lands in chronological order.
    """

    def __init__(self, path: str = "trajectories.jsonl", *, append: bool = True) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._step_counter = 0
        self._buffer: List[TraceStep] = []
        if not append and self.path.exists():
            self.path.unlink()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def next_step_number(self) -> int:
        """Return the next monotonically increasing step number."""
        with self._lock:
            self._step_counter += 1
            return self._step_counter

    def log(
        self,
        *,
        run_id: str,
        scenario_id: str,
        agent_id: str,
        agent_role: str,
        system_instructions: str,
        intermediate_thought: str,
        action_taken: Dict[str, Any],
        tool_response: Any,
        feedback_and_retries: Optional[Dict[str, Any]] = None,
        hitl_checkpoint: Optional[Dict[str, Any]] = None,
        tokens: Optional[Dict[str, int]] = None,
    ) -> TraceStep:
        """
        Log a single agent step. Returns the created TraceStep.
        
        feedback_and_retries: populated only on verifier-triggered retries.
        hitl_checkpoint: populated only on sandbox (HITL) steps.
        """
        step = TraceStep(
            run_id=run_id,
            scenario_id=scenario_id,
            step_number=self.next_step_number(),
            agent_id=agent_id,
            agent_role=agent_role,
            system_instructions=system_instructions,
            intermediate_thought=intermediate_thought,
            action_taken=action_taken,
            tool_response=tool_response,
            feedback_and_retries=feedback_and_retries,
            hitl_checkpoint=hitl_checkpoint,
            tokens=tokens or {"prompt": 0, "completion": 0},
        )
        with self._lock:
            self._buffer.append(step)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(step.to_json(), ensure_ascii=False, default=str) + "\n")
        return step

    @property
    def steps(self) -> List[TraceStep]:
        """Return a copy of all logged steps."""
        with self._lock:
            return list(self._buffer)

    def total_tokens(self) -> Dict[str, int]:
        """Aggregate token counts across all logged steps."""
        with self._lock:
            prompt = sum(s.tokens.get("prompt", 0) for s in self._buffer)
            completion = sum(s.tokens.get("completion", 0) for s in self._buffer)
        return {"prompt": prompt, "completion": completion}

    def reset(self) -> None:
        """Clear in-memory buffer and step counter. Does NOT delete the file."""
        with self._lock:
            self._buffer.clear()
            self._step_counter = 0


def new_run_id() -> str:
    """Generate a unique run identifier."""
    return "run_" + uuid.uuid4().hex[:12]
