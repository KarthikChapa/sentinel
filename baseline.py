"""
Baseline — single-pass naive IAM policy optimizer.

NO usage data, NO simulator, NO denylist, NO HITL.
Just: "here's a policy, make it least-privilege."

Emits a minimal trajectory trace for fair comparison with the advanced system.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict

from agent_system.schemas import Hypothesis, RunResult
from agent_system.logger import TrajectoryLogger, new_run_id
from config import Settings, get_llm_for_task
from prompts import load_prompt


def run_baseline(
    scenario: Dict[str, Any],
    settings: Settings,
    tracer: TrajectoryLogger,
) -> RunResult:
    """
    Run the naive baseline on a single scenario.
    Returns RunResult with hypothesis but no verification/approval.
    """
    start_time = time.time()
    run_id = new_run_id()
    scenario_id = scenario.get("id", "unknown")
    fixtures = scenario.get("fixtures", {})
    current_policy = fixtures.get("current_policy", {})

    # Extract granted actions from current policy
    granted_actions = []
    for stmt in current_policy.get("Statement", []):
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        granted_actions.extend(actions)

    # Single LLM pass with baseline prompt
    llm = get_llm_for_task("baseline", settings)
    prompt_text, prompt_version = load_prompt("baseline", "v1")

    context = json.dumps({
        "granted_actions": granted_actions,
        "current_policy": current_policy,
    })

    llm_result = llm.complete(prompt_text, context, json_mode=True)

    try:
        output = json.loads(llm_result.text)
        hypothesis = Hypothesis.from_dict(output)
    except (json.JSONDecodeError, KeyError):
        hypothesis = Hypothesis(
            new_policy=current_policy,
            removed=[], kept=granted_actions,
            confidence=0.5, requires_hitl=False,
            rationale="Baseline: parse error, returning original policy.",
        )

    # Trace the single step
    tracer.log(
        run_id=run_id, scenario_id=scenario_id,
        agent_id="baseline-1", agent_role="Baseline",
        system_instructions=prompt_version,
        intermediate_thought="Single-pass policy optimization, no usage data or verification",
        action_taken={"tool": "baseline_rewrite", "args": {"granted_count": len(granted_actions)}},
        tool_response={
            "removed": len(hypothesis.removed),
            "kept": len(hypothesis.kept),
            "confidence": hypothesis.confidence,
        },
        tokens={"prompt": llm_result.prompt_tokens, "completion": llm_result.completion_tokens},
    )

    wall_time = time.time() - start_time

    return RunResult(
        scenario_id=scenario_id,
        system="baseline",
        hypothesis=hypothesis,
        verification=None,
        approval_decision=None,
        applied=False,
        route="",
        retries=0,
        tokens={"prompt": llm_result.prompt_tokens, "completion": llm_result.completion_tokens},
        wall_time_s=round(wall_time, 2),
    )
