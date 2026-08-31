"""
Orchestrator — wires the full pipeline end-to-end.

Flow: classify+plan → run workers (parallel) → merge evidence →
      retrieve memory → [Gateway] Actor → [OutputValidator] → Verifier loop
      (≤ max_retries) → compute confidence → risk engine → HITL gateway →
      mock apply.

Senior-level patterns:
  - LLM Gateway: injection defense, PII filtering, token budget, circuit breaker
  - Output Validator: schema validation, grounding checks, consistency
  - Context Manager: evidence ranking, window packing, retry optimization

Emits a trace step at every stage. Returns RunResult.
"""

from __future__ import annotations

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from .schemas import (
    Alert, Hypothesis, RunResult, Task, UsageEvidence, VerificationResult,
)
from .planner import classify_finding, build_dag, choose_strategy
from .workers import get_backend, run_worker, merge_evidence
from .memory import RemediationMemory
from .confidence import compute_confidence
from .risk import compute_risk
from .verifier import verify
from .sandbox import (
    get_channel, build_rationale, mock_terraform_apply, verify_token, mint_token,
)
from .logger import TrajectoryLogger, new_run_id
from .gateway import LLMGateway, TokenBudget, CircuitBreaker, scrub_pii
from .output_validator import validate_llm_output
from .context_manager import pack_context, build_retry_context

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import Settings, get_llm_for_task, estimate_cost
from prompts import load_prompt

log = logging.getLogger("sentinel.orchestrator")


def investigate(
    scenario: Dict[str, Any],
    settings: Settings,
    tracer: TrajectoryLogger,
    memory: Optional[RemediationMemory] = None,
) -> RunResult:
    """
    Run the full advanced pipeline on a single scenario.
    Returns RunResult with hypothesis, verification, approval, and metrics.
    """
    start_time = time.time()
    run_id = new_run_id()
    scenario_id = scenario.get("id", "unknown")
    alert = Alert.from_scenario(scenario)
    fixtures = scenario.get("fixtures", {})
    oracle = scenario.get("_oracle", {})
    total_prompt = 0
    total_completion = 0

    # ── Initialize Gateway ───────────────────────────────────────────
    gateway = LLMGateway(
        budget=TokenBudget(max_tokens_per_run=50_000),
        breaker=CircuitBreaker(failure_threshold=3, reset_timeout=60),
        scrub_responses=True,
    )

    # ── 1. PLAN ──────────────────────────────────────────────────────────
    route = classify_finding(alert)
    strategy = choose_strategy(route)
    dag_tasks = build_dag(alert, route)

    tracer.log(
        run_id=run_id, scenario_id=scenario_id,
        agent_id="planner-1", agent_role="Planner",
        system_instructions="planner_v1",
        intermediate_thought=f"Classified as '{route}', strategy: {strategy}",
        action_taken={"tool": "classify_and_plan", "args": {"category": alert.category}},
        tool_response={"route": route, "strategy": strategy,
                       "dag_size": len(dag_tasks)},
    )

    # ── 2. RUN WORKERS (parallel) ────────────────────────────────────────
    backend = get_backend(settings.backend, fixtures)
    worker_outputs: List[Dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {
            pool.submit(run_worker, task, backend): task
            for task in dag_tasks
        }
        for future in as_completed(futures):
            task = futures[future]
            try:
                result = future.result(timeout=30)
            except Exception as exc:
                result = {"tool": task.tool, "task_id": task.id, "error": str(exc)}
            worker_outputs.append(result)

            tracer.log(
                run_id=run_id, scenario_id=scenario_id,
                agent_id=f"worker-{task.id}", agent_role="Worker",
                system_instructions="worker",
                intermediate_thought=f"Running {task.tool} for {task.args.get('principal', '?')}",
                action_taken={"tool": task.tool, "args": task.args},
                tool_response=result if "error" not in result else {"error": result["error"]},
            )

    evidence = merge_evidence(worker_outputs)

    # ── 2b. EVIDENCE QUALITY CHECK ───────────────────────────────────
    if evidence.errors:
        error_rate = len(evidence.errors) / max(1, len(worker_outputs))
        if error_rate > 0.5:
            log.warning(
                "High worker error rate (%.0f%%), %d/%d failed — evidence may be incomplete",
                error_rate * 100, len(evidence.errors), len(worker_outputs),
            )
            tracer.log(
                run_id=run_id, scenario_id=scenario_id,
                agent_id="orchestrator-1", agent_role="Orchestrator",
                system_instructions="evidence_quality_check",
                intermediate_thought=f"Warning: {len(evidence.errors)}/{len(worker_outputs)} "
                                     f"workers failed. Proceeding with partial evidence.",
                action_taken={"tool": "evidence_quality_check"},
                tool_response={"error_rate": round(error_rate, 2),
                               "errors": [e.get("error", "") for e in evidence.errors[:3]]},
            )

    # ── 3. RETRIEVE MEMORY ───────────────────────────────────────────────
    memory_history: List[Dict[str, Any]] = []
    if memory and alert.principal:
        memory_history = memory.get_history(alert.principal)

    # ── 4. ACTOR → VERIFIER LOOP ────────────────────────────────────────
    llm = get_llm_for_task("policy_synthesis", settings)
    prompt_text, prompt_version = load_prompt("actor", "v1")

    hypothesis: Optional[Hypothesis] = None
    verification: Optional[VerificationResult] = None
    retry_feedback: Optional[str] = None
    failed_check: str = ""
    retries = 0

    for attempt in range(1, settings.max_retries + 1):
        # ── Context Management: pack evidence intelligently ──────────
        if retry_feedback and attempt > 1:
            packed = build_retry_context(
                evidence=evidence,
                route=route,
                retry_feedback=retry_feedback,
                failed_check=failed_check,
                attempt=attempt,
                memory_history=memory_history,
            )
            p_text, p_ver = load_prompt("actor_retry", "v1")
            system_prompt = p_text.replace("{feedback}", retry_feedback)
        else:
            packed = pack_context(
                evidence=evidence,
                route=route,
                memory_history=memory_history,
            )
            system_prompt = prompt_text

        # Build actor context with packed evidence
        actor_context = {
            "principal": alert.principal,
            "service": alert.service,
            "route": route,
            "strategy": strategy,
            "lookback_days": settings.lookback_days,
            "_oracle": oracle,
        }
        # Merge packed evidence into context
        try:
            packed_evidence = json.loads(packed.evidence_json)
            # Maintain backward-compatible keys for MockLLM
            packed_evidence["used_actions"] = evidence.used_actions
            packed_evidence["granted_actions"] = evidence.granted_actions
            actor_context["evidence"] = packed_evidence
        except json.JSONDecodeError:
            actor_context["evidence"] = evidence.to_json()

        # ── Gateway: mediated LLM call ───────────────────────────────
        gw_result = gateway.call(
            llm, system_prompt, json.dumps(actor_context),
            json_mode=True, run_id=run_id, scenario_id=scenario_id,
        )
        total_prompt += gw_result.prompt_tokens
        total_completion += gw_result.completion_tokens

        # ── Output Validation: check LLM response quality ────────────
        validation = validate_llm_output(
            gw_result.text,
            granted_actions=evidence.granted_actions,
            used_actions=[a.get("action", str(a)) if isinstance(a, dict) else str(a)
                          for a in evidence.used_actions],
        )

        try:
            actor_output = json.loads(gw_result.text)
            # Apply auto-corrections if validation found minor issues
            if validation.corrected_output:
                actor_output = validation.corrected_output
            hypothesis = Hypothesis.from_dict(actor_output)
        except (json.JSONDecodeError, KeyError) as exc:
            hypothesis = Hypothesis(
                new_policy={}, removed=[], kept=[],
                confidence=0.0, requires_hitl=True,
                rationale=f"Actor parse error: {exc}",
            )

        tracer.log(
            run_id=run_id, scenario_id=scenario_id,
            agent_id="actor-1", agent_role="Actor",
            system_instructions=prompt_version if not retry_feedback else "actor_retry_v1",
            intermediate_thought=f"Attempt {attempt}: synthesizing policy for {route}"
                                 + (f" | Context: {', '.join(packed.included_sources)}"
                                    if packed.included_sources else "")
                                 + (f" | Injection detected" if gw_result.injection_detected else "")
                                 + (f" | PII filtered" if gw_result.filtered else ""),
            action_taken={"tool": "rewrite_hcl", "args": {"principal": alert.principal, "strategy": route}},
            tool_response={
                "removed": len(hypothesis.removed), "kept": len(hypothesis.kept),
                "confidence": hypothesis.confidence,
                "validation": validation.to_dict(),
                "gateway": {
                    "latency_ms": round(gw_result.latency_ms, 1),
                    "injection_detected": gw_result.injection_detected,
                    "pii_filtered": gw_result.filtered,
                    "budget_warning": gw_result.budget_warning,
                },
                "context_packing": {
                    "included": packed.included_sources,
                    "excluded": packed.excluded_sources,
                    "truncated": packed.truncated,
                },
            },
            tokens={"prompt": gw_result.prompt_tokens, "completion": gw_result.completion_tokens},
            feedback_and_retries={
                "attempt": attempt,
                "verifier_feedback": retry_feedback or "",
                "prior_attempts": attempt - 1,
                "output_validation_errors": len(validation.errors),
                "output_validation_warnings": len(validation.warnings),
            } if retry_feedback or not validation.valid else None,
        )

        # Verify
        verification = verify(hypothesis, evidence)

        tracer.log(
            run_id=run_id, scenario_id=scenario_id,
            agent_id="verifier-1", agent_role="Verifier",
            system_instructions="deterministic_verifier_v1",
            intermediate_thought=f"Running V1-V9 checks, attempt {attempt}",
            action_taken={"tool": "verify", "args": {"checks": "V1-V9"}},
            tool_response={"passed": verification.passed,
                           "checks_passed": sum(1 for c in verification.checks if c.passed),
                           "checks_total": len(verification.checks),
                           "feedback": verification.feedback[:200] if verification.feedback else ""},
        )

        if verification.passed:
            break

        retry_feedback = verification.feedback
        # Extract the failed check name for context optimization
        for check in verification.checks:
            if not check.passed:
                failed_check = check.name
                break
        retries = attempt

    # Force HITL if retries exhausted without passing
    if not verification.passed:
        hypothesis.requires_hitl = True
        hypothesis.confidence = min(hypothesis.confidence, 0.4)

    # ── 5. COMPUTE CONFIDENCE ────────────────────────────────────────────
    conf = compute_confidence(evidence, hypothesis, verification, memory_history)
    hypothesis.confidence = conf["score"]

    # ── 6. RISK ENGINE ───────────────────────────────────────────────────
    risk = compute_risk(hypothesis, conf["score"])

    # Override requires_hitl based on risk
    if risk["mandatory_hitl"]:
        hypothesis.requires_hitl = True

    # ── 7. HITL GATEWAY ──────────────────────────────────────────────────
    channel = get_channel(settings.hitl_channel, settings.auto_approve)

    rationale = build_rationale(
        kept=hypothesis.kept, removed=hypothesis.removed,
        principal=alert.principal,
        lookback_days=settings.lookback_days,
        confidence=conf["score"],
    )

    blast_radius = {
        "services_affected": list(set(a.split(":")[0] for a in hypothesis.removed if ":" in a)),
        "permissions_removed": len(hypothesis.removed),
        "permissions_retained": len(hypothesis.kept),
    }

    # Trace PENDING
    tracer.log(
        run_id=run_id, scenario_id=scenario_id,
        agent_id="sandbox-1", agent_role="Sandbox",
        system_instructions="hitl_gateway",
        intermediate_thought=f"Awaiting approval. Risk: {risk['tier']} ({risk['score']})",
        action_taken={"tool": "request_approval", "args": {"channel": settings.hitl_channel}},
        tool_response={"rationale": rationale[:300]},
        hitl_checkpoint={
            "state": "PENDING",
            "token": None,
            "rationale": rationale,
            "risk": risk,
            "confidence": conf,
        },
    )

    # Present and collect
    channel.present(rationale, hypothesis.git_diff, blast_radius, risk)
    token = channel.collect(run_id, scenario_id, settings.hitl_secret)
    token_valid = verify_token(token, settings.hitl_secret)

    # Trace RESOLVED
    tracer.log(
        run_id=run_id, scenario_id=scenario_id,
        agent_id="sandbox-1", agent_role="Sandbox",
        system_instructions="hitl_gateway",
        intermediate_thought=f"Decision: {token.decision} by {token.approver}",
        action_taken={"tool": "resolve_approval", "args": {}},
        tool_response={"decision": token.decision, "valid": token_valid},
        hitl_checkpoint={
            "state": "RESOLVED",
            "token": token.token,
            "decision": token.decision,
            "approver": token.approver,
        },
    )

    # ── 8. APPLY ─────────────────────────────────────────────────────────
    applied = False
    if token.decision == "APPROVE" and token_valid:
        apply_result = mock_terraform_apply(
            new_policy=hypothesis.new_policy,
            prior_policy=evidence.current_policy,
        )
        applied = apply_result.get("applied", False)

    # ── 9. RECORD MEMORY ─────────────────────────────────────────────────
    if memory and alert.principal:
        memory.record_decision(
            principal=alert.principal,
            run_id=run_id,
            finding_class=route,
            removed=hypothesis.removed,
            kept=hypothesis.kept,
            human_decision=token.decision,
            confidence=conf["score"],
            verification_passed=verification.passed if verification else False,
        )

    wall_time = time.time() - start_time

    # ── 10. GATEWAY SUMMARY (observability) ──────────────────────────
    gw_summary = gateway.summary()
    tracer.log(
        run_id=run_id, scenario_id=scenario_id,
        agent_id="gateway-1", agent_role="Gateway",
        system_instructions="llm_gateway",
        intermediate_thought=f"Gateway summary: {gw_summary['total_calls']} calls, "
                             f"{gw_summary['injections_detected']} injections detected, "
                             f"{gw_summary['pii_filtered']} PII filtered",
        action_taken={"tool": "gateway_summary"},
        tool_response=gw_summary,
    )

    return RunResult(
        scenario_id=scenario_id,
        system="advanced",
        hypothesis=hypothesis,
        verification=verification,
        approval_decision=token.decision,
        applied=applied,
        route=route,
        retries=retries,
        tokens={"prompt": total_prompt, "completion": total_completion},
        wall_time_s=round(wall_time, 2),
    )
