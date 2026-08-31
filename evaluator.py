#!/usr/bin/env python3
"""
Evaluator — runs baseline + advanced over all scenarios, scores against
_oracle, prints metrics table, writes results/metrics.json and agent
evaluation scorecards.

Usage:
    python evaluator.py                          # all scenarios
    python evaluator.py --scenario sc-03-passrole-escalation  # single
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from config import SETTINGS, estimate_cost
from agent_system.logger import TrajectoryLogger
from agent_system.memory import RemediationMemory
from agent_system.schemas import Hypothesis, RunResult
from agent_system.orchestrator import investigate
from baseline import run_baseline


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def score_run(
    result: RunResult,
    oracle: Dict[str, Any],
    all_granted: List[str],
) -> Dict[str, Any]:
    """Score a single run against the oracle."""
    hyp = result.hypothesis or Hypothesis()
    safe = set(oracle.get("safe_actions", []))
    must_escalate = oracle.get("must_escalate", False)

    # Broken-access: used actions denied by the new policy
    if hyp.new_policy and hyp.new_policy.get("Statement"):
        from iam_simulator import find_denied_used_actions
        denied = find_denied_used_actions(hyp.new_policy, list(safe))
        broken_count = len(denied)
    else:
        broken_count = 0

    total_used = max(1, len(safe))
    broken_rate = broken_count / total_used

    # Escalation paths remaining
    escalation_remaining = 0
    if hyp.new_policy:
        from agent_system.verifier import verify
        from agent_system.schemas import UsageEvidence
        dummy_evidence = UsageEvidence(
            used_actions=[{"action": a} for a in safe],
            granted_actions=all_granted,
            current_policy={},
        )
        vr = verify(hyp, dummy_evidence)
        escalation_remaining = sum(
            1 for c in vr.checks
            if not c.passed and c.name in (
                "V2_no_passrole_escalation", "V3_no_admin_star",
                "V4_no_credential_mgmt", "V5_sensitive_service_scoping",
                "V6_s3_admin_equivalent",
            )
        )

    # Reduction %
    total_granted = max(1, len(all_granted), len(hyp.removed) + len(hyp.kept))
    reduction = len(hyp.removed) / total_granted if hyp.removed else 0.0

    # HITL escalated correctly?
    hitl_escalated = result.approval_decision is not None
    escalation_correct = True
    if must_escalate and not hitl_escalated:
        escalation_correct = False

    # Classification correct?
    expected_class = oracle.get("expected_class", "")
    classification_correct = result.route == expected_class if expected_class else True

    return {
        "scenario_id": result.scenario_id,
        "system": result.system,
        "broken_access_rate": round(broken_rate, 4),
        "broken_access_count": broken_count,
        "escalation_paths_remaining": escalation_remaining,
        "reduction_pct": round(reduction * 100, 1),
        "retries": result.retries,
        "hitl_escalated": hitl_escalated,
        "escalation_correct": escalation_correct,
        "classification_correct": classification_correct,
        "confidence": hyp.confidence,
        "wall_time_s": result.wall_time_s,
        "tokens": result.tokens,
        "cost": estimate_cost(result.tokens.get("prompt", 0), result.tokens.get("completion", 0)),
        "applied": result.applied,
    }


# ---------------------------------------------------------------------------
# Metrics aggregation
# ---------------------------------------------------------------------------

def aggregate_metrics(scores: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate per-scenario scores into summary metrics."""
    n = max(1, len(scores))
    return {
        "scenarios": n,
        "avg_broken_access_rate": round(sum(s["broken_access_rate"] for s in scores) / n, 4),
        "total_broken_access": sum(s["broken_access_count"] for s in scores),
        "total_escalation_remaining": sum(s["escalation_paths_remaining"] for s in scores),
        "avg_reduction_pct": round(sum(s["reduction_pct"] for s in scores) / n, 1),
        "total_retries": sum(s["retries"] for s in scores),
        "hitl_escalation_rate": round(sum(1 for s in scores if s["hitl_escalated"]) / n, 2),
        "classification_accuracy": round(sum(1 for s in scores if s["classification_correct"]) / n, 2),
        "avg_wall_time_s": round(sum(s["wall_time_s"] for s in scores) / n, 2),
        "total_cost": round(sum(s["cost"] for s in scores), 6),
    }


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def print_comparison(baseline_agg: dict, advanced_agg: dict) -> None:
    """Print the baseline vs advanced comparison table."""
    print("\n" + "=" * 70)
    print("  SENTINEL-IAM — BASELINE vs ADVANCED COMPARISON")
    print("=" * 70)

    rows = [
        ("Broken-access rate (PRIMARY)", f"{baseline_agg['avg_broken_access_rate']:.1%}",
         f"{advanced_agg['avg_broken_access_rate']:.1%}"),
        ("Escalation paths remaining", str(baseline_agg["total_escalation_remaining"]),
         str(advanced_agg["total_escalation_remaining"])),
        ("Avg reduction %", f"{baseline_agg['avg_reduction_pct']:.1f}%",
         f"{advanced_agg['avg_reduction_pct']:.1f}%"),
        ("Total retries (self-correction)", str(baseline_agg["total_retries"]),
         str(advanced_agg["total_retries"])),
        ("HITL escalation rate", f"{baseline_agg['hitl_escalation_rate']:.0%}",
         f"{advanced_agg['hitl_escalation_rate']:.0%}"),
        ("Classification accuracy", "N/A",
         f"{advanced_agg['classification_accuracy']:.0%}"),
        ("Avg wall time", f"{baseline_agg['avg_wall_time_s']:.2f}s",
         f"{advanced_agg['avg_wall_time_s']:.2f}s"),
        ("Total cost", f"${baseline_agg['total_cost']:.4f}",
         f"${advanced_agg['total_cost']:.4f}"),
    ]

    print(f"\n  {'Metric':<35} {'Baseline':>12} {'Advanced':>12}")
    print("  " + "-" * 60)
    for label, bl, adv in rows:
        print(f"  {label:<35} {bl:>12} {adv:>12}")
    print()


def print_scorecard(scenario_scores: List[Dict[str, Any]], system: str) -> None:
    """Print per-scenario scorecard."""
    print(f"\n{'─' * 70}")
    print(f"  {system.upper()} — PER-SCENARIO RESULTS")
    print(f"{'─' * 70}")
    print(f"  {'Scenario':<30} {'Broken':>7} {'Escal':>6} {'Red%':>6} {'Retry':>6} {'HITL':>5} {'Class':>6}")
    print("  " + "-" * 66)
    for s in scenario_scores:
        sid = s["scenario_id"][:28]
        print(f"  {sid:<30} {s['broken_access_count']:>7} {s['escalation_paths_remaining']:>6} "
              f"{s['reduction_pct']:>5.0f}% {s['retries']:>6} "
              f"{'YES' if s['hitl_escalated'] else 'no':>5} "
              f"{'✓' if s['classification_correct'] else '✗':>6}")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def evaluate(
    scenarios_path: str = "data/scenarios.json",
    out_dir: str = "results",
    scenario_filter: Optional[str] = None,
) -> Dict[str, Any]:
    """Run evaluation: baseline + advanced over all scenarios."""
    # Load scenarios
    sp = Path(scenarios_path)
    if not sp.exists():
        print(f"[evaluator] Scenarios not found at {sp}, generating...")
        from scripts.generate_data import main as gen
        gen()

    scenarios = json.loads(sp.read_text())
    if scenario_filter:
        scenarios = [s for s in scenarios if s["id"] == scenario_filter]
        if not scenarios:
            print(f"[evaluator] No scenario matching '{scenario_filter}'")
            sys.exit(1)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Initialize
    tracer = TrajectoryLogger(path=str(out / "trajectories.jsonl"), append=False)
    memory = RemediationMemory(path=str(out / "memory.json"))

    baseline_scores: List[Dict[str, Any]] = []
    advanced_scores: List[Dict[str, Any]] = []

    print(f"\nRunning evaluation on {len(scenarios)} scenarios (mode={SETTINGS.mode})")
    print(f"{'─' * 50}")

    for i, scenario in enumerate(scenarios, 1):
        sid = scenario["id"]
        oracle = scenario.get("_oracle", {})
        fixtures = scenario.get("fixtures", {})

        # Extract granted actions for scoring
        all_granted = []
        for stmt in fixtures.get("current_policy", {}).get("Statement", []):
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            all_granted.extend(actions)

        print(f"  [{i}/{len(scenarios)}] {sid}...", end=" ", flush=True)

        # Baseline
        bl_result = run_baseline(scenario, SETTINGS, tracer)
        bl_score = score_run(bl_result, oracle, all_granted)
        baseline_scores.append(bl_score)

        # Advanced
        adv_result = investigate(scenario, SETTINGS, tracer, memory)
        adv_score = score_run(adv_result, oracle, all_granted)
        advanced_scores.append(adv_score)

        status = "✓" if adv_score["broken_access_count"] == 0 else "✗"
        retry_info = f" retry={adv_score['retries']}" if adv_score["retries"] > 0 else ""
        hitl_info = " HITL" if adv_score["hitl_escalated"] else ""
        print(f"{status} route={adv_result.route}{retry_info}{hitl_info}")

    # Aggregate
    bl_agg = aggregate_metrics(baseline_scores)
    bl_agg["mode"] = SETTINGS.mode
    adv_agg = aggregate_metrics(advanced_scores)
    adv_agg["mode"] = SETTINGS.mode

    # Display
    print_comparison(bl_agg, adv_agg)
    print_scorecard(advanced_scores, "advanced")
    print_scorecard(baseline_scores, "baseline")

    # Write results
    results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": SETTINGS.mode,
        "scenarios_count": len(scenarios),
        "baseline": {"aggregate": bl_agg, "per_scenario": baseline_scores},
        "advanced": {"aggregate": adv_agg, "per_scenario": advanced_scores},
    }

    metrics_path = out / "metrics.json"
    metrics_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    print(f"Results written to {metrics_path}")
    print(f"Traces written to {tracer.path} ({len(tracer.steps)} steps)")
    print(f"Memory written to {out / 'memory.json'}")

    return results


def main():
    parser = argparse.ArgumentParser(description="Sentinel-IAM Evaluator")
    parser.add_argument("--scenario", type=str, default=None,
                        help="Run only a specific scenario ID")
    parser.add_argument("--out", type=str, default="results",
                        help="Output directory (default: results)")
    args = parser.parse_args()

    evaluate(scenario_filter=args.scenario, out_dir=args.out)


if __name__ == "__main__":
    main()
