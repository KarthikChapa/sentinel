#!/usr/bin/env python3
"""
Sentinel-IAM — Interactive Demo Runner

Beautiful Rich TUI that runs baseline vs advanced side-by-side,
shows live progress, per-scenario detail cards, and a final
comparison dashboard. Designed for screen-recording.

Usage:
    python demo.py                              # full demo (auto-approve)
    python demo.py --interactive                # pause for HITL approval at each scenario
    python demo.py --scenario sc-03-passrole-escalation  # single scenario
    python demo.py --slack                      # also post to Slack
    python demo.py --interactive --slack        # full interactive + Slack
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Load .env before anything reads env vars
try:
    from dotenv import load_dotenv
    load_dotenv(override=False)
except ImportError:
    pass

# ── Rich imports ──────────────────────────────────────────────────────────
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.layout import Layout
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID
from rich.columns import Columns
from rich.rule import Rule
from rich.syntax import Syntax
from rich.align import Align
from rich import box

# ── Project imports ───────────────────────────────────────────────────────
from config import SETTINGS, Settings, estimate_cost
from agent_system.logger import TrajectoryLogger, new_run_id
from agent_system.memory import RemediationMemory
from agent_system.schemas import Hypothesis, RunResult
from agent_system.orchestrator import investigate
from baseline import run_baseline
from evaluator import score_run, aggregate_metrics

console = Console()

# ── SSL helper for Slack ──────────────────────────────────────────────────
def _slack_ssl_ctx() -> ssl.SSLContext:
    """Unverified SSL context — works around broken miniconda CA store."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

# ── Colour palette ────────────────────────────────────────────────────────
BRAND       = "bold cyan"
ACCENT      = "bold magenta"
SUCCESS     = "bold green"
DANGER      = "bold red"
WARNING     = "bold yellow"
DIM         = "dim white"
HEADER_STYLE = "bold white on blue"


# ═══════════════════════════════════════════════════════════════════════════
#   BANNER
# ═══════════════════════════════════════════════════════════════════════════

BANNER = r"""[bold cyan]
  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
  [bold white]Cloud IAM Least-Privilege Auto-Remediation[/]
  [dim]with Human-in-the-Loop Gateway[/]
"""


# ═══════════════════════════════════════════════════════════════════════════
#   HELPER: render scenario detail card
# ═══════════════════════════════════════════════════════════════════════════

def render_scenario_header(scenario: Dict[str, Any], idx: int, total: int) -> Panel:
    """Render a scenario identification header."""
    sid = scenario["id"]
    alert = scenario.get("alert", {})
    category = alert.get("category", scenario.get("category", ""))
    principal = alert.get("principal", scenario.get("principal", ""))
    severity = alert.get("severity", scenario.get("severity", ""))
    title = alert.get("title", scenario.get("description", ""))

    sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "green"}.get(
        severity.lower(), "white")

    grid = Table(show_header=False, box=None, padding=(0, 2))
    grid.add_column(style="bold white", min_width=14)
    grid.add_column()
    grid.add_row("Scenario:", f"[bold]{sid}[/]")
    grid.add_row("Title:", title[:50] if title else "")
    grid.add_row("Category:", category)
    grid.add_row("Principal:", principal.split("/")[-1] if "/" in principal else principal)
    grid.add_row("Severity:", f"[{sev_color}]{severity.upper()}[/]")
    grid.add_row("Progress:", f"[{BRAND}]{idx}[/] / {total}")

    return Panel(grid, title=f"[bold]  Scenario {idx}/{total}  [/]",
                 border_style="blue", width=70)


def render_pipeline_steps(
    route: str, retries: int, verification_passed: bool,
    confidence: float, risk_tier: str, decision: str,
) -> Panel:
    """Render pipeline execution steps with status indicators."""
    risk_color = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red"}.get(risk_tier, "white")

    steps = Table(show_header=False, box=None, padding=(0, 1))
    steps.add_column(width=3)
    steps.add_column(min_width=36)
    steps.add_column(justify="right", min_width=24)

    steps.add_row("[green]1[/]", "Classify & Plan",
                  f"route=[bold]{route}[/]")
    steps.add_row("[green]2[/]", "Gather Evidence (parallel workers)",
                  "[green]4 tools[/]")
    steps.add_row("[green]3[/]", "Actor: Synthesize Policy",
                  f"retries=[bold]{retries}[/]")

    v_icon = "[green]PASS[/]" if verification_passed else "[red]FAIL[/]"
    steps.add_row("[green]4[/]", "Verifier: V1-V9 Checks", v_icon)
    steps.add_row("[green]5[/]", "Compute Confidence",
                  f"[bold]{confidence:.0%}[/]")
    steps.add_row("[green]6[/]", "Risk Assessment",
                  f"[{risk_color}]{risk_tier}[/]")

    dec_style = "green" if decision == "APPROVE" else "red"
    steps.add_row("[green]7[/]", "HITL Gateway",
                  f"[{dec_style}]{decision}[/]")

    return Panel(steps, title="[bold]  Pipeline Execution  [/]",
                 border_style="cyan", width=72)


def render_policy_diff(removed: list, kept: list) -> Panel:
    """Render a visual policy diff."""
    diff_lines = []

    if removed:
        diff_lines.append("[red bold]- REMOVED (unnecessary/dangerous):[/]")
        for a in removed[:12]:
            esc = ""
            low = a.lower()
            if "passrole" in low or "createaccesskey" in low or "createpolicy" in low:
                esc = " [red][ESCALATION PATH CLOSED][/]"
            elif a.endswith(":*") or a == "*":
                esc = " [yellow][WILDCARD REMOVED][/]"
            diff_lines.append(f"  [red]- {a}[/]{esc}")
        if len(removed) > 12:
            diff_lines.append(f"  [dim]... and {len(removed) - 12} more[/]")

    diff_lines.append("")

    if kept:
        diff_lines.append("[green bold]+ RETAINED (actively used):[/]")
        for a in kept[:8]:
            diff_lines.append(f"  [green]+ {a}[/]")
        if len(kept) > 8:
            diff_lines.append(f"  [dim]... and {len(kept) - 8} more[/]")

    return Panel("\n".join(diff_lines), title="[bold]  Permission Changes  [/]",
                 border_style="magenta", width=70)


def render_baseline_comparison(bl_score: dict, adv_score: dict) -> Panel:
    """Render side-by-side comparison for a single scenario."""
    t = Table(box=box.SIMPLE_HEAVY, show_edge=False)
    t.add_column("Metric", style="bold", min_width=28)
    t.add_column("Baseline", justify="center", min_width=12)
    t.add_column("Advanced", justify="center", min_width=12)
    t.add_column("Winner", justify="center", min_width=8)

    # Broken access
    bl_broken = bl_score["broken_access_count"]
    adv_broken = adv_score["broken_access_count"]
    bl_style = "red" if bl_broken > 0 else "green"
    adv_style = "green" if adv_broken == 0 else "red"
    winner = "[green]Advanced[/]" if adv_broken < bl_broken else (
        "[yellow]Tie[/]" if adv_broken == bl_broken else "[red]Baseline[/]")
    t.add_row("Broken Access",
              f"[{bl_style}]{bl_broken}[/]", f"[{adv_style}]{adv_broken}[/]", winner)

    # Escalation paths
    bl_esc = bl_score["escalation_paths_remaining"]
    adv_esc = adv_score["escalation_paths_remaining"]
    bl_style = "red" if bl_esc > 0 else "green"
    adv_style = "green" if adv_esc == 0 else "yellow"
    winner = "[green]Advanced[/]" if adv_esc < bl_esc else (
        "[yellow]Tie[/]" if adv_esc == bl_esc else "[red]Baseline[/]")
    t.add_row("Escalation Paths Left",
              f"[{bl_style}]{bl_esc}[/]", f"[{adv_style}]{adv_esc}[/]", winner)

    # Reduction
    bl_red = bl_score["reduction_pct"]
    adv_red = adv_score["reduction_pct"]
    t.add_row("Reduction %",
              f"{bl_red:.0f}%", f"[bold]{adv_red:.0f}%[/]",
              "[green]Advanced[/]" if adv_red >= bl_red else "[yellow]Baseline[/]")

    # HITL
    t.add_row("HITL Escalation",
              "[dim]None[/]",
              "[green]Yes[/]" if adv_score["hitl_escalated"] else "[dim]No[/]",
              "[green]Advanced[/]" if adv_score["hitl_escalated"] else "[yellow]Tie[/]")

    # Classification
    t.add_row("Classification",
              "[dim]N/A[/]",
              "[green]Correct[/]" if adv_score["classification_correct"] else "[red]Wrong[/]",
              "")

    return Panel(t, title="[bold]  Baseline vs Advanced  [/]",
                 border_style="yellow", width=70)


# ═══════════════════════════════════════════════════════════════════════════
#   FINAL DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════

def render_final_dashboard(
    baseline_scores: list, advanced_scores: list,
    bl_agg: dict, adv_agg: dict,
    wall_time: float,
) -> None:
    """Render the final comparison dashboard."""
    console.print()
    console.print(Rule("[bold white on blue]  FINAL RESULTS DASHBOARD  [/]", style="blue"))
    console.print()

    # ── Summary cards ─────────────────────────────────────────────────
    cards = []

    # Primary metric
    bl_broken = bl_agg["avg_broken_access_rate"]
    adv_broken = adv_agg["avg_broken_access_rate"]
    improvement = bl_broken - adv_broken
    cards.append(Panel(
        f"[bold white]Broken-Access Rate[/]\n\n"
        f"  Baseline:  [{DANGER}]{bl_broken:.1%}[/]\n"
        f"  Advanced:  [{SUCCESS}]{adv_broken:.1%}[/]\n\n"
        f"  Improvement: [{SUCCESS}]{improvement:+.1%}[/]",
        border_style="green" if adv_broken == 0 else "red",
        title="[bold]PRIMARY METRIC[/]", width=34,
    ))

    # Escalation
    bl_esc = bl_agg["total_escalation_remaining"]
    adv_esc = adv_agg["total_escalation_remaining"]
    cards.append(Panel(
        f"[bold white]Escalation Paths[/]\n\n"
        f"  Baseline:  [{DANGER}]{bl_esc}[/]\n"
        f"  Advanced:  [{'green' if adv_esc <= 1 else 'yellow'}]{adv_esc}[/]\n\n"
        f"  Closed: [{SUCCESS}]{bl_esc - adv_esc}[/] paths",
        border_style="green" if adv_esc <= 1 else "yellow",
        title="[bold]SECURITY[/]", width=34,
    ))

    console.print(Columns(cards, padding=(0, 1), align="center"))
    console.print()

    # ── Detailed comparison table ─────────────────────────────────────
    t = Table(title="[bold]Aggregate Metrics[/]",
              box=box.DOUBLE_EDGE, border_style="blue",
              title_style="bold white")
    t.add_column("Metric", style="bold", min_width=32)
    t.add_column("Baseline", justify="center", min_width=14, style="red")
    t.add_column("Advanced", justify="center", min_width=14, style="green")
    t.add_column("Delta", justify="center", min_width=10)

    def delta(bl_val, adv_val, fmt=".1f", lower_better=True):
        d = adv_val - bl_val
        if lower_better:
            color = "green" if d <= 0 else "red"
        else:
            color = "green" if d >= 0 else "red"
        return f"[{color}]{d:+{fmt}}[/]"

    t.add_row("Broken-Access Rate",
              f"{bl_agg['avg_broken_access_rate']:.1%}",
              f"{adv_agg['avg_broken_access_rate']:.1%}",
              delta(bl_agg['avg_broken_access_rate'], adv_agg['avg_broken_access_rate'], ".1%"))
    t.add_row("Escalation Paths Remaining",
              str(bl_esc), str(adv_esc),
              delta(bl_esc, adv_esc, "d"))
    t.add_row("Avg Reduction %",
              f"{bl_agg['avg_reduction_pct']:.1f}%",
              f"{adv_agg['avg_reduction_pct']:.1f}%",
              delta(bl_agg['avg_reduction_pct'], adv_agg['avg_reduction_pct'], ".1f", lower_better=False))
    t.add_row("Self-Correction Retries",
              str(bl_agg['total_retries']),
              str(adv_agg['total_retries']),
              f"[cyan]+{adv_agg['total_retries']}[/]")
    t.add_row("HITL Escalation Rate",
              f"{bl_agg['hitl_escalation_rate']:.0%}",
              f"{adv_agg['hitl_escalation_rate']:.0%}",
              f"[green]+{adv_agg['hitl_escalation_rate']:.0%}[/]")
    t.add_row("Classification Accuracy",
              "[dim]N/A[/]",
              f"{adv_agg['classification_accuracy']:.0%}",
              f"[green]{adv_agg['classification_accuracy']:.0%}[/]")

    console.print(Align.center(t))
    console.print()

    # ── Per-scenario scorecard ────────────────────────────────────────
    sc_table = Table(title="[bold]Per-Scenario Breakdown[/]",
                     box=box.ROUNDED, border_style="cyan",
                     title_style="bold white", show_lines=True)
    sc_table.add_column("Scenario", style="bold", min_width=30)
    sc_table.add_column("BL Broken", justify="center", min_width=10)
    sc_table.add_column("Adv Broken", justify="center", min_width=10)
    sc_table.add_column("BL Escal", justify="center", min_width=9)
    sc_table.add_column("Adv Escal", justify="center", min_width=9)
    sc_table.add_column("BL Red%", justify="center", min_width=8)
    sc_table.add_column("Adv Red%", justify="center", min_width=8)
    sc_table.add_column("Retries", justify="center", min_width=8)
    sc_table.add_column("Class", justify="center", min_width=6)

    for bl, adv in zip(baseline_scores, advanced_scores):
        sid = bl["scenario_id"]
        bl_br = bl["broken_access_count"]
        adv_br = adv["broken_access_count"]
        bl_es = bl["escalation_paths_remaining"]
        adv_es = adv["escalation_paths_remaining"]

        sc_table.add_row(
            sid,
            f"[{'red' if bl_br > 0 else 'green'}]{bl_br}[/]",
            f"[{'red' if adv_br > 0 else 'green'}]{adv_br}[/]",
            f"[{'red' if bl_es > 0 else 'green'}]{bl_es}[/]",
            f"[{'red' if adv_es > 0 else 'green'}]{adv_es}[/]",
            f"{bl['reduction_pct']:.0f}%",
            f"[bold]{adv['reduction_pct']:.0f}%[/]",
            str(adv["retries"]) if adv["retries"] > 0 else "[dim]0[/]",
            "[green]OK[/]" if adv["classification_correct"] else "[red]MISS[/]",
        )

    console.print(Align.center(sc_table))
    console.print()

    # ── Footer ────────────────────────────────────────────────────────
    footer = Table(show_header=False, box=None, padding=(0, 2))
    footer.add_column(min_width=20)
    footer.add_column()
    footer.add_row("[bold]Total wall time:", f"{wall_time:.1f}s")
    footer.add_row("[bold]Mode:", SETTINGS.mode)
    footer.add_row("[bold]Scenarios:", str(len(baseline_scores)))
    footer.add_row("[bold]Artifacts:", "results/metrics.json, results/trajectories.jsonl")

    console.print(Panel(footer, title="[bold]  Run Info  [/]",
                        border_style="dim", width=60))
    console.print()


# ═══════════════════════════════════════════════════════════════════════════
#   HITL CARD (Interactive mode)
# ═══════════════════════════════════════════════════════════════════════════

def render_hitl_card(
    scenario: Dict[str, Any],
    hypothesis: Hypothesis,
    risk: Dict[str, Any],
    confidence: float,
) -> str:
    """Render a full HITL approval card and collect decision."""
    tier = risk.get("tier", "?")
    score = risk.get("score", 0)
    risk_color = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red"}.get(tier, "white")

    console.print()
    console.print(Rule(f"[bold white on {risk_color}]  HUMAN-IN-THE-LOOP APPROVAL  [/]",
                       style=risk_color))
    console.print()

    # Risk badge
    risk_panel = Table(show_header=False, box=None, padding=(0, 2))
    risk_panel.add_column(style="bold", min_width=20)
    risk_panel.add_column()
    risk_panel.add_row("Risk Tier:",
                       Text(f"  {tier}  ", style=f"bold white on {risk_color}"))
    risk_panel.add_row("Risk Score:", f"[{risk_color}]{score:.2f}[/]")
    risk_panel.add_row("Confidence:", f"{confidence:.0%}")
    risk_panel.add_row("Scenario:", scenario.get("id", ""))
    risk_panel.add_row("Principal:", scenario.get("principal", ""))
    components = risk.get("components", {})
    for k, v in components.items():
        risk_panel.add_row(f"  {k}:", f"{v:.2f}")

    console.print(Panel(risk_panel, title="[bold]  Risk Assessment  [/]",
                        border_style=risk_color, width=70))

    # Rationale
    console.print(Panel(
        hypothesis.rationale or "No rationale provided.",
        title="[bold]  Rationale  [/]",
        border_style="blue", width=70,
    ))

    # Permission diff
    console.print(render_policy_diff(hypothesis.removed, hypothesis.kept))

    # Blast radius
    services = list(set(a.split(":")[0] for a in hypothesis.removed if ":" in a))
    blast = Table(show_header=False, box=None, padding=(0, 2))
    blast.add_column(style="bold", min_width=22)
    blast.add_column()
    blast.add_row("Permissions removed:", f"[bold]{len(hypothesis.removed)}[/]")
    blast.add_row("Permissions retained:", f"[bold]{len(hypothesis.kept)}[/]")
    blast.add_row("Services affected:", ", ".join(services[:8]) if services else "N/A")

    console.print(Panel(blast, title="[bold]  Blast Radius  [/]",
                        border_style="cyan", width=70))
    console.print()

    # Decision prompt
    from rich.prompt import Prompt
    while True:
        choice = Prompt.ask(
            f"[bold {risk_color}]Decision[/]",
            choices=["APPROVE", "REJECT"],
            default="APPROVE",
            console=console,
        ).upper()
        if choice in ("APPROVE", "REJECT"):
            dec_color = "green" if choice == "APPROVE" else "red"
            console.print(f"\n  [{dec_color} bold]{choice}D[/]", highlight=False)
            return choice


# ═══════════════════════════════════════════════════════════════════════════
#   SLACK INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════

def post_to_slack(
    scenario: Dict[str, Any],
    adv_score: Dict[str, Any],
    bl_score: Dict[str, Any],
    hypothesis: Hypothesis,
    risk: Dict[str, Any],
) -> bool:
    """Post a summary to Slack. Returns True if successful."""
    try:
        from slack_sdk import WebClient
    except ImportError:
        return False

    token = os.getenv("SLACK_BOT_TOKEN")
    channel = os.getenv("SLACK_CHANNEL")
    if not token or not channel:
        return False

    client = WebClient(token=token, ssl=_slack_ssl_ctx())
    sid = scenario.get("id", "unknown")
    tier = risk.get("tier", "?")
    tier_emoji = {"LOW": ":large_green_circle:", "MEDIUM": ":large_yellow_circle:",
                  "HIGH": ":red_circle:"}.get(tier, ":white_circle:")

    blocks = [
        {"type": "header",
         "text": {"type": "plain_text",
                  "text": f"Sentinel-IAM: {sid}"}},
        {"type": "section",
         "text": {"type": "mrkdwn",
                  "text": f"{tier_emoji} *Risk: {tier}*  |  "
                          f"Removed: *{len(hypothesis.removed)}*  |  "
                          f"Retained: *{len(hypothesis.kept)}*"}},
        {"type": "divider"},
        {"type": "section",
         "fields": [
             {"type": "mrkdwn",
              "text": f"*Baseline*\n"
                      f"Broken: {bl_score['broken_access_count']}\n"
                      f"Escalation: {bl_score['escalation_paths_remaining']}\n"
                      f"Reduction: {bl_score['reduction_pct']:.0f}%"},
             {"type": "mrkdwn",
              "text": f"*Advanced*\n"
                      f"Broken: {adv_score['broken_access_count']}\n"
                      f"Escalation: {adv_score['escalation_paths_remaining']}\n"
                      f"Reduction: {adv_score['reduction_pct']:.0f}%"},
         ]},
    ]

    # Add diff snippet
    diff_text = ""
    for a in hypothesis.removed[:5]:
        diff_text += f"- {a}\n"
    for a in hypothesis.kept[:3]:
        diff_text += f"+ {a}\n"
    if diff_text:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn",
                     "text": f"*Policy Changes*\n```{diff_text.strip()}```"},
        })

    try:
        client.chat_postMessage(
            channel=channel,
            text=f"Sentinel-IAM result for {sid}",
            blocks=blocks,
        )
        return True
    except Exception:
        return False


def post_final_summary_to_slack(bl_agg: dict, adv_agg: dict, n_scenarios: int) -> bool:
    """Post the final comparison summary to Slack."""
    try:
        from slack_sdk import WebClient
    except ImportError:
        return False

    token = os.getenv("SLACK_BOT_TOKEN")
    channel = os.getenv("SLACK_CHANNEL")
    if not token or not channel:
        return False

    client = WebClient(token=token, ssl=_slack_ssl_ctx())
    improvement = bl_agg["avg_broken_access_rate"] - adv_agg["avg_broken_access_rate"]
    esc_closed = bl_agg["total_escalation_remaining"] - adv_agg["total_escalation_remaining"]

    blocks = [
        {"type": "header",
         "text": {"type": "plain_text",
                  "text": ":shield: Sentinel-IAM Final Results"}},
        {"type": "section",
         "text": {"type": "mrkdwn",
                  "text": f"Evaluated *{n_scenarios}* scenarios\n\n"
                          f":dart: *Primary Metric: Broken-Access Rate*\n"
                          f"  Baseline: `{bl_agg['avg_broken_access_rate']:.1%}` "
                          f"| Advanced: `{adv_agg['avg_broken_access_rate']:.1%}` "
                          f"| Improvement: `{improvement:+.1%}`\n\n"
                          f":lock: *Escalation Paths*\n"
                          f"  Baseline: `{bl_agg['total_escalation_remaining']}` "
                          f"| Advanced: `{adv_agg['total_escalation_remaining']}` "
                          f"| Closed: `{esc_closed}`\n\n"
                          f":scissors: *Avg Reduction*\n"
                          f"  Baseline: `{bl_agg['avg_reduction_pct']:.1f}%` "
                          f"| Advanced: `{adv_agg['avg_reduction_pct']:.1f}%`\n\n"
                          f":robot_face: *Self-Correction Retries:* `{adv_agg['total_retries']}`\n"
                          f":raising_hand: *HITL Escalation Rate:* `{adv_agg['hitl_escalation_rate']:.0%}`\n"
                          f":white_check_mark: *Classification Accuracy:* `{adv_agg['classification_accuracy']:.0%}`"}},
    ]

    try:
        client.chat_postMessage(
            channel=channel,
            text="Sentinel-IAM Final Results",
            blocks=blocks,
        )
        return True
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════════════════
#   MAIN DEMO RUNNER
# ═══════════════════════════════════════════════════════════════════════════

def run_demo(
    interactive: bool = False,
    scenario_filter: Optional[str] = None,
    use_slack: bool = False,
) -> None:
    """Run the full demo with Rich TUI output."""
    demo_start = time.time()

    # ── Banner ────────────────────────────────────────────────────────
    console.print(BANNER)
    console.print()

    mode_info = Table(show_header=False, box=None, padding=(0, 2))
    mode_info.add_column(style="bold cyan", min_width=16)
    mode_info.add_column()
    mode_info.add_row("Mode:", f"[bold]{SETTINGS.mode}[/]")
    mode_info.add_row("Backend:", SETTINGS.backend)
    mode_info.add_row("Interactive:", "[green]Yes[/]" if interactive else "[dim]No (auto-approve)[/]")
    mode_info.add_row("Slack:", "[green]Enabled[/]" if use_slack else "[dim]Disabled[/]")
    mode_info.add_row("Max Retries:", str(SETTINGS.max_retries))
    mode_info.add_row("AWS-Ready:", "[yellow]Backend abstraction ready[/]")

    console.print(Panel(mode_info, title="[bold]  Configuration  [/]",
                        border_style="blue", width=60))
    console.print()

    # ── Load scenarios ────────────────────────────────────────────────
    sp = Path("data/scenarios.json")
    if not sp.exists():
        console.print("[yellow]Generating scenarios...[/]")
        from scripts.generate_data import main as gen
        gen()

    scenarios = json.loads(sp.read_text())
    if scenario_filter:
        scenarios = [s for s in scenarios if s["id"] == scenario_filter]
        if not scenarios:
            console.print(f"[red]No scenario matching '{scenario_filter}'[/]")
            return

    console.print(f"[bold]Loaded {len(scenarios)} scenarios[/]\n")

    # ── Initialize ────────────────────────────────────────────────────
    out = Path("results")
    out.mkdir(parents=True, exist_ok=True)
    tracer = TrajectoryLogger(path=str(out / "trajectories.jsonl"), append=False)
    memory = RemediationMemory(path=str(out / "memory.json"))

    # Override settings for interactive mode
    settings = Settings()
    if interactive:
        settings.auto_approve = False
        if use_slack:
            settings.hitl_channel = "slack"
        else:
            settings.hitl_channel = "tui"
    else:
        settings.auto_approve = True
        settings.hitl_channel = "auto"

    baseline_scores: List[Dict[str, Any]] = []
    advanced_scores: List[Dict[str, Any]] = []

    # ── Run scenarios ─────────────────────────────────────────────────
    for idx, scenario in enumerate(scenarios, 1):
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

        # Scenario header
        console.print(render_scenario_header(scenario, idx, len(scenarios)))

        # Progress spinner for baseline
        with Progress(
            SpinnerColumn("dots"),
            TextColumn("[bold blue]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Running baseline (single-pass, no verification)...", total=None)
            bl_result = run_baseline(scenario, settings, tracer)
            progress.update(task, description="[green]Baseline complete[/]")

        bl_score = score_run(bl_result, oracle, all_granted)
        baseline_scores.append(bl_score)

        # Quick baseline result
        bl_broken = bl_score["broken_access_count"]
        bl_esc = bl_score["escalation_paths_remaining"]
        bl_red = bl_score["reduction_pct"]
        bl_style = "red" if bl_broken > 0 else "green"
        console.print(f"  Baseline: [{bl_style}]broken={bl_broken}[/] "
                      f"escal=[{'red' if bl_esc > 0 else 'green'}]{bl_esc}[/] "
                      f"reduction={bl_red:.0f}%\n")

        # Run advanced pipeline
        if interactive:
            # In interactive mode, don't wrap in spinner — the HITL card
            # renders inline during investigate() and needs the console
            console.print(f"  [bold cyan]Running advanced pipeline...[/]")
            adv_result = investigate(scenario, settings, tracer, memory)
            console.print(f"  [green]Advanced pipeline complete[/]\n")
        else:
            with Progress(
                SpinnerColumn("dots"),
                TextColumn("[bold cyan]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task("Running advanced pipeline...", total=None)
                adv_result = investigate(scenario, settings, tracer, memory)
                progress.update(task, description="[green]Advanced pipeline complete[/]")

        adv_score = score_run(adv_result, oracle, all_granted)
        advanced_scores.append(adv_score)

        hyp = adv_result.hypothesis or Hypothesis()

        # Compute risk info for display
        from agent_system.risk import compute_risk
        risk = compute_risk(hyp, hyp.confidence)

        # Pipeline steps
        v_passed = adv_result.verification.passed if adv_result.verification else False
        console.print(render_pipeline_steps(
            route=adv_result.route,
            retries=adv_result.retries,
            verification_passed=v_passed,
            confidence=hyp.confidence,
            risk_tier=risk["tier"],
            decision=adv_result.approval_decision or "AUTO",
        ))

        # Permission diff
        console.print(render_policy_diff(hyp.removed, hyp.kept))

        # Comparison
        console.print(render_baseline_comparison(bl_score, adv_score))

        # Slack integration
        if use_slack:
            slack_ok = post_to_slack(scenario, adv_score, bl_score, hyp, risk)
            if slack_ok:
                console.print(f"  [bold green]Posted to Slack[/]\n")
            else:
                console.print(f"  [dim]Slack: skipped (not configured)[/]\n")

        # Pause between scenarios for readability
        if idx < len(scenarios):
            console.print(Rule(style="dim"))
            if not interactive:
                time.sleep(0.3)

    # ── Final dashboard ───────────────────────────────────────────────
    bl_agg = aggregate_metrics(baseline_scores)
    adv_agg = aggregate_metrics(advanced_scores)
    wall_time = time.time() - demo_start

    render_final_dashboard(baseline_scores, advanced_scores, bl_agg, adv_agg, wall_time)

    # Post final summary to Slack
    if use_slack:
        if post_final_summary_to_slack(bl_agg, adv_agg, len(scenarios)):
            console.print("[bold green]Final summary posted to Slack[/]\n")

    # Write results
    results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": SETTINGS.mode,
        "scenarios_count": len(scenarios),
        "demo_mode": "interactive" if interactive else "batch",
        "baseline": {"aggregate": bl_agg, "per_scenario": baseline_scores},
        "advanced": {"aggregate": adv_agg, "per_scenario": advanced_scores},
    }
    (out / "metrics.json").write_text(json.dumps(results, indent=2, default=str))

    console.print(Panel(
        f"[bold]Artifacts saved:[/]\n"
        f"  results/metrics.json\n"
        f"  results/trajectories.jsonl ({len(tracer.steps)} steps)\n"
        f"  results/memory.json",
        title="[bold]  Output  [/]",
        border_style="green", width=50,
    ))

    # Final verdict
    console.print()
    if adv_agg["avg_broken_access_rate"] == 0:
        console.print(Panel(
            "[bold green]ZERO broken access across all scenarios.[/]\n"
            "[bold]The advanced system achieves least-privilege without breaking production.[/]",
            title="[bold white on green]  VERDICT  [/]",
            border_style="green", width=70,
        ))
    else:
        console.print(Panel(
            f"[yellow]Broken-access rate: {adv_agg['avg_broken_access_rate']:.1%}[/]\n"
            f"Some scenarios have regressions. Review needed.",
            title="[bold white on yellow]  VERDICT  [/]",
            border_style="yellow", width=70,
        ))
    console.print()


# ═══════════════════════════════════════════════════════════════════════════
#   CLI
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Sentinel-IAM Interactive Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python demo.py                     Full batch demo (screen-recording friendly)
  python demo.py --interactive       Pause at each scenario for HITL approval
  python demo.py --slack             Post results to Slack
  python demo.py --scenario sc-03    Run a single scenario
        """,
    )
    parser.add_argument("--interactive", "-i", action="store_true",
                        help="Enable interactive HITL approval (pause at each scenario)")
    parser.add_argument("--scenario", "-s", type=str, default=None,
                        help="Run only a specific scenario ID (prefix match)")
    parser.add_argument("--slack", action="store_true",
                        help="Post results to Slack channel")
    args = parser.parse_args()

    run_demo(
        interactive=args.interactive,
        scenario_filter=args.scenario,
        use_slack=args.slack,
    )


if __name__ == "__main__":
    main()
