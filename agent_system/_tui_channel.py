"""
Rich TUI Approval Channel — interactive terminal card for HITL demo.

Shows: risk tier, rationale, permission diff, blast radius, APPROVE/REJECT prompt.
Falls back to CliChannel if rich is not installed.
"""

from __future__ import annotations

from typing import Any, Dict

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.prompt import Prompt
    from rich.rule import Rule
    from rich.columns import Columns
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from .sandbox import ApprovalToken, mint_token


class TuiChannel:
    """Rich TUI approval channel with colored terminal output."""

    def __init__(self):
        if not HAS_RICH:
            raise ImportError("rich package not installed")
        self._console = Console()

    def present(self, rationale: str, diff: str, blast_radius: Dict[str, Any],
                risk: Dict[str, Any]) -> None:
        c = self._console

        tier = risk.get("tier", "?")
        score = risk.get("score", 0)
        tier_color = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red"}.get(tier, "white")
        components = risk.get("components", {})

        c.print()
        c.print(Rule(f"[bold white on {tier_color}]  HITL APPROVAL REQUIRED  [/]",
                     style=tier_color))
        c.print()

        # ── Risk assessment panel ─────────────────────────────────────
        risk_table = Table(show_header=False, box=None, padding=(0, 2))
        risk_table.add_column(style="bold", min_width=20)
        risk_table.add_column(min_width=30)

        risk_badge = Text(f"  {tier}  ", style=f"bold white on {tier_color}")
        risk_table.add_row("Risk Tier:", risk_badge)
        risk_table.add_row("Risk Score:", f"[{tier_color}]{score:.2f}[/]")

        for k, v in components.items():
            bar_len = int(v * 20)
            bar = "[red]" + "█" * bar_len + "[/]" + "[dim]░[/]" * (20 - bar_len)
            risk_table.add_row(f"  {k}:", f"{bar} {v:.2f}")

        c.print(Panel(risk_table, title="[bold]  Risk Assessment  [/]",
                      border_style=tier_color, width=68))

        # ── Rationale ─────────────────────────────────────────────────
        c.print(Panel(rationale, title="[bold]  Rationale  [/]",
                      border_style="blue", width=68))

        # ── Blast radius ──────────────────────────────────────────────
        if blast_radius:
            removed = blast_radius.get("permissions_removed", 0)
            retained = blast_radius.get("permissions_retained", 0)
            services = blast_radius.get("services_affected", [])
            total = removed + retained
            pct = (removed / total * 100) if total > 0 else 0

            br_grid = Table(show_header=False, box=None, padding=(0, 2))
            br_grid.add_column(style="bold", min_width=22)
            br_grid.add_column(min_width=35)
            br_grid.add_row("Permissions removed:",
                            f"[bold red]{removed}[/] ({pct:.0f}% of total)")
            br_grid.add_row("Permissions retained:",
                            f"[bold green]{retained}[/]")

            # Visual bar
            bar_total = 40
            if total > 0:
                rem_bar = int(removed / total * bar_total)
                ret_bar = bar_total - rem_bar
            else:
                rem_bar, ret_bar = 0, bar_total
            bar_text = f"[red]{'█' * rem_bar}[/][green]{'█' * ret_bar}[/]"
            br_grid.add_row("Impact:", bar_text)

            if services:
                svc_text = ", ".join(f"[cyan]{s}[/]" for s in services[:8])
                br_grid.add_row("Services affected:", svc_text)

            c.print(Panel(br_grid, title="[bold]  Blast Radius  [/]",
                          border_style="cyan", width=68))

        # ── Policy diff ───────────────────────────────────────────────
        if diff:
            diff_lines = []
            for line in diff.split("\n")[:20]:
                if line.startswith("-"):
                    diff_lines.append(f"[red]{line}[/]")
                elif line.startswith("+"):
                    diff_lines.append(f"[green]{line}[/]")
                else:
                    diff_lines.append(f"[dim]{line}[/]")
            c.print(Panel("\n".join(diff_lines),
                          title="[bold]  Policy Diff  [/]",
                          border_style="dim", width=68))

        c.print()

    def collect(self, run_id: str, scenario_id: str, secret: str) -> ApprovalToken:
        c = self._console

        while True:
            choice = Prompt.ask(
                "[bold]  Your decision[/]",
                choices=["APPROVE", "REJECT"],
                default="APPROVE",
                console=c,
            ).upper()
            if choice in ("APPROVE", "REJECT"):
                dec_color = "green" if choice == "APPROVE" else "red"
                icon = "  " if choice == "APPROVE" else "  "
                c.print(f"\n  [{dec_color} bold]{icon}{choice}D[/]\n")
                return mint_token(run_id, scenario_id, choice, "human:tui", secret)
