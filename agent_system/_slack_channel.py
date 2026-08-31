"""
Slack HITL Approval Channel — full Slack-native decision collection.

Posts a Block Kit approval card, then polls Slack for the human's decision:
  1. Thread reply: human replies 'approve' or 'reject' in the message thread
  2. Reaction: human reacts with a checkmark or X emoji
  3. CLI fallback: if Slack polling times out after 5 minutes

The card updates live when a decision is received.
"""

from __future__ import annotations

import logging
import os
import ssl
import socket
import time
from typing import Any, Dict, List, Optional

try:
    from dotenv import load_dotenv
    load_dotenv(override=False)
except ImportError:
    pass

from .sandbox import ApprovalToken, mint_token

try:
    from slack_sdk import WebClient
    from slack_sdk.errors import SlackApiError
    HAS_SLACK = True
except ImportError:
    HAS_SLACK = False

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.rule import Rule
    from rich.spinner import Spinner
    from rich.live import Live
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

log = logging.getLogger("sentinel.slack")

SLACK_POLL_TIMEOUT = 300   # 5 minutes
SLACK_POLL_INTERVAL = 2    # seconds between polls

REACTION_APPROVE = {"white_check_mark", "heavy_check_mark", "+1", "thumbsup", "rocket", "tada"}
REACTION_REJECT = {"x", "no_entry", "-1", "thumbsdown", "octagonal_sign"}


def _make_ssl_context() -> ssl.SSLContext:
    """SSL context with fallback for broken CA stores (macOS miniconda)."""
    try:
        ctx = ssl.create_default_context()
        sock = socket.create_connection(("slack.com", 443), timeout=5)
        ssock = ctx.wrap_socket(sock, server_hostname="slack.com")
        ssock.close()
        return ctx
    except Exception:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx


class SlackChannel:
    """
    Full Slack-native HITL channel.

    Posts approval card → polls for thread reply or reaction → updates card.
    Decision is made entirely in Slack — no terminal input needed.
    """

    def __init__(self) -> None:
        if not HAS_SLACK:
            raise ImportError("slack_sdk not installed")

        self._token = os.getenv("SLACK_BOT_TOKEN")
        self._channel = os.getenv("SLACK_CHANNEL")
        if not self._token or not self._channel:
            raise ValueError("SLACK_BOT_TOKEN and SLACK_CHANNEL must be set")

        self._client = WebClient(token=self._token, ssl=_make_ssl_context())
        self._message_ts: Optional[str] = None
        self._bot_user_id: Optional[str] = None
        self._console = Console() if HAS_RICH else None

        try:
            auth = self._client.auth_test()
            self._bot_user_id = auth.get("user_id")
        except Exception as e:
            log.warning("Could not get bot user ID: %s", e)

    # ──────────────────────────────────────────────────────────────────
    #  PRESENT
    # ──────────────────────────────────────────────────────────────────

    def present(self, rationale: str, diff: str, blast_radius: Dict[str, Any],
                risk: Dict[str, Any]) -> None:
        """Post approval card to Slack."""
        tier = risk.get("tier", "UNKNOWN")
        score = risk.get("score", 0)
        removed = blast_radius.get("permissions_removed", 0)
        retained = blast_radius.get("permissions_retained", 0)
        services = blast_radius.get("services_affected", [])
        tier_emoji = {"LOW": ":large_green_circle:", "MEDIUM": ":large_yellow_circle:",
                      "HIGH": ":red_circle:"}.get(tier, ":white_circle:")

        blocks = [
            {"type": "header",
             "text": {"type": "plain_text",
                      "text": "Sentinel-IAM  Approval Required"}},
            {"type": "section",
             "text": {"type": "mrkdwn",
                      "text": f"{tier_emoji} *Risk: {tier}* (score {score:.2f})"}},
            {"type": "divider"},
            {"type": "section",
             "text": {"type": "mrkdwn",
                      "text": f"*Rationale*\n{rationale[:2000]}"}},
            {"type": "section",
             "fields": [
                 {"type": "mrkdwn", "text": f"*Removed:* {removed} permissions"},
                 {"type": "mrkdwn", "text": f"*Retained:* {retained} permissions"},
                 {"type": "mrkdwn",
                  "text": f"*Services:* {', '.join(services[:5]) if services else 'N/A'}"},
             ]},
        ]

        if diff:
            blocks.append({"type": "section",
                           "text": {"type": "mrkdwn",
                                    "text": f"*Policy Diff*\n```{diff[:500]}```"}})

        blocks.extend([
            {"type": "divider"},
            {"type": "section",
             "text": {"type": "mrkdwn",
                      "text": ":point_right: *To approve:* Reply `approve` in this thread "
                              "or react :white_check_mark:\n"
                              ":point_right: *To reject:* Reply `reject` in this thread "
                              "or react :x:"}},
            {"type": "context",
             "elements": [
                 {"type": "mrkdwn",
                  "text": ":hourglass_flowing_sand: Awaiting human decision..."}]},
        ])

        try:
            resp = self._client.chat_postMessage(
                channel=self._channel,
                text=f"Sentinel-IAM approval needed — Risk: {tier}",
                blocks=blocks,
            )
            self._message_ts = resp.get("ts")
        except Exception as e:
            log.error("Slack post failed: %s", e)

        # Store for later
        self._risk = risk
        self._blast_radius = blast_radius

    # ──────────────────────────────────────────────────────────────────
    #  COLLECT — poll Slack for decision
    # ──────────────────────────────────────────────────────────────────

    def collect(self, run_id: str, scenario_id: str, secret: str) -> ApprovalToken:
        """Poll Slack for thread reply or reaction. Falls back to CLI on timeout."""
        if not self._message_ts:
            return self._cli_fallback(run_id, scenario_id, secret)

        start = time.time()
        c = self._console

        if c:
            c.print()
            c.print(Panel(
                "[bold cyan]Waiting for decision in Slack...[/]\n\n"
                "  Reply [bold green]approve[/] or [bold red]reject[/] in the Slack thread\n"
                "  Or react with :white_check_mark: / :x: on the message\n\n"
                f"  [dim]Channel: {self._channel}  |  Timeout: {SLACK_POLL_TIMEOUT}s[/]",
                title="[bold]  Slack HITL — Listening  [/]",
                border_style="cyan", width=65,
            ))
            c.print()
        else:
            print(f"\n[slack] Waiting for decision in Slack (reply or react)...")
            print(f"[slack] Channel: {self._channel} | Timeout: {SLACK_POLL_TIMEOUT}s")

        while time.time() - start < SLACK_POLL_TIMEOUT:
            elapsed = int(time.time() - start)

            # 1. Check thread replies
            decision = self._check_thread_replies()
            if decision:
                approver = "human:slack_thread"
                self._announce_decision(decision, "thread reply", c)
                self._update_card(decision, "thread reply")
                return mint_token(run_id, scenario_id, decision, approver, secret)

            # 2. Check reactions
            decision = self._check_reactions()
            if decision:
                approver = "human:slack_reaction"
                self._announce_decision(decision, "reaction", c)
                self._update_card(decision, "reaction")
                return mint_token(run_id, scenario_id, decision, approver, secret)

            # Progress indicator every 15s
            if elapsed > 0 and elapsed % 15 == 0:
                remaining = SLACK_POLL_TIMEOUT - elapsed
                if c:
                    c.print(f"  [dim]...waiting ({elapsed}s elapsed, {remaining}s remaining)[/]")
                else:
                    print(f"  ...waiting ({elapsed}s / {SLACK_POLL_TIMEOUT}s)")

            time.sleep(SLACK_POLL_INTERVAL)

        # Timeout
        if c:
            c.print("[yellow]  Slack polling timed out. Falling back to terminal.[/]\n")
        else:
            print(f"\n[slack] Timed out after {SLACK_POLL_TIMEOUT}s.")

        return self._cli_fallback(run_id, scenario_id, secret)

    # ──────────────────────────────────────────────────────────────────
    #  POLL METHODS
    # ──────────────────────────────────────────────────────────────────

    def _check_thread_replies(self) -> Optional[str]:
        """Check for approve/reject replies in the Slack thread."""
        try:
            result = self._client.conversations_replies(
                channel=self._channel, ts=self._message_ts, limit=10)
            for msg in result.get("messages", [])[1:]:  # skip the card itself
                if msg.get("user") == self._bot_user_id or msg.get("bot_id"):
                    continue
                text = msg.get("text", "").strip().lower()
                if text in ("approve", "approved", "yes", "lgtm", "ok", "ship it"):
                    return "APPROVE"
                if text in ("reject", "rejected", "no", "deny", "denied", "nope"):
                    return "REJECT"
        except SlackApiError:
            pass
        except Exception:
            pass
        return None

    def _check_reactions(self) -> Optional[str]:
        """Check for approve/reject reactions on the card."""
        try:
            result = self._client.reactions_get(
                channel=self._channel, timestamp=self._message_ts)
            for reaction in result.get("message", {}).get("reactions", []):
                name = reaction.get("name", "")
                users = reaction.get("users", [])
                human = any(u != self._bot_user_id for u in users)
                if not human:
                    continue
                if name in REACTION_APPROVE:
                    return "APPROVE"
                if name in REACTION_REJECT:
                    return "REJECT"
        except SlackApiError:
            pass
        except Exception:
            pass
        return None

    # ──────────────────────────────────────────────────────────────────
    #  UPDATE CARD + ANNOUNCE
    # ──────────────────────────────────────────────────────────────────

    def _announce_decision(self, decision: str, source: str,
                           console: Optional[Any] = None) -> None:
        """Announce the decision in the terminal."""
        color = "green" if decision == "APPROVE" else "red"
        icon = "APPROVED" if decision == "APPROVE" else "REJECTED"
        if console:
            console.print()
            console.print(Panel(
                f"[bold {color}]{icon}[/]  (via Slack {source})",
                border_style=color, width=50,
            ))
            console.print()
        else:
            print(f"\n  [{decision}] Decision received from Slack {source}\n")

    def _update_card(self, decision: str, source: str) -> None:
        """Update the Slack card to show the resolved state."""
        if not self._message_ts:
            return

        emoji = ":white_check_mark:" if decision == "APPROVE" else ":x:"
        label = "APPROVED" if decision == "APPROVE" else "REJECTED"
        ts_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        tier = self._risk.get("tier", "?") if hasattr(self, "_risk") else "?"
        removed = self._blast_radius.get("permissions_removed", 0) if hasattr(self, "_blast_radius") else 0
        retained = self._blast_radius.get("permissions_retained", 0) if hasattr(self, "_blast_radius") else 0

        try:
            self._client.chat_update(
                channel=self._channel, ts=self._message_ts,
                text=f"{emoji} {label}",
                blocks=[
                    {"type": "header",
                     "text": {"type": "plain_text",
                              "text": f"Sentinel-IAM — {label}"}},
                    {"type": "section",
                     "text": {"type": "mrkdwn",
                              "text": f"{emoji} *Decision: {label}*\n"
                                      f"Via: {source}\n"
                                      f"At: {ts_str}"}},
                    {"type": "divider"},
                    {"type": "context",
                     "elements": [{"type": "mrkdwn",
                                   "text": f"Risk: {tier} | "
                                           f"Removed: {removed} | "
                                           f"Retained: {retained}"}]},
                ],
            )
            self._client.chat_postMessage(
                channel=self._channel, thread_ts=self._message_ts,
                text=f"{emoji} Decision recorded: *{label}* via {source} at {ts_str}",
            )
        except Exception:
            pass

    # ──────────────────────────────────────────────────────────────────
    #  CLI FALLBACK
    # ──────────────────────────────────────────────────────────────────

    def _cli_fallback(self, run_id: str, scenario_id: str, secret: str) -> ApprovalToken:
        """Terminal fallback when Slack polling times out or card wasn't posted."""
        while True:
            choice = input("  APPROVE or REJECT? ").strip().upper()
            if choice in ("APPROVE", "REJECT"):
                self._update_card(choice, "CLI fallback")
                return mint_token(run_id, scenario_id, choice, "human:slack_cli", secret)
            print("  Please type APPROVE or REJECT.")
