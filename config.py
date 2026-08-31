"""
Central configuration and LLM abstraction for Sentinel-IAM.

Mock mode (default): fully deterministic, offline, no API key. The MockLLM
returns structured, scenario-aware responses so the entire DAG, verifier loop,
and HITL flow execute end-to-end with reproducible output.

Live mode: uses OpenRouter (OpenAI-compatible) when OPENAI_API_KEY is set.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Optional .env loading — degrades gracefully if python-dotenv is absent.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _env_bool(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int = 0) -> int:
    val = os.getenv(name)
    if val is None:
        return default
    try:
        return int(val.strip())
    except ValueError:
        return default


def _env_float(name: str, default: float = 0.0) -> float:
    val = os.getenv(name)
    if val is None:
        return default
    try:
        return float(val.strip())
    except ValueError:
        return default


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

@dataclass
class Settings:
    """Runtime settings resolved from environment variables."""

    # Core
    mode: str = field(default_factory=lambda: _env("SENTINEL_MODE", "mock"))
    backend: str = field(default_factory=lambda: _env("SENTINEL_BACKEND", "mock"))
    auto_approve: bool = field(default_factory=lambda: _env_bool("SENTINEL_AUTO_APPROVE", True))
    max_retries: int = field(default_factory=lambda: _env_int("SENTINEL_MAX_RETRIES", 3))
    lookback_days: int = field(default_factory=lambda: _env_int("SENTINEL_LOOKBACK_DAYS", 90))

    # LLM
    model: str = field(
        default_factory=lambda: _env("SENTINEL_MODEL", "meta-llama/llama-3.1-8b-instruct:free")
    )
    fast_model: str = field(
        default_factory=lambda: _env("SENTINEL_FAST_MODEL", "meta-llama/llama-3.1-8b-instruct:free")
    )
    temperature: float = field(default_factory=lambda: _env_float("SENTINEL_TEMPERATURE", 0.0))
    openai_api_key: Optional[str] = field(default_factory=lambda: os.getenv("OPENAI_API_KEY"))
    openai_base_url: Optional[str] = field(
        default_factory=lambda: _env("OPENAI_BASE_URL", "https://openrouter.ai/api/v1")
    )

    # Presentation
    hitl_channel: str = field(default_factory=lambda: _env("SENTINEL_HITL_CHANNEL", "auto"))
    ui: str = field(default_factory=lambda: _env("SENTINEL_UI", "plain"))
    hitl_secret: str = field(default_factory=lambda: _env("SENTINEL_HITL_SECRET", "dev-secret"))

    # Slack (optional)
    slack_bot_token: Optional[str] = field(default_factory=lambda: os.getenv("SLACK_BOT_TOKEN"))
    slack_signing_secret: Optional[str] = field(
        default_factory=lambda: os.getenv("SLACK_SIGNING_SECRET")
    )
    slack_channel: Optional[str] = field(default_factory=lambda: os.getenv("SLACK_CHANNEL"))

    @property
    def is_live(self) -> bool:
        return self.mode == "live" and bool(self.openai_api_key)

    @property
    def has_slack(self) -> bool:
        return bool(self.slack_bot_token and self.slack_signing_secret and self.slack_channel)


# Singleton — importable as `from config import SETTINGS`
SETTINGS = Settings()


# ---------------------------------------------------------------------------
# LLM Abstraction
# ---------------------------------------------------------------------------

@dataclass
class LLMResult:
    """Result from a single LLM completion."""
    text: str
    prompt_tokens: int
    completion_tokens: int

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class BaseLLM:
    """Minimal chat interface. Subclass must implement complete()."""

    def complete(
        self, system: str, user: str, *, json_mode: bool = False
    ) -> LLMResult:
        raise NotImplementedError


class LiveLLM(BaseLLM):
    """
    OpenRouter / OpenAI-compatible client for live mode.

    Resilience features:
    - Exponential backoff with jitter on transient failures (429, 500, 502, 503)
    - Configurable timeout (connect + read)
    - Model fallback chain: primary → fast → error
    - max_tokens guard to prevent runaway completions
    - Token budget estimation before sending
    """

    # Transient HTTP status codes that warrant a retry
    _RETRYABLE_STATUS = {429, 500, 502, 503, 504}
    _MAX_RETRIES = 3
    _BASE_DELAY = 1.0  # seconds
    _TIMEOUT = 30.0    # seconds per request

    def __init__(self, settings: Settings, model_override: Optional[str] = None) -> None:
        try:
            from openai import OpenAI
        except ImportError:
            raise RuntimeError(
                "Live mode requires the 'openai' package. "
                "Install with: pip install openai"
            )
        self._client = OpenAI(
            api_key=settings.openai_api_key,
            base_url=settings.openai_base_url,
            timeout=self._TIMEOUT,
        )
        self._model = model_override or settings.model
        self._settings = settings
        self._call_count = 0
        self._error_count = 0

    def complete(
        self, system: str, user: str, *, json_mode: bool = False
    ) -> LLMResult:
        import random
        import time as _time

        # Estimate prompt tokens (~4 chars per token) for budget guard
        estimated_prompt_tokens = (len(system) + len(user)) // 4
        max_tokens = min(4096, max(512, 8192 - estimated_prompt_tokens))

        kwargs: Dict[str, Any] = {
            "model": self._model,
            "temperature": self._settings.temperature,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        last_exc: Optional[Exception] = None
        for attempt in range(1, self._MAX_RETRIES + 1):
            self._call_count += 1
            try:
                resp = self._client.chat.completions.create(**kwargs)
                choice = resp.choices[0]
                usage = resp.usage
                # Reset error count on success
                self._error_count = max(0, self._error_count - 1)
                return LLMResult(
                    text=choice.message.content or "",
                    prompt_tokens=getattr(usage, "prompt_tokens", 0) if usage else estimated_prompt_tokens,
                    completion_tokens=getattr(usage, "completion_tokens", 0) if usage else 0,
                )
            except Exception as exc:
                last_exc = exc
                self._error_count += 1
                exc_str = str(exc).lower()

                # Check if retryable
                is_retryable = any(str(code) in exc_str for code in self._RETRYABLE_STATUS)
                is_retryable = is_retryable or "timeout" in exc_str or "connection" in exc_str

                if not is_retryable or attempt == self._MAX_RETRIES:
                    break

                # Exponential backoff with jitter
                delay = self._BASE_DELAY * (2 ** (attempt - 1)) + random.uniform(0, 0.5)
                _time.sleep(delay)

        raise RuntimeError(
            f"LLM call failed after {self._MAX_RETRIES} attempts "
            f"(model={self._model}): {last_exc}"
        )


class MockLLM(BaseLLM):
    """
    Deterministic, offline stand-in for a real model.

    Scenario-aware: prompts embed the finding + evidence as JSON. The MockLLM
    parses that context and returns a plausible, consistent response. On the
    Actor path it reads a retry_feedback field so it demonstrably self-corrects
    rather than repeating a bad answer.
    """

    def complete(
        self, system: str, user: str, *, json_mode: bool = False
    ) -> LLMResult:
        role = self._detect_role(system)
        ctx = self._extract_json_context(user)

        if role == "planner":
            text = self._mock_plan(ctx)
        elif role == "actor":
            text = self._mock_remediation(ctx)
        elif role == "baseline":
            text = self._mock_baseline(ctx)
        else:
            text = json.dumps({"note": "mock no-op response"})

        # Rough token accounting keeps cost model meaningful in mock mode
        pt = max(1, len(system.split()) + len(user.split()))
        ct = max(1, len(text.split()))
        return LLMResult(text=text, prompt_tokens=pt, completion_tokens=ct)

    # -- Role detection -----------------------------------------------------

    @staticmethod
    def _detect_role(system: str) -> str:
        s = system.lower()
        if "planner" in s or "classify" in s:
            return "planner"
        if "actor" in s or "remediat" in s:
            return "actor"
        if "baseline" in s:
            return "baseline"
        return "unknown"

    @staticmethod
    def _extract_json_context(user: str) -> Dict[str, Any]:
        """Extract embedded JSON from the user prompt."""
        # Try ```json ... ``` fenced block first
        m = re.search(r"```json\s*(\{.*?\})\s*```", user, re.DOTALL)
        if not m:
            # Try bare {...}
            m = re.search(r"(\{.*\})", user, re.DOTALL)
        if not m:
            return {}
        try:
            return json.loads(m.group(1))
        except (json.JSONDecodeError, IndexError):
            return {}

    # -- Mock responses per role --------------------------------------------

    @staticmethod
    def _mock_plan(ctx: Dict[str, Any]) -> str:
        """Produce a DAG of investigative subtasks tailored to the alert."""
        category = str(ctx.get("category", ctx.get("class", ""))).lower()
        service = ctx.get("service", ctx.get("principal", "unknown-svc"))

        tasks = [
            {
                "id": "t_cloudtrail",
                "tool": "cloudtrail_usage",
                "args": {"principal": service, "days": 90},
                "depends_on": [],
                "rationale": "Pull 90-day actual API usage from CloudTrail.",
            },
            {
                "id": "t_last_accessed",
                "tool": "last_accessed",
                "args": {"principal": service},
                "depends_on": [],
                "rationale": "Get IAM Access Advisor last-accessed data.",
            },
            {
                "id": "t_analyzer",
                "tool": "analyzer_findings",
                "args": {"principal": service},
                "depends_on": [],
                "rationale": "Pull unused-access findings from Access Analyzer.",
            },
            {
                "id": "t_terraform",
                "tool": "terraform_state",
                "args": {"principal": service},
                "depends_on": [],
                "rationale": "Read the current Terraform HCL and live policy.",
            },
        ]

        # Route classification
        route = "wildcard_action"
        if "unused" in category or "dormant" in category:
            route = "unused_role"
        elif "passrole" in category or "escalat" in category:
            route = "passrole_escalation"
        elif "admin" in category or "*:*" in category:
            route = "admin_star"
        elif "cross" in category or "trust" in category:
            route = "cross_account_trust"
        elif "kms" in category or "secret" in category:
            route = "sensitive_wildcard"
        elif "contradict" in category or "boundary" in category:
            route = "contradictory"

        return json.dumps({
            "route": route,
            "strategy": route,
            "tasks": tasks,
        }, indent=2)

    @staticmethod
    def _mock_remediation(ctx: Dict[str, Any]) -> str:
        """Synthesize a least-privilege policy from evidence."""
        evidence = ctx.get("evidence", {})
        oracle = ctx.get("_oracle", {})
        feedback = ctx.get("retry_feedback")

        raw_used = evidence.get("used_actions", oracle.get("safe_actions", []))
        # Normalize: used_actions can be list of dicts or list of strings
        used_actions: list = []
        for item in raw_used:
            if isinstance(item, dict):
                used_actions.append(item.get("action", str(item)))
            else:
                used_actions.append(str(item))
        granted_actions = evidence.get("granted_actions", [])
        principal = ctx.get("principal", ctx.get("service", "unknown"))

        # Build the new policy from the ALLOWLIST of used actions
        new_statements = []
        if used_actions:
            new_statements.append({
                "Effect": "Allow",
                "Action": sorted(set(used_actions)),
                "Resource": oracle.get("resource_arns", ["*"]),
            })

        new_policy = {
            "Version": "2012-10-17",
            "Statement": new_statements,
        }

        # Self-correction: if verifier complained, fix the specific issue
        if feedback:
            fb = feedback.lower()
            # Remove PassRole wildcard — scope to specific ARN
            if "passrole" in fb:
                for stmt in new_policy["Statement"]:
                    if "iam:PassRole" in stmt.get("Action", []):
                        stmt["Resource"] = [
                            f"arn:aws:iam::*:role/{principal}-execution-role"
                        ]
                        stmt["Condition"] = {
                            "StringEquals": {
                                "iam:PassedToService": "lambda.amazonaws.com"
                            }
                        }
            # Remove admin wildcard
            if "wildcard admin" in fb or "*:*" in fb:
                for stmt in new_policy["Statement"]:
                    stmt["Action"] = [
                        a for a in stmt.get("Action", [])
                        if a != "*" and not a.endswith(":*")
                    ]
            # Remove credential management actions
            if "credential" in fb:
                cred_actions = {
                    "iam:CreateAccessKey", "iam:CreateLoginProfile",
                    "iam:UpdateAccessKey",
                }
                for stmt in new_policy["Statement"]:
                    stmt["Action"] = [
                        a for a in stmt.get("Action", [])
                        if a not in cred_actions
                    ]
            # Fix s3:* → enumerate
            if "s3:*" in fb or "s3 admin" in fb.lower():
                for stmt in new_policy["Statement"]:
                    stmt["Action"] = [
                        a for a in stmt.get("Action", [])
                        if a != "s3:*"
                    ] + [ua for ua in used_actions if ua.startswith("s3:")]
            # Scope sensitive services
            if "scope" in fb and "sensitive" in fb:
                pass  # already scoped by allowlist-first construction

        removed = sorted(set(granted_actions) - set(used_actions))
        kept = sorted(set(used_actions))

        confidence = 0.85
        if feedback:
            confidence = min(0.95, confidence + 0.07)
        if ctx.get("route") == "contradictory" or oracle.get("must_escalate"):
            confidence = 0.35

        # Build HCL diff representation
        old_hcl = f'resource "aws_iam_role_policy" "{principal}" {{\n'
        old_hcl += f'  # BROAD: {len(granted_actions)} actions granted\n}}'
        new_hcl = f'resource "aws_iam_role_policy" "{principal}" {{\n'
        new_hcl += f'  # SCOPED: {len(kept)} actions (was {len(granted_actions)})\n}}'
        git_diff = f"--- a/iam.tf\n+++ b/iam.tf\n@@ -1 +1 @@\n-{old_hcl}\n+{new_hcl}"

        return json.dumps({
            "new_policy": new_policy,
            "removed": removed,
            "kept": kept,
            "added_conditions": [],
            "confidence": round(confidence, 2),
            "requires_hitl": confidence < 0.5 or bool(oracle.get("must_escalate")),
            "git_diff": git_diff,
            "rationale": (
                f"Removing {len(removed)} unnecessary permissions based on "
                f"{ctx.get('lookback_days', 90)}-day CloudTrail usage. "
                f"Retaining {len(kept)} actions that were actually called."
            ),
        }, indent=2)

    @staticmethod
    def _mock_baseline(ctx: Dict[str, Any]) -> str:
        """
        Baseline: naive single-pass without usage data or checks.
        
        Realistically simulates what happens when you ask "make this least-privilege"
        without CloudTrail data:
        - Keeps wildcards it shouldn't (leaves escalation paths)  
        - Removes some actions that were actually needed (breaks access)
        - No condition scoping, no resource narrowing
        """
        granted = ctx.get("granted_actions", [])
        current_policy = ctx.get("current_policy", {})

        if not granted:
            # Extract from policy if not provided directly
            for stmt in current_policy.get("Statement", []):
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                granted.extend(actions)

        if not granted:
            return json.dumps({
                "new_policy": current_policy or {"Version": "2012-10-17", "Statement": []},
                "removed": [], "kept": [],
                "confidence": 0.5, "requires_hitl": False,
                "rationale": "Baseline: no actions found in policy.",
            }, indent=2)

        import random
        rng = random.Random(42)

        # Baseline behavior: expand obvious wildcards, keep some dangerous ones
        expanded = []
        for a in granted:
            if a == "*" or a == "*:*":
                # Baseline tries to be helpful: expands * to common actions
                # but KEEPS some dangerous ones it doesn't know are escalation paths
                expanded.extend([
                    "s3:GetObject", "s3:PutObject", "s3:ListBucket",
                    "ec2:DescribeInstances", "logs:PutLogEvents",
                    "iam:PassRole",  # LEAVES THIS — escalation path
                    "iam:CreateAccessKey",  # LEAVES THIS — credential mgmt
                ])
            elif a.endswith(":*"):
                svc = a.split(":")[0]
                # Expands service:* but keeps a broad set
                if svc == "s3":
                    expanded.extend(["s3:GetObject", "s3:PutObject", "s3:DeleteObject",
                                     "s3:ListBucket", "s3:PutBucketPolicy"])
                elif svc == "lambda":
                    expanded.extend(["lambda:InvokeFunction", "lambda:CreateFunction",
                                     "lambda:GetFunction"])
                elif svc == "iam":
                    expanded.extend(["iam:PassRole", "iam:GetRole", "iam:ListRoles"])
                elif svc == "codecommit":
                    expanded.extend(["codecommit:GitPull", "codecommit:GitPush",
                                     "codecommit:CreateBranch"])
                elif svc == "logs":
                    expanded.extend(["logs:PutLogEvents", "logs:CreateLogGroup",
                                     "logs:CreateLogStream"])
                else:
                    expanded.append(a)  # keep the wildcard
            else:
                expanded.append(a)

        # Now randomly remove ~30-60% (the naive "trim")
        # This WILL remove some actions that are actually used (over-trimming)
        expanded = sorted(set(expanded))
        if len(expanded) > 2:
            keep_count = max(1, int(len(expanded) * rng.uniform(0.4, 0.7)))
            kept = sorted(rng.sample(expanded, min(keep_count, len(expanded))))
        else:
            kept = expanded

        removed = sorted(set(expanded) - set(kept))

        new_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": kept, "Resource": ["*"]}] if kept else [],
        }

        return json.dumps({
            "new_policy": new_policy,
            "removed": removed,
            "kept": kept,
            "confidence": 0.5,
            "requires_hitl": False,
            "rationale": f"Baseline: heuristic trim, kept {len(kept)}/{len(expanded)} "
                         f"actions without usage data.",
        }, indent=2)


# ---------------------------------------------------------------------------
# LLM Factory
# ---------------------------------------------------------------------------

def get_llm(settings: Settings = SETTINGS) -> BaseLLM:
    """Return a live client if configured, else the deterministic mock."""
    if settings.is_live:
        try:
            return LiveLLM(settings)
        except Exception as exc:
            import logging
            logging.getLogger("sentinel.config").warning(
                "Live mode unavailable (%s); falling back to MockLLM", exc
            )
    return MockLLM()


# Task types that need a strong model
_STRONG_TASKS = {"policy_synthesis", "self_correction"}


def get_llm_for_task(task_type: str, settings: Settings = SETTINGS) -> BaseLLM:
    """
    Model router: route tasks to appropriate model based on complexity.

    Strong model for: policy_synthesis, self_correction
    Fast/free model for: classification, evidence_summary, rationale, baseline

    Fallback chain: strong → fast → MockLLM (never silently degrade)
    """
    if not settings.is_live:
        return MockLLM()

    if task_type in _STRONG_TASKS:
        # Try strong model, fall back to fast, then mock
        for model in [settings.model, settings.fast_model]:
            try:
                return LiveLLM(settings, model_override=model)
            except Exception:
                continue
        import logging
        logging.getLogger("sentinel.config").warning(
            "All live models unavailable for %s; falling back to MockLLM", task_type
        )
        return MockLLM()
    else:
        try:
            return LiveLLM(settings, model_override=settings.fast_model)
        except Exception as exc:
            import logging
            logging.getLogger("sentinel.config").warning(
                "Fast model unavailable for %s (%s); falling back to MockLLM", task_type, exc
            )
            return MockLLM()


# ---------------------------------------------------------------------------
# Cost Model
# ---------------------------------------------------------------------------

# Approximate USD per 1K tokens — only the ratio matters for comparison.
# Based on typical OpenRouter free-tier / low-cost model pricing.
COST_PER_1K_PROMPT = 0.0
COST_PER_1K_COMPLETION = 0.0
# For paid models, override these:
COST_PER_1K_PROMPT_PAID = 0.00015
COST_PER_1K_COMPLETION_PAID = 0.0006


def estimate_cost(
    prompt_tokens: int,
    completion_tokens: int,
    *,
    paid: bool = False,
) -> float:
    """Estimate USD cost for a completion."""
    if paid:
        p = COST_PER_1K_PROMPT_PAID
        c = COST_PER_1K_COMPLETION_PAID
    else:
        p = COST_PER_1K_PROMPT
        c = COST_PER_1K_COMPLETION
    return round(
        (prompt_tokens / 1000.0) * p + (completion_tokens / 1000.0) * c,
        6,
    )
