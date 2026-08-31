"""
Structured logging for Sentinel-IAM.

Provides JSON-formatted log output with correlation IDs (run_id, scenario_id)
threaded through every log line. Replaces bare print() calls.

Usage:
    from agent_system.log import get_logger
    log = get_logger("sentinel.orchestrator")
    log.info("Pipeline started", extra={"run_id": rid, "scenario_id": sid})
"""

from __future__ import annotations

import json
import logging
import sys
import threading
from typing import Any, Optional

# Thread-local storage for correlation IDs
_context = threading.local()


def set_correlation(run_id: str = "", scenario_id: str = "") -> None:
    """Set correlation IDs for the current thread."""
    _context.run_id = run_id
    _context.scenario_id = scenario_id


def get_correlation() -> dict:
    """Get current correlation IDs."""
    return {
        "run_id": getattr(_context, "run_id", ""),
        "scenario_id": getattr(_context, "scenario_id", ""),
    }


class StructuredFormatter(logging.Formatter):
    """JSON log formatter with correlation IDs and structured fields."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }

        # Add correlation IDs from thread-local context
        ctx = get_correlation()
        if ctx["run_id"]:
            entry["run_id"] = ctx["run_id"]
        if ctx["scenario_id"]:
            entry["scenario_id"] = ctx["scenario_id"]

        # Add any extra fields passed via extra={}
        for key in ("run_id", "scenario_id", "agent", "tool", "model",
                     "tokens", "latency_ms", "error", "detail", "attempt"):
            val = getattr(record, key, None)
            if val is not None:
                entry[key] = val

        return json.dumps(entry, default=str)


class HumanFormatter(logging.Formatter):
    """Human-readable formatter for terminal output."""

    LEVEL_COLORS = {
        "DEBUG": "\033[36m",    # cyan
        "INFO": "\033[32m",     # green
        "WARNING": "\033[33m",  # yellow
        "ERROR": "\033[31m",    # red
        "CRITICAL": "\033[35m", # magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.LEVEL_COLORS.get(record.levelname, "")
        ctx = get_correlation()
        prefix = ""
        if ctx.get("scenario_id"):
            prefix = f"[{ctx['scenario_id']}] "
        return f"{color}[{record.name}]{self.RESET} {prefix}{record.getMessage()}"


def get_logger(name: str) -> logging.Logger:
    """Get or create a named logger with structured output."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        # Use human-readable format for terminal, JSON for production
        import os
        if os.getenv("SENTINEL_LOG_FORMAT", "human") == "json":
            handler.setFormatter(StructuredFormatter())
        else:
            handler.setFormatter(HumanFormatter())

        logger.addHandler(handler)
        logger.setLevel(
            getattr(logging, os.getenv("SENTINEL_LOG_LEVEL", "INFO").upper(), logging.INFO)
        )
        logger.propagate = False

    return logger
