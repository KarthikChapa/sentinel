"""
Prompt Registry — versioned prompt templates loaded from files.

Each prompt file has a metadata header:
  # prompt_version: actor_v1
  # role: Actor
  # output_format: json
  # ---
  <prompt text>

The prompt_version is recorded in every trace step's system_instructions.
"""

from __future__ import annotations

from pathlib import Path
from typing import Tuple

_PROMPTS_DIR = Path(__file__).parent


def load_prompt(name: str, version: str = "v1") -> Tuple[str, str]:
    """
    Load a prompt template by name and version.

    Returns (prompt_text, prompt_version).
    Example: load_prompt("actor", "v1") loads prompts/actor_v1.txt
    """
    filename = f"{name}_{version}.txt"
    filepath = _PROMPTS_DIR / filename
    if not filepath.exists():
        raise FileNotFoundError(f"Prompt not found: {filepath}")

    content = filepath.read_text(encoding="utf-8")

    # Extract version from header
    prompt_version = f"{name}_{version}"
    lines = content.split("\n")
    body_lines = []
    past_header = False
    for line in lines:
        if line.strip() == "# ---":
            past_header = True
            continue
        if not past_header:
            if line.startswith("# prompt_version:"):
                prompt_version = line.split(":", 1)[1].strip()
            continue
        body_lines.append(line)

    return "\n".join(body_lines).strip(), prompt_version


def list_prompts() -> list[str]:
    """List all available prompt files."""
    return sorted(f.stem for f in _PROMPTS_DIR.glob("*_v*.txt"))
