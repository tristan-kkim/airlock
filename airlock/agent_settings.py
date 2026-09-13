"""Agent-mode settings, read from the environment (after `load_settings` has loaded `.env`).

Kept apart from `Settings` so agent mode can evolve without touching the core configuration.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Literal

JudgeMode = Literal["nano", "safety", "both"]
JUDGE_MODES: tuple[str, ...] = ("nano", "safety", "both")

DEFAULT_SAFETY_BASE_URL = "http://127.0.0.1:8086/v1"
DEFAULT_SAFETY_MODEL = "nemotron-3.5-content-safety"


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class AgentSettings:
    max_steps: int = 8
    # reasoning_effort for the planning model; "none" keeps turns fast and tool calls reliable.
    reasoning_effort: str | None = "none"
    max_tokens: int = 2000
    search_max_results: int = 5
    # Intent judge for rewritten search queries.
    search_judge: JudgeMode = "nano"
    safety_base_url: str = DEFAULT_SAFETY_BASE_URL
    safety_model: str = DEFAULT_SAFETY_MODEL
    safety_timeout_s: float = 20.0
    # Evaluation only: allows `guard=False` runs that send raw documents and queries.
    allow_unguarded: bool = False

    def with_overrides(self, **kwargs: object) -> AgentSettings:
        return replace(self, **kwargs)  # type: ignore[arg-type]


def load_agent_settings(env: Mapping[str, str] | None = None) -> AgentSettings:
    env = os.environ if env is None else env
    judge = (env.get("AIRLOCK_SEARCH_JUDGE") or "nano").strip().lower()
    if judge not in JUDGE_MODES:
        raise ValueError(f"AIRLOCK_SEARCH_JUDGE must be nano|safety|both, got {judge!r}")
    try:
        max_steps = int(env.get("AIRLOCK_AGENT_MAX_STEPS") or 8)
    except ValueError as exc:
        raise ValueError("AIRLOCK_AGENT_MAX_STEPS must be an integer") from exc
    effort = env.get("AIRLOCK_AGENT_REASONING_EFFORT")
    return AgentSettings(
        max_steps=max(1, min(max_steps, 16)),
        reasoning_effort=(effort.strip() or None) if effort is not None else "none",
        search_judge=judge,  # type: ignore[arg-type]
        safety_base_url=(env.get("AIRLOCK_SAFETY_BASE_URL") or DEFAULT_SAFETY_BASE_URL).rstrip("/"),
        safety_model=env.get("AIRLOCK_SAFETY_MODEL") or DEFAULT_SAFETY_MODEL,
        allow_unguarded=_truthy(env.get("AIRLOCK_ALLOW_UNGUARDED")),
    )
