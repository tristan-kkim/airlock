"""Runtime configuration, loaded from environment variables (and `.env`)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path

from dotenv import load_dotenv


class ProtectionLevel(StrEnum):
    STRICT = "strict"
    BALANCED = "balanced"
    MINIMAL = "minimal"


class ReviewMode(StrEnum):
    """When Airlock stops and asks the client to confirm proposed redactions (HTTP 409)."""

    ALWAYS = "always"
    UNCERTAIN = "uncertain"  # only when LLM-only spans, discarded spans or semantic cues exist
    NEVER = "never"


DEFAULT_LOCAL_BASE_URL = "http://127.0.0.1:8081/v1"
DEFAULT_LOCAL_MODEL = "nemotron-3-nano-4b"
# Nebius Token Factory, OpenAI-compatible. Auth: `Authorization: Bearer $NEBIUS_API_KEY`.
DEFAULT_UPSTREAM_BASE_URL = "https://api.tokenfactory.nebius.com/v1"
DEFAULT_UPSTREAM_MODEL = "nvidia/Nemotron-3-Ultra-550b-a55b"
# Used once when the primary model returns 5xx or reports itself unavailable.
DEFAULT_UPSTREAM_FALLBACK_MODEL = "nvidia/nemotron-3-super-120b-a12b"
DEFAULT_TAVILY_BASE_URL = "https://api.tavily.com"
# NVIDIA GLiNER-PII (optional second span proposer): a local directory or a cached Hub id.
DEFAULT_GLINER_MODEL = "nvidia/gliner-PII"
DEFAULT_GLINER_THRESHOLD = 0.4


def _bool(value: str | None, default: bool) -> bool:
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _float(value: str | None, default: float) -> float:
    try:
        return float(value) if value not in (None, "") else default
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    local_base_url: str = DEFAULT_LOCAL_BASE_URL
    local_model: str = DEFAULT_LOCAL_MODEL
    local_api_key: str | None = None
    local_disable_thinking: bool = True
    local_timeout_s: float = 30.0
    # Sampling for the local detector, per the local-model spike (temp 0 hit repetition loops).
    local_temperature: float = 0.6
    local_top_p: float = 0.95

    nebius_api_key: str | None = None
    upstream_base_url: str = DEFAULT_UPSTREAM_BASE_URL
    upstream_model: str = DEFAULT_UPSTREAM_MODEL
    upstream_fallback_model: str | None = DEFAULT_UPSTREAM_FALLBACK_MODEL
    upstream_timeout_s: float = 120.0

    tavily_api_key: str | None = None
    tavily_base_url: str = DEFAULT_TAVILY_BASE_URL

    vault_path: str = "./.airlock/vault.sqlite3"
    audit_db: str = "./.airlock/audit.sqlite3"
    # HMAC key for audit hashes. If unset, a random key is created once at audit_hash_key_file.
    audit_hash_key: str | None = None
    audit_hash_key_file: str = "./.airlock/audit_hash.key"

    protection_level: ProtectionLevel = ProtectionLevel.BALANCED
    review_mode: ReviewMode = ReviewMode.NEVER
    review_ttl_s: float = 600.0
    canaries: tuple[str, ...] = field(default_factory=tuple)

    # GLiNER ensemble (airlock.detect.gliner). Off by default; needs `uv sync --extra gliner`.
    gliner: bool = False
    gliner_model: str = DEFAULT_GLINER_MODEL
    # cpu: GLiNER on Metal competes with the local model; see airlock.detect.gliner.pick_device.
    gliner_device: str = "cpu"  # cpu | mps | cuda | auto
    gliner_threshold: float = DEFAULT_GLINER_THRESHOLD
    gliner_thresholds: str = ""  # per-label overrides: "first_name=0.6,password=0.8"
    gliner_adjudicate: bool = True  # ask the local model about GLiNER-only spans

    host: str = "127.0.0.1"
    port: int = 8787
    # Host headers the server answers to (DNS-rebinding protection). "*" disables the check.
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "::1")

    def with_overrides(self, **kwargs: object) -> Settings:
        return replace(self, **kwargs)  # type: ignore[arg-type]


def load_settings(env_file: str | Path | None = ".env") -> Settings:
    """Build settings from the process environment. `.env` never overrides real env vars."""
    if env_file is not None and Path(env_file).is_file():
        load_dotenv(env_file, override=False)
    env = os.environ

    level_raw = (env.get("AIRLOCK_PROTECTION_LEVEL") or "balanced").strip().lower()
    try:
        level = ProtectionLevel(level_raw)
    except ValueError as exc:
        raise ValueError(
            f"AIRLOCK_PROTECTION_LEVEL must be strict|balanced|minimal, got {level_raw!r}"
        ) from exc

    review_raw = (env.get("AIRLOCK_REVIEW") or "never").strip().lower()
    try:
        review = ReviewMode(review_raw)
    except ValueError as exc:
        raise ValueError(
            f"AIRLOCK_REVIEW must be always|uncertain|never, got {review_raw!r}"
        ) from exc

    canaries = tuple(c.strip() for c in (env.get("AIRLOCK_CANARIES") or "").split(",") if c.strip())

    return Settings(
        local_base_url=(env.get("AIRLOCK_LOCAL_BASE_URL") or DEFAULT_LOCAL_BASE_URL).rstrip("/"),
        local_model=env.get("AIRLOCK_LOCAL_MODEL") or DEFAULT_LOCAL_MODEL,
        local_api_key=env.get("AIRLOCK_LOCAL_API_KEY") or None,
        local_disable_thinking=_bool(env.get("AIRLOCK_LOCAL_DISABLE_THINKING"), True),
        local_timeout_s=_float(env.get("AIRLOCK_LOCAL_TIMEOUT_S"), 30.0),
        local_temperature=_float(env.get("AIRLOCK_LOCAL_TEMPERATURE"), 0.6),
        local_top_p=_float(env.get("AIRLOCK_LOCAL_TOP_P"), 0.95),
        nebius_api_key=env.get("NEBIUS_API_KEY") or None,
        upstream_base_url=(
            env.get("AIRLOCK_UPSTREAM_BASE_URL") or DEFAULT_UPSTREAM_BASE_URL
        ).rstrip("/"),
        upstream_model=env.get("AIRLOCK_UPSTREAM_MODEL") or DEFAULT_UPSTREAM_MODEL,
        # Set AIRLOCK_UPSTREAM_FALLBACK_MODEL to an empty string to disable the fallback.
        upstream_fallback_model=(
            env["AIRLOCK_UPSTREAM_FALLBACK_MODEL"] or None
            if "AIRLOCK_UPSTREAM_FALLBACK_MODEL" in env
            else DEFAULT_UPSTREAM_FALLBACK_MODEL
        ),
        upstream_timeout_s=_float(env.get("AIRLOCK_UPSTREAM_TIMEOUT_S"), 120.0),
        tavily_api_key=env.get("TAVILY_API_KEY") or None,
        tavily_base_url=(env.get("AIRLOCK_TAVILY_BASE_URL") or DEFAULT_TAVILY_BASE_URL).rstrip("/"),
        vault_path=env.get("AIRLOCK_VAULT_PATH") or "./.airlock/vault.sqlite3",
        audit_db=env.get("AIRLOCK_AUDIT_DB") or "./.airlock/audit.sqlite3",
        audit_hash_key=env.get("AIRLOCK_AUDIT_HASH_KEY") or None,
        audit_hash_key_file=env.get("AIRLOCK_AUDIT_HASH_KEY_FILE") or "./.airlock/audit_hash.key",
        protection_level=level,
        review_mode=review,
        canaries=canaries,
        gliner=_bool(env.get("AIRLOCK_GLINER"), False),
        gliner_model=(
            env.get("AIRLOCK_GLINER_MODEL") or env.get("GLINER_PII_MODEL") or DEFAULT_GLINER_MODEL
        ),
        gliner_device=(env.get("AIRLOCK_GLINER_DEVICE") or "cpu").strip().lower(),
        gliner_threshold=_float(env.get("AIRLOCK_GLINER_THRESHOLD"), DEFAULT_GLINER_THRESHOLD),
        gliner_thresholds=env.get("AIRLOCK_GLINER_THRESHOLDS") or "",
        gliner_adjudicate=_bool(env.get("AIRLOCK_GLINER_ADJUDICATE"), True),
        host=env.get("AIRLOCK_HOST") or "127.0.0.1",
        port=int(env.get("AIRLOCK_PORT") or 8787),
        allowed_hosts=tuple(
            h.strip()
            for h in (env.get("AIRLOCK_ALLOWED_HOSTS") or "127.0.0.1,localhost,::1").split(",")
            if h.strip()
        ),
    )
