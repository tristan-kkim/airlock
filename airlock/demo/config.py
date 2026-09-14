"""Demo-mode settings, read from the environment after `load_settings` has loaded `.env`."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Literal

DetectorBackend = Literal["local", "cloud"]

# Token Factory model for the cloud detector backend: cheap ($0.06/$0.24 per 1M tokens, catalog of
# 2026-09-14) and an NVIDIA open model, like the on-device Nemotron-3-Nano-4B it stands in for.
DEFAULT_CLOUD_DETECTOR_MODEL = "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
README_QUICKSTART_URL = "https://github.com/tristan-kkim/airlock#quickstart"


class DemoConfigError(ValueError):
    pass


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _int(env: Mapping[str, str], name: str, default: int, low: int = 0) -> int:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise DemoConfigError(f"{name} must be an integer, got {raw!r}") from exc
    if value < low:
        raise DemoConfigError(f"{name} must be >= {low}, got {value}")
    return value


def demo_enabled(env: Mapping[str, str] | None = None) -> bool:
    return _truthy((os.environ if env is None else env).get("AIRLOCK_DEMO"))


def is_loopback(host: str) -> bool:
    return host.strip().strip("[]").lower() in LOOPBACK_HOSTS


def resolve_allowed_hosts(env: Mapping[str, str] | None = None) -> tuple[str, ...]:
    """Host headers the server answers to.

    Local mode only ever answers to loopback names, whatever AIRLOCK_ALLOWED_HOSTS says: a
    non-loopback name or `*` there would expose the vault and audit API to DNS rebinding or the
    network. Demo mode (`AIRLOCK_DEMO=1`) honors the list as written, so a public hostname works.
    """
    env = os.environ if env is None else env
    raw = env.get("AIRLOCK_ALLOWED_HOSTS") or ",".join(LOOPBACK_HOSTS)
    hosts = tuple(h.strip() for h in raw.split(",") if h.strip())
    if demo_enabled(env):
        return hosts or LOOPBACK_HOSTS
    return tuple(h for h in hosts if is_loopback(h)) or LOOPBACK_HOSTS


def ignored_hosts(env: Mapping[str, str] | None = None) -> list[str]:
    """Entries of AIRLOCK_ALLOWED_HOSTS that local mode drops (for a startup warning)."""
    env = os.environ if env is None else env
    raw = env.get("AIRLOCK_ALLOWED_HOSTS") or ""
    kept = set(resolve_allowed_hosts(env))
    return [h.strip() for h in raw.split(",") if h.strip() and h.strip() not in kept]


@dataclass(frozen=True)
class DemoSettings:
    enabled: bool = False
    detector_backend: DetectorBackend = "local"
    cloud_detector_model: str = DEFAULT_CLOUD_DETECTOR_MODEL

    # Abuse and cost guards. "Costly" = any request that can reach Token Factory or Tavily.
    ip_limit: int = 20
    session_limit: int = 20
    window_s: int = 600
    # All requests (pages, audit views) per IP in the same window: a floor against hammering.
    ip_request_limit: int = 300
    max_input_chars: int = 4000
    max_body_bytes: int = 64_000
    max_tokens: int = 1024
    agent_max_steps: int = 6
    max_concurrent: int = 8
    # Global per-UTC-day budget. 0 disables that counter.
    daily_requests: int = 400
    daily_cloud_calls: int = 3000

    # Sessions: in-memory vault and audit, dropped after idle TTL.
    session_ttl_s: int = 1800
    max_sessions: int = 300

    # Presets: auto = live while the budget lasts, recorded after; recorded = never call out.
    presets: Literal["auto", "recorded"] = "auto"
    # Client IP from X-Forwarded-For, counting this many trusted proxies from the right.
    trusted_proxy_hops: int = 0
    # Or from a header the platform proxy sets itself (e.g. Fly-Client-IP). Takes precedence.
    client_ip_header: str = ""
    # Shown in the banner and runbook smoke test; empty until the URL exists.
    public_url: str = ""
    quickstart_url: str = README_QUICKSTART_URL

    def with_overrides(self, **kwargs: object) -> DemoSettings:
        return replace(self, **kwargs)  # type: ignore[arg-type]

    @property
    def detector_label(self) -> str:
        if self.detector_backend == "cloud":
            return f"Token Factory {self.cloud_detector_model} (cloud, demo only)"
        return "llama.cpp sidecar in this container (Nemotron-3-Nano-4B)"


def load_demo_settings(env: Mapping[str, str] | None = None) -> DemoSettings:
    env = os.environ if env is None else env
    enabled = demo_enabled(env)
    backend = (env.get("AIRLOCK_DETECTOR_BACKEND") or "local").strip().lower()
    if backend not in ("local", "cloud"):
        raise DemoConfigError(f"AIRLOCK_DETECTOR_BACKEND must be local|cloud, got {backend!r}")
    if backend == "cloud" and not enabled:
        # A cloud detector sends the raw text to a provider before redaction. That is acceptable
        # only for fictional demo inputs, never for real use.
        raise DemoConfigError("AIRLOCK_DETECTOR_BACKEND=cloud requires AIRLOCK_DEMO=1")
    presets = (env.get("AIRLOCK_DEMO_PRESETS") or "auto").strip().lower()
    if presets not in ("auto", "recorded"):
        raise DemoConfigError(f"AIRLOCK_DEMO_PRESETS must be auto|recorded, got {presets!r}")
    return DemoSettings(
        enabled=enabled,
        detector_backend=backend,  # type: ignore[arg-type]
        cloud_detector_model=env.get("AIRLOCK_CLOUD_DETECTOR_MODEL")
        or DEFAULT_CLOUD_DETECTOR_MODEL,
        ip_limit=_int(env, "AIRLOCK_DEMO_IP_LIMIT", 20, 1),
        session_limit=_int(env, "AIRLOCK_DEMO_SESSION_LIMIT", 20, 1),
        window_s=_int(env, "AIRLOCK_DEMO_WINDOW_S", 600, 1),
        ip_request_limit=_int(env, "AIRLOCK_DEMO_IP_REQUEST_LIMIT", 300, 1),
        max_input_chars=_int(env, "AIRLOCK_DEMO_MAX_INPUT_CHARS", 4000, 1),
        max_body_bytes=_int(env, "AIRLOCK_DEMO_MAX_BODY_BYTES", 64_000, 256),
        max_tokens=_int(env, "AIRLOCK_DEMO_MAX_TOKENS", 1024, 16),
        agent_max_steps=_int(env, "AIRLOCK_DEMO_AGENT_MAX_STEPS", 6, 1),
        max_concurrent=_int(env, "AIRLOCK_DEMO_MAX_CONCURRENT", 8, 1),
        daily_requests=_int(env, "AIRLOCK_DEMO_DAILY_REQUESTS", 400),
        daily_cloud_calls=_int(env, "AIRLOCK_DEMO_DAILY_CLOUD_CALLS", 3000),
        session_ttl_s=_int(env, "AIRLOCK_DEMO_SESSION_TTL_S", 1800, 60),
        max_sessions=_int(env, "AIRLOCK_DEMO_MAX_SESSIONS", 300, 1),
        presets=presets,  # type: ignore[arg-type]
        trusted_proxy_hops=_int(env, "AIRLOCK_DEMO_TRUSTED_PROXY_HOPS", 0),
        client_ip_header=(env.get("AIRLOCK_DEMO_CLIENT_IP_HEADER") or "").strip().lower(),
        public_url=(env.get("AIRLOCK_DEMO_PUBLIC_URL") or "").strip(),
    )
