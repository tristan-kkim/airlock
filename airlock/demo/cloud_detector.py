"""Cloud detector backend for the hosted demo ONLY (`AIRLOCK_DETECTOR_BACKEND=cloud`).

Airlock's privacy claim rests on the detector running on the user's machine. A hosted demo has no
user machine, so it has two honest options:

  (a) `local`: llama.cpp `llama-server` with Nemotron-3-Nano-4B as a sidecar in the same
      container (Dockerfile target `sidecar`). Detection stays inside the demo server.
  (b) `cloud`: this adapter. Detection calls NVIDIA Nemotron-3-Nano-30B-A3B on Nebius Token
      Factory. The raw input reaches a cloud model before redaction, which is acceptable only
      because demo inputs are fictional presets plus user text under a visible warning.
      `load_demo_settings` refuses this backend unless AIRLOCK_DEMO=1.

The adapter plugs into the existing `LocalModel` interface (`chat_json`, `ping`): the detector,
search rewriter, re-ranker, entailment check and agent intent judge all use it unchanged. Nothing
in `airlock.detect` knows it exists. The gate, vault and fail-closed behavior are identical; a
Token Factory error is a detector failure and blocks the request.
"""

from __future__ import annotations

from typing import Any

import httpx

from airlock.config import Settings
from airlock.demo.config import DEFAULT_CLOUD_DETECTOR_MODEL
from airlock.detect.llm import LocalModel, LocalModelUnavailable


class CloudDetectorNotConfigured(LocalModelUnavailable):
    """No NEBIUS_API_KEY: the cloud detector cannot run, so requests fail closed."""


class CloudDetectorRateLimited(LocalModelUnavailable):
    """Token Factory answered 429."""


class CloudDetectorOutOfCredit(LocalModelUnavailable):
    """Token Factory answered 402 (the account ran out of credit)."""


# Detector calls are short JSON answers (about 2 s), but Token Factory latency varies: the first
# container smoke test (2026-09-14) saw 13-27 s calls, and a 30 s timeout failed two presets closed.
CLOUD_TIMEOUT_S = 60.0


def cloud_detector_settings(
    settings: Settings, model: str = DEFAULT_CLOUD_DETECTOR_MODEL
) -> Settings:
    """The same Settings with the `local_*` detector fields pointed at Token Factory.

    Components that build their own `LocalModel` from settings (the agent's search intent judge)
    follow automatically. Upstream (Nemotron 3 Ultra) and Tavily settings are unchanged.
    """
    return settings.with_overrides(
        local_base_url=settings.upstream_base_url.rstrip("/"),
        local_api_key=settings.nebius_api_key,
        local_model=model,
        # vLLM on Token Factory honors chat_template_kwargs.enable_thinking=false for Nemotron.
        local_disable_thinking=True,
        local_timeout_s=max(settings.local_timeout_s, CLOUD_TIMEOUT_S),
    )


class CloudDetectorModel(LocalModel):
    """`LocalModel` whose server is Token Factory. Construct with already-remapped settings."""

    backend = "cloud"

    def __init__(self, settings: Settings, client: httpx.AsyncClient):
        super().__init__(settings, client)

    @classmethod
    def factory(cls, model: str = DEFAULT_CLOUD_DETECTOR_MODEL):
        """A `local_factory` for `airlock.server.build_services` / `create_app`."""

        def build(settings: Settings, client: httpx.AsyncClient) -> CloudDetectorModel:
            return cls(cloud_detector_settings(settings, model), client)

        return build

    async def chat_json(self, *args: Any, **kwargs: Any) -> Any:
        if not self.settings.local_api_key:
            raise CloudDetectorNotConfigured("NEBIUS_API_KEY is not set")
        try:
            return await super().chat_json(*args, **kwargs)
        except LocalModelUnavailable as exc:
            status = str(exc)
            if status == "HTTP 429":
                raise CloudDetectorRateLimited(status) from exc
            if status == "HTTP 402":
                raise CloudDetectorOutOfCredit(status) from exc
            raise

    async def ping(self) -> dict[str, Any]:
        resp = await self.client.get(
            f"{self.settings.local_base_url}/models",
            headers={"Authorization": f"Bearer {self.settings.local_api_key or ''}"},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()
