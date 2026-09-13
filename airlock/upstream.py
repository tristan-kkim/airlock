"""Client for the cloud model: Nebius Token Factory (OpenAI-compatible), Nemotron 3 Ultra.

If the primary model answers with a 5xx or reports itself unavailable, the request is retried
once on the fallback model. The fallback attempt changes `model` and drops `reasoning_effort`
(which the fallback rejects); every attempt is recorded as its own outbound payload in the audit.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx

from airlock.config import Settings


class UpstreamError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def serialize(payload: dict[str, Any]) -> bytes:
    """The exact bytes that leave the machine. The gate and audit see the same object."""
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


_MODEL_WORD = re.compile(r"model", re.IGNORECASE)
_UNAVAILABLE = re.compile(
    r"not found|unavailable|not available|does not exist|no such|not supported|not ready|"
    r"overloaded|disabled",
    re.IGNORECASE,
)


def should_fallback(status: int, body_text: str) -> bool:
    if status >= 500 or status == 404:
        return True
    return status in (400, 403, 422) and bool(
        _MODEL_WORD.search(body_text) and _UNAVAILABLE.search(body_text)
    )


@dataclass
class UpstreamResult:
    model_used: str
    fallback: bool
    data: dict[str, Any] | None = None  # non-streaming JSON body
    stream: httpx.Response | None = None  # open streaming response; caller must close it


class Upstream:
    def __init__(self, settings: Settings, client: httpx.AsyncClient):
        self.settings = settings
        self.client = client

    @property
    def configured(self) -> bool:
        return bool(self.settings.nebius_api_key)

    async def send(
        self,
        payload: dict[str, Any],
        on_send: Callable[[dict[str, Any]], None],
        *,
        stream: bool = False,
    ) -> UpstreamResult:
        """POST /chat/completions. `on_send` receives each exact payload right before it leaves."""
        if not self.settings.nebius_api_key:
            raise UpstreamError("NEBIUS_API_KEY is not set")
        models = [payload["model"]]
        fallback = self.settings.upstream_fallback_model
        if fallback and fallback != payload["model"]:
            models.append(fallback)

        for attempt, model in enumerate(models):
            body = {**payload, "model": model}
            if attempt > 0:
                # The fallback (Nemotron 3 Super) rejects every reasoning_effort value.
                body.pop("reasoning_effort", None)
            wire = serialize(body)
            on_send(json.loads(wire))
            request = self.client.build_request(
                "POST",
                f"{self.settings.upstream_base_url}/chat/completions",
                content=wire,
                headers={
                    "Authorization": f"Bearer {self.settings.nebius_api_key}",
                    "Content-Type": "application/json",
                    "Accept": "text/event-stream" if stream else "application/json",
                },
                timeout=self.settings.upstream_timeout_s,
            )
            try:
                resp = await self.client.send(request, stream=True)
            except httpx.HTTPError as exc:
                raise UpstreamError(f"upstream unreachable: {type(exc).__name__}") from exc

            if resp.status_code >= 400:
                text = (await resp.aread()).decode("utf-8", errors="replace")[:4000]
                await resp.aclose()
                if attempt + 1 < len(models) and should_fallback(resp.status_code, text):
                    continue
                raise UpstreamError(f"upstream returned HTTP {resp.status_code}", resp.status_code)

            if stream:
                return UpstreamResult(model, attempt > 0, stream=resp)
            try:
                await resp.aread()
                data = resp.json()
            except ValueError as exc:
                raise UpstreamError("upstream returned non-JSON body", resp.status_code) from exc
            finally:
                await resp.aclose()
            if not isinstance(data, dict):
                raise UpstreamError("upstream returned unexpected JSON", resp.status_code)
            return UpstreamResult(model, attempt > 0, data=data)
        raise UpstreamError("no upstream model available")  # pragma: no cover
