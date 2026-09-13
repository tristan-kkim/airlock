"""Local model client and LLM span detector (NVIDIA Nemotron-3-Nano-4B on a local server).

The local model only *proposes* spans. It never decides whether a request may leave the machine;
that is the job of `airlock.gate`. If the local model cannot be reached or keeps returning
unusable output, callers must fail closed.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from collections import OrderedDict
from importlib import resources
from typing import Any

import httpx

from airlock.config import ProtectionLevel, Settings
from airlock.detect.spans import MIN_SPAN_CHARS, SPAN_TYPES, Span, contains_placeholder, find_term


class LocalModelError(Exception):
    """Base class: the local model could not produce a usable answer."""


class LocalModelUnavailable(LocalModelError):
    """Connection failure, timeout, or non-2xx status from the local server."""


class LocalModelBadOutput(LocalModelError):
    """The local server answered but not with JSON matching the schema."""


def load_prompt(name: str) -> str:
    return resources.files("airlock.prompts").joinpath(name).read_text(encoding="utf-8")


DETECTOR_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "spans": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                    "type": {"type": "string", "enum": list(SPAN_TYPES)},
                    "action": {"type": "string", "enum": ["mask", "generalize"]},
                    "replacement": {"type": "string"},
                },
                "required": ["text", "type", "action", "replacement"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["spans"],
    "additionalProperties": False,
}

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)


def extract_json(content: str) -> Any:
    """Parse a JSON object from model output, tolerating think blocks and code fences."""
    text = _THINK_RE.sub("", content or "").strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                pass
    raise LocalModelBadOutput("local model output is not valid JSON")


class LocalModel:
    """Minimal OpenAI-compatible client for the on-device model."""

    def __init__(self, settings: Settings, client: httpx.AsyncClient):
        self.settings = settings
        self.client = client

    async def chat_json(
        self,
        system: str,
        user: str,
        schema: dict[str, Any],
        schema_name: str,
        *,
        max_tokens: int = 1024,
        retries: int = 1,
    ) -> Any:
        body: dict[str, Any] = {
            "model": self.settings.local_model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": 0,
            "max_tokens": max_tokens,
            "stream": False,
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": schema_name, "strict": True, "schema": schema},
            },
        }
        if self.settings.local_disable_thinking:
            body["chat_template_kwargs"] = {"enable_thinking": False}
        headers = {}
        if self.settings.local_api_key:
            headers["Authorization"] = f"Bearer {self.settings.local_api_key}"

        last_error: LocalModelError | None = None
        for _ in range(retries + 1):
            try:
                resp = await self.client.post(
                    f"{self.settings.local_base_url}/chat/completions",
                    json=body,
                    headers=headers,
                    timeout=self.settings.local_timeout_s,
                )
            except httpx.HTTPError as exc:
                raise LocalModelUnavailable(f"{type(exc).__name__}") from exc
            if resp.status_code >= 400:
                raise LocalModelUnavailable(f"HTTP {resp.status_code}")
            try:
                content = resp.json()["choices"][0]["message"]["content"]
                return extract_json(content)
            except LocalModelBadOutput as exc:
                last_error = exc
            except (KeyError, IndexError, TypeError, ValueError) as exc:
                last_error = LocalModelBadOutput(f"unexpected response shape: {type(exc).__name__}")
        assert last_error is not None
        raise last_error

    async def ping(self) -> dict[str, Any]:
        resp = await self.client.get(f"{self.settings.local_base_url}/models", timeout=5)
        resp.raise_for_status()
        return resp.json()


_LEVEL_GUIDANCE = {
    ProtectionLevel.STRICT: (
        "STRICT: flag aggressively. Include every quasi-identifier (ages, dates, job titles, "
        "schools, neighbourhoods, rare conditions, unusual events) even when it seems harmless."
    ),
    ProtectionLevel.BALANCED: (
        "BALANCED: flag direct identifiers and secrets, plus quasi-identifiers that could "
        "narrow the person down when combined."
    ),
    ProtectionLevel.MINIMAL: (
        "MINIMAL: focus on direct identifiers, contact details, ID numbers, financial data, "
        "secrets and health information."
    ),
}


def chunk_text(text: str, max_chars: int = 4000) -> list[str]:
    """Split on paragraph/line boundaries so each detector call stays small."""
    if len(text) <= max_chars:
        return [text]
    chunks: list[str] = []
    current = ""
    for piece in re.split(r"(\n+)", text):
        if len(current) + len(piece) > max_chars and current:
            chunks.append(current)
            current = ""
        while len(piece) > max_chars:
            chunks.append(piece[:max_chars])
            piece = piece[max_chars - 200 :] if max_chars > 400 else piece[max_chars:]
        current += piece
    if current:
        chunks.append(current)
    return chunks


class LLMDetector:
    def __init__(self, model: LocalModel, level: ProtectionLevel, cache_size: int = 2048):
        self.model = model
        self.level = level
        self._cache: OrderedDict[str, list[Span]] = OrderedDict()
        self._cache_size = cache_size
        self._sem = asyncio.Semaphore(2)
        self._prompt_template = load_prompt("detector.md")

    def clear_cache(self) -> int:
        n = len(self._cache)
        self._cache.clear()
        return n

    def system_prompt(self) -> str:
        return self._prompt_template.replace("{{PROTECTION_LEVEL}}", _LEVEL_GUIDANCE[self.level])

    async def detect(self, text: str) -> list[Span]:
        if not text.strip():
            return []
        key = hashlib.sha256(f"{self.level}\x00{text}".encode()).hexdigest()
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]

        spans: list[Span] = []
        async with self._sem:
            for chunk in chunk_text(text):
                data = await self.model.chat_json(
                    self.system_prompt(), chunk, DETECTOR_SCHEMA, "airlock_spans"
                )
                spans.extend(parse_spans(data, text))

        self._cache[key] = spans
        if len(self._cache) > self._cache_size:
            self._cache.popitem(last=False)
        return spans


def parse_spans(data: Any, source_text: str) -> list[Span]:
    """Validate model output. Spans that do not occur verbatim in the source are dropped."""
    if not isinstance(data, dict) or not isinstance(data.get("spans"), list):
        raise LocalModelBadOutput("missing 'spans' array")
    out: list[Span] = []
    seen: set[tuple[str, str]] = set()
    for item in data["spans"]:
        if not isinstance(item, dict):
            continue
        text = str(item.get("text") or "").strip()
        typ = str(item.get("type") or "").upper()
        action = str(item.get("action") or "mask").lower()
        replacement = item.get("replacement")
        if len(text) < MIN_SPAN_CHARS or typ not in SPAN_TYPES or contains_placeholder(text):
            continue
        if action not in ("mask", "generalize"):
            action = "mask"
        if not find_term(source_text, text):
            continue  # hallucinated or paraphrased span
        if (text.casefold(), typ) in seen:
            continue
        seen.add((text.casefold(), typ))
        out.append(
            Span(
                text=text,
                type=typ,
                action=action,  # type: ignore[arg-type]
                replacement=str(replacement).strip() if replacement else None,
                source="llm",
            )
        )
    return out
