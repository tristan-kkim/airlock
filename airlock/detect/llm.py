"""Local model client and LLM span detector (NVIDIA Nemotron-3-Nano-4B on a local server).

The local model only *proposes* spans. It never decides whether a request may leave the machine;
that is the job of `airlock.gate`. If the local model cannot be reached or returns anything other
than clean JSON (prose, truncated output, a repetition loop, a timeout), callers must fail closed.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from importlib import resources
from typing import Any

import httpx

from airlock.config import ProtectionLevel, Settings
from airlock.detect.spans import MIN_SPAN_CHARS, SPAN_TYPES, Span, contains_placeholder, find_term
from airlock.detect.verify import grounded


class LocalModelError(Exception):
    """Base class: the local model could not produce a usable answer."""


class LocalModelUnavailable(LocalModelError):
    """Connection failure or non-2xx status from the local server."""


class LocalModelBadOutput(LocalModelError):
    """The local server answered but not with JSON matching the schema."""


class LocalModelMalformed(LocalModelBadOutput):
    """The detector malfunctioned: prose, invalid JSON, truncation, repetition or timeout."""

    KINDS = ("invalid_json", "prose", "length", "repetition", "timeout", "schema")

    def __init__(self, kind: str):
        super().__init__(kind)
        self.kind = kind


def block_reason(exc: LocalModelError, prefix: str = "local_detector") -> str:
    """Gate reason code for a local model failure."""
    if isinstance(exc, LocalModelMalformed):
        return f"{prefix}_malformed:{exc.kind}"
    return f"{prefix}_unavailable:{type(exc).__name__}"


def load_prompt(name: str) -> str:
    return resources.files("airlock.prompts").joinpath(name).read_text(encoding="utf-8")


MAX_SPANS = 40

DETECTOR_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "spans": {
            "type": "array",
            "maxItems": MAX_SPANS,
            "items": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "minLength": 1, "maxLength": 300},
                    "type": {"type": "string", "enum": list(SPAN_TYPES)},
                    "action": {"type": "string", "enum": ["mask", "generalize"]},
                    "replacement": {"type": "string", "maxLength": 120},
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
_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$")
# The same unit of 8-200 characters repeated 5+ times in a row (e.g. one span object looping).
_LOOP_RE = re.compile(r"(.{8,200}?)\1{4,}", re.DOTALL)
REPEATED_ITEM_LIMIT = 6


def extract_json(content: str) -> Any:
    """Parse model output that must be a single JSON object.

    Think blocks and a surrounding code fence are tolerated. Anything else around the object,
    or an answer that is not an object, is a malfunction.
    """
    text = _THINK_RE.sub("", content or "").strip()
    text = _FENCE_RE.sub("", text).strip()
    if not text:
        raise LocalModelMalformed("invalid_json")
    if "<think>" in text or not (text.startswith("{") and text.endswith("}")):
        start = text.find("{")
        raise LocalModelMalformed("prose" if start != 0 else "invalid_json")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        raise LocalModelMalformed("invalid_json") from None


def looks_repetitive(content: str) -> bool:
    return bool(_LOOP_RE.search(content or ""))


def detector_max_tokens(chars: int) -> int:
    """Output cap sized to the input: a span copies input text plus ~25 tokens of JSON."""
    return max(160, min(1536, 160 + 2 * chars))


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
        max_tokens: int = 512,
        retries: int = 1,
    ) -> Any:
        body: dict[str, Any] = {
            "model": self.settings.local_model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": self.settings.local_temperature,
            "top_p": self.settings.local_top_p,
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
            except httpx.TimeoutException as exc:
                raise LocalModelMalformed("timeout") from exc
            except httpx.HTTPError as exc:
                raise LocalModelUnavailable(f"{type(exc).__name__}") from exc
            if resp.status_code >= 400:
                raise LocalModelUnavailable(f"HTTP {resp.status_code}")
            try:
                choice = resp.json()["choices"][0]
                content = choice["message"]["content"]
                finish = choice.get("finish_reason")
            except (KeyError, IndexError, TypeError, ValueError):
                last_error = LocalModelMalformed("schema")
                continue
            # Running into the output cap costs a full generation, so it is not retried. Short
            # malformed answers (prose, a runaway string that stopped) are sampled again once.
            if finish == "length":
                raise LocalModelMalformed("length")
            if not isinstance(content, str):
                last_error = LocalModelMalformed("schema")
                continue
            if looks_repetitive(content):
                last_error = LocalModelMalformed("repetition")
                continue
            try:
                return extract_json(content)
            except LocalModelMalformed as exc:
                last_error = exc
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

CHUNK_CHARS = 2000


def chunk_text(text: str, max_chars: int = CHUNK_CHARS) -> list[str]:
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


def draft_message(text: str) -> str:
    return "<draft>\n" + text + "\n</draft>"


@dataclass
class LLMResult:
    spans: list[Span] = field(default_factory=list)
    proposed: int = 0  # items the model returned
    discarded_ungrounded: int = 0  # text not in the original (hallucinated or paraphrased)
    discarded_invalid: int = 0  # unknown type, too short, placeholder text, duplicates
    calls: int = 0


_MASK_ONLY_TYPES = frozenset({"PERSON", "ORG", "CONTACT", "ID_NUMBER", "FINANCIAL", "SECRET"})


class LLMDetector:
    def __init__(self, model: LocalModel, level: ProtectionLevel, cache_size: int = 2048):
        self.model = model
        self.level = level
        self._cache: OrderedDict[str, LLMResult] = OrderedDict()
        self._cache_size = cache_size
        self._sem = asyncio.Semaphore(2)
        self._prompt_template = load_prompt("detector.md")

    def clear_cache(self) -> int:
        n = len(self._cache)
        self._cache.clear()
        return n

    def system_prompt(self) -> str:
        return self._prompt_template.replace("{{PROTECTION_LEVEL}}", _LEVEL_GUIDANCE[self.level])

    async def detect(self, text: str, original: str | None = None) -> LLMResult:
        """Spans in `text` (already partially masked). They are verified against `original`."""
        original = text if original is None else original
        if not text.strip():
            return LLMResult()
        key = hashlib.sha256(f"{self.level}\x00{text}\x00{original}".encode()).hexdigest()
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]

        result = LLMResult()
        async with self._sem:
            for chunk in chunk_text(text):
                data = await self.model.chat_json(
                    self.system_prompt(),
                    draft_message(chunk),
                    DETECTOR_SCHEMA,
                    "airlock_spans",
                    max_tokens=detector_max_tokens(len(chunk)),
                )
                result.calls += 1
                merge_into(result, parse_spans(data, original))

        self._cache[key] = result
        if len(self._cache) > self._cache_size:
            self._cache.popitem(last=False)
        return result


def merge_into(result: LLMResult, part: LLMResult) -> None:
    seen = {(s.text.casefold(), s.type) for s in result.spans}
    for span in part.spans:
        if (span.text.casefold(), span.type) not in seen:
            seen.add((span.text.casefold(), span.type))
            result.spans.append(span)
    result.proposed += part.proposed
    result.discarded_ungrounded += part.discarded_ungrounded
    result.discarded_invalid += part.discarded_invalid


def parse_spans(data: Any, source_text: str) -> LLMResult:
    """Validate model output against the original text.

    Raises LocalModelMalformed when the shape is wrong or the model looped on one item. Spans
    that do not occur in the original (after normalization) are dropped and counted.
    """
    if not isinstance(data, dict) or not isinstance(data.get("spans"), list):
        raise LocalModelMalformed("schema")
    items = data["spans"]
    result = LLMResult(proposed=len(items))
    counts: dict[str, int] = {}
    for item in items:
        if isinstance(item, dict):
            sig = json.dumps(item, sort_keys=True, ensure_ascii=False)
            counts[sig] = counts.get(sig, 0) + 1
    if counts and max(counts.values()) >= REPEATED_ITEM_LIMIT:
        raise LocalModelMalformed("repetition")

    seen: set[tuple[str, str]] = set()
    for item in items:
        if not isinstance(item, dict):
            result.discarded_invalid += 1
            continue
        text = str(item.get("text") or "").strip()
        typ = str(item.get("type") or "").upper()
        action = str(item.get("action") or "mask").lower()
        replacement = item.get("replacement")
        if len(text) < MIN_SPAN_CHARS or typ not in SPAN_TYPES or contains_placeholder(text):
            result.discarded_invalid += 1
            continue
        if not grounded(text, source_text) or not find_term(source_text, text):
            result.discarded_ungrounded += 1
            continue
        if (text.casefold(), typ) in seen:
            continue
        seen.add((text.casefold(), typ))
        if action not in ("mask", "generalize") or typ in _MASK_ONLY_TYPES:
            action = "mask"
        result.spans.append(
            Span(
                text=text,
                type=typ,
                action=action,  # type: ignore[arg-type]
                # A mask's replacement is ignored: it becomes a placeholder.
                replacement=str(replacement).strip()
                if action == "generalize" and replacement
                else None,
                source="llm",
            )
        )
    return result
