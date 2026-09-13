"""Detection + vault substitution for chat payloads and free text.

Flow per text: regex/entropy spans + vault spans (declared terms, earlier mappings) + LLM spans
-> protection-level policy -> overlap resolution (longest wins) -> placeholders/generalizations.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any

from airlock.config import ProtectionLevel, Settings
from airlock.detect.llm import LLMDetector
from airlock.detect.patterns import detect_patterns
from airlock.detect.spans import (
    Span,
    contains_placeholder,
    find_term,
    locate,
    normalize,
    resolve_overlaps,
)
from airlock.gate import Protected
from airlock.textnorm import B64_TOKEN, try_base64
from airlock.vault import Vault, VaultSession

# Request fields forwarded upstream. Everything else (user, metadata, store, ...) is dropped
# because it tends to carry identifiers and Airlock cannot vouch for it.
FORWARDED_KEYS = (
    "messages",
    "temperature",
    "top_p",
    "max_tokens",
    "max_completion_tokens",
    "n",
    "stop",
    "presence_penalty",
    "frequency_penalty",
    "seed",
    "tools",
    "tool_choice",
    "parallel_tool_calls",
    "response_format",
    "logprobs",
    "top_logprobs",
    "reasoning_effort",
    "stream",
    "stream_options",
)

PLACEHOLDER_NOTE = (
    "Privacy note: some values in this conversation were replaced by placeholders such as "
    "[[PERSON_1]] or [[CONTACT_2]]. Treat each placeholder as the real value it stands for. "
    "When you refer to one, repeat the placeholder exactly, including the double brackets. "
    "Do not guess or invent the hidden values."
)


class PayloadError(ValueError):
    """The client request is malformed."""


@dataclass(frozen=True)
class Detection:
    text: str
    type: str
    action: str
    source: str

    def audit(self, hasher: Callable[[str], str]) -> dict[str, str]:
        # Field name kept for compatibility; the value is HMAC-SHA256 under the local audit key.
        return {
            "text_sha256": hasher(self.text),
            "type": self.type,
            "action": self.action,
            "source": self.source,
        }


@dataclass
class TextResult:
    text: str
    detections: list[Detection] = field(default_factory=list)
    protected: list[Protected] = field(default_factory=list)


@dataclass
class ChatSanitized:
    payload: dict[str, Any]
    detections: list[Detection]
    protected: list[Protected]
    extra_reasons: list[str]


def dedupe_detections(items: list[Detection]) -> list[Detection]:
    seen: set[tuple[str, str, str, str]] = set()
    out = []
    for d in items:
        key = (normalize(d.text), d.type, d.action, d.source)
        if key not in seen:
            seen.add(key)
            out.append(d)
    return out


def conversation_id_for(body: dict[str, Any]) -> str:
    """Stable id for a stateless chat: derived from the first user message."""
    for msg in body.get("messages") or []:
        if isinstance(msg, dict) and msg.get("role") == "user":
            raw = json.dumps(msg.get("content"), ensure_ascii=False, sort_keys=True)
            return "conv_" + hashlib.sha256(raw.encode()).hexdigest()[:24]
    return (
        "conv_"
        + hashlib.sha256(
            json.dumps(body.get("messages"), sort_keys=True, default=str).encode()
        ).hexdigest()[:24]
    )


class Sanitizer:
    def __init__(self, settings: Settings, detector: LLMDetector, vault: Vault):
        self.settings = settings
        self.detector = detector
        self.vault = vault

    # ---- protected strings the gate always enforces ------------------------
    def standing_protected(self) -> list[Protected]:
        items = [Protected(t.text, t.type, "declared_term") for t in self.vault.terms("sensitive")]
        items += [Protected(t.text, "CANARY", "canary") for t in self.vault.terms("canary")]
        items += [Protected(c, "CANARY", "canary") for c in self.settings.canaries]
        return items

    # ---- detection ----------------------------------------------------------
    async def detect(self, text: str, session: VaultSession) -> list[Span]:
        """All candidate spans for `text`. Raises LocalModelError if the local model fails."""
        spans = detect_patterns(text)
        declared = self.vault.terms("sensitive")
        for term in declared:
            if find_term(text, term.text):
                spans.append(Span(text=term.text, type=term.type, source="vault"))
        # Mask base64 blobs whose decoded content holds a secret, an ID or a known value.
        for tok in B64_TOKEN.finditer(text):
            decoded = try_base64(tok.group())
            if decoded and (
                detect_patterns(decoded)
                or any(find_term(decoded, t.text) for t in declared)
                or any(find_term(decoded, m.original) for m in session.mappings())
            ):
                spans.append(
                    Span(
                        text=tok.group(),
                        type="SECRET",
                        source="regex",
                        start=tok.start(),
                        end=tok.end(),
                        rule="base64_payload",
                    )
                )
        for m in session.mappings():
            if find_term(text, m.original):
                spans.append(
                    Span(
                        text=m.original,
                        type=m.type,
                        action=m.action,
                        replacement=m.value if m.action == "generalize" else None,
                        source="vault",
                    )
                )
        spans.extend(await self.detector.detect(text))
        return spans

    def _policy(self, span: Span) -> Span:
        level = self.settings.protection_level
        if span.source != "llm":
            return span
        if level is ProtectionLevel.MINIMAL and span.type == "QUASI_IDENTIFIER":
            return replace(span, action="keep")
        if level is ProtectionLevel.STRICT and span.action == "generalize":
            return replace(span, action="mask", replacement=None)
        return span

    def apply(
        self, text: str, spans: list[Span], session: VaultSession, *, json_safe: bool = False
    ) -> TextResult:
        spans = [self._policy(s) for s in spans]
        kept = [s for s in spans if s.action == "keep"]
        active = [s for s in spans if s.action != "keep"]
        originals = [normalize(s.text) for s in active]

        def valid_generalization(span: Span) -> bool:
            repl = (span.replacement or "").strip()
            if not repl or contains_placeholder(repl):
                return False
            if any(ord(c) < 32 for c in repl) or (json_safe and any(c in repl for c in '"\\')):
                return False
            norm_repl = normalize(repl)
            return not any(o and o in norm_repl for o in originals)

        chosen = resolve_overlaps(locate(text, active))
        out: list[str] = []
        cursor = 0
        detections: list[Detection] = []
        variants: list[Protected] = []
        for p in chosen:
            original = text[p.start : p.end]
            span = p.span
            # A variant ("새론 다움물류") maps to the entry of the canonical term ("새론다움물류").
            key = original if span.start is not None else span.text
            existing = session.get(original) or session.get(key)
            if existing is not None:
                mapping = existing
            elif span.action == "generalize" and valid_generalization(span):
                mapping = session.generalize(key, span.type, span.replacement or "")
            else:
                mapping = session.mask(key, span.type)
            out.append(text[cursor : p.start])
            out.append(mapping.outbound)
            cursor = p.end
            detections.append(
                Detection(mapping.original, mapping.type, mapping.action, span.source)
            )
            if normalize(original) != normalize(mapping.original):
                variants.append(Protected(original, mapping.type, "vault_original"))
        out.append(text[cursor:])

        detections += [Detection(s.text, s.type, "keep", s.source) for s in kept]
        protected = [Protected(s.text, s.type, "vault_original") for s in active] + variants
        protected += [
            Protected(d.text, d.type, "vault_original") for d in detections if d.action != "keep"
        ]
        return TextResult("".join(out), dedupe_detections(detections), protected)

    async def sanitize_text(self, text: str, session: VaultSession) -> TextResult:
        return self.apply(text, await self.detect(text, session), session)

    # ---- chat payloads ------------------------------------------------------
    async def sanitize_chat(self, body: dict[str, Any], session: VaultSession) -> ChatSanitized:
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            raise PayloadError("'messages' must be a non-empty array")

        messages = copy.deepcopy(messages)
        extra_reasons: list[str] = []
        # (container, key, json_safe) for every text slot we rewrite, in message order.
        slots: list[tuple[Any, Any, bool]] = []
        for msg in messages:
            if not isinstance(msg, dict):
                raise PayloadError("each message must be an object")
            content = msg.get("content")
            if isinstance(content, str):
                slots.append((msg, "content", False))
            elif isinstance(content, list):
                for part in content:
                    if not isinstance(part, dict):
                        continue
                    if part.get("type") == "text" and isinstance(part.get("text"), str):
                        slots.append((part, "text", False))
                    else:
                        extra_reasons.append(f"uninspectable_content:{part.get('type')}")
            for call in msg.get("tool_calls") or []:
                fn = call.get("function") if isinstance(call, dict) else None
                if isinstance(fn, dict) and isinstance(fn.get("arguments"), str):
                    slots.append((fn, "arguments", True))
            fc = msg.get("function_call")
            if isinstance(fc, dict) and isinstance(fc.get("arguments"), str):
                slots.append((fc, "arguments", True))

        unique_texts = list(dict.fromkeys(container[key] for container, key, _ in slots))
        detected = await asyncio.gather(*(self.detect(t, session) for t in unique_texts))
        spans_by_text = dict(zip(unique_texts, detected, strict=True))

        detections: list[Detection] = []
        protected: list[Protected] = []
        for container, key, json_safe in slots:
            original = container[key]
            result = self.apply(original, spans_by_text[original], session, json_safe=json_safe)
            container[key] = result.text
            detections += result.detections
            protected += result.protected

        payload: dict[str, Any] = {"model": self.settings.upstream_model}
        for key in FORWARDED_KEYS:
            if key in body:
                payload[key] = messages if key == "messages" else copy.deepcopy(body[key])
        if any(m.action == "mask" for m in session.mappings()):
            _add_placeholder_note(payload["messages"])

        protected += [Protected(m.original, m.type, "vault_original") for m in session.mappings()]
        protected += self.standing_protected()
        return ChatSanitized(payload, dedupe_detections(detections), protected, extra_reasons)


def _add_placeholder_note(messages: list[dict[str, Any]]) -> None:
    first = messages[0] if messages else None
    if (
        first
        and first.get("role") in ("system", "developer")
        and isinstance(first.get("content"), str)
    ):
        first["content"] = f"{PLACEHOLDER_NOTE}\n\n{first['content']}"
    else:
        messages.insert(0, {"role": "system", "content": PLACEHOLDER_NOTE})
