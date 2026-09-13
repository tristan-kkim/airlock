"""Detection + vault substitution for chat payloads and free text.

Flow per text slot:

1. Deterministic spans first: regex/entropy patterns, declared vault terms, base64 payloads that
   hide a known value, and originals mapped earlier in the conversation.
2. Those spans are masked (`<SECRET_1>`, ...) in the copy of the text the local model sees, so the
   model never receives raw secrets and cannot echo them.
3. Deterministic semantic rules (`airlock.detect.ko_rules`) run on the original text.
4. The local model runs on the partially masked text. Its spans are verified against the
   original: text that does not occur there is discarded and counted.
   With `AIRLOCK_GLINER=on`, NVIDIA GLiNER-PII runs on the same texts in parallel, and its spans
   pass the ensemble policy (agreement, type consistency, one batched local adjudication call;
   see `airlock.detect.gliner`) before they join the others.
5. All spans are merged -> protection-level policy -> overlap resolution (longest wins) ->
   placeholders or validated generalizations.

`analyze_chat` runs steps 1-4 and `build_chat` runs step 5, so review mode can stop in between.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field, replace
from typing import Any

from airlock import placeholders
from airlock.config import ProtectionLevel, Settings
from airlock.detect.gliner import Ensemble, build_ensemble
from airlock.detect.ko_rules import detect_rules
from airlock.detect.llm import LLMDetector
from airlock.detect.patterns import HIGH_CONFIDENCE_RULES, detect_patterns
from airlock.detect.spans import (
    Span,
    find_term,
    locate,
    normalize,
    resolve_overlaps,
)
from airlock.detect.verify import generalization_ok
from airlock.gate import Protected
from airlock.textnorm import B64_TOKEN, try_base64
from airlock.vault import Mapping, Vault, VaultSession

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
    "Tokens like <PERSON_1> are placeholders for private values; copy them exactly. "
    "Do not guess or invent the hidden values."
)

_HIGH_CONFIDENCE_NAMES = frozenset(r.name for r in HIGH_CONFIDENCE_RULES)


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
class DetectStats:
    """Counts only, never text. Stored in audit `meta.detector`."""

    texts: int = 0
    pattern_spans: int = 0  # regex + entropy
    vault_spans: int = 0  # declared terms, base64 payloads with known values, earlier mappings
    masked_before_llm: int = 0  # deterministic spans hidden from the local model
    rule_spans: int = 0  # ko_rules proposals
    llm_calls: int = 0
    llm_proposed: int = 0
    llm_kept: int = 0
    llm_discarded_ungrounded: int = 0
    llm_discarded_invalid: int = 0
    generalize_rejected: int = 0  # generalizations that leaked the original; masked instead
    semantic_cues: int = 0  # rule spans of type QUASI_IDENTIFIER or HEALTH
    # GLiNER ensemble, per request (absent from `as_dict` when the ensemble is off).
    gliner_texts: int = 0
    gliner_spans: int = 0  # GLiNER spans above threshold, after joining name parts
    gliner_agreed: int = 0  # overlapped a span from another source
    gliner_rejected_mislabel: int = 0  # age/date/money text under another label
    gliner_rejected_shape: int = 0  # failed the type-consistency check
    gliner_rejected_label: int = 0  # GLiNER-only span of an agreement-only label
    gliner_remapped: int = 0  # a name under another label, kept as PERSON
    gliner_candidates: int = 0  # GLiNER-only spans sent to adjudication
    adjudication_calls: int = 0
    adjudicated_yes: int = 0
    adjudicated_no: int = 0
    gliner_ms: int = 0
    adjudication_ms: int = 0

    def add(self, other: DetectStats) -> None:
        for key, value in asdict(other).items():
            setattr(self, key, getattr(self, key) + value)

    @property
    def llm_discarded(self) -> int:
        return self.llm_discarded_ungrounded + self.llm_discarded_invalid

    def as_dict(self) -> dict[str, int]:
        data = asdict(self)
        if not self.gliner_texts:
            data = {k: v for k, v in data.items() if k not in _ENSEMBLE_FIELDS}
        return data


_ENSEMBLE_FIELDS = frozenset(
    k for k in DetectStats.__dataclass_fields__ if k.startswith(("gliner_", "adjudicat"))
)


@dataclass
class Applied:
    """One substitution made by `Sanitizer.apply` (local only: holds the original)."""

    start: int
    end: int
    out_start: int
    out_end: int
    original: str
    span: Span
    mapping: Mapping


@dataclass
class TextResult:
    text: str
    detections: list[Detection] = field(default_factory=list)
    protected: list[Protected] = field(default_factory=list)
    applied: list[Applied] = field(default_factory=list)
    generalize_rejected: int = 0


@dataclass
class Detected:
    spans: list[Span]
    stats: DetectStats


@dataclass
class ChatAnalysis:
    """Detection results for a chat body, before any vault mapping is created."""

    spans_by_text: dict[str, list[Span]]
    stats: DetectStats
    extra_reasons: list[str]


@dataclass
class ChatSanitized:
    payload: dict[str, Any]
    detections: list[Detection]
    protected: list[Protected]
    extra_reasons: list[str]
    stats: DetectStats = field(default_factory=DetectStats)
    # (slot text before, slot text after, substitution), for review previews. Local only.
    applied: list[tuple[str, str, Applied]] = field(default_factory=list)


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


def mask_for_detector(text: str, spans: list[Span]) -> tuple[str, int]:
    """Replace deterministic spans with local-only `<TYPE_N>` tokens for the local model."""
    chosen = resolve_overlaps(locate(text, spans))
    numbers: Counter[str] = Counter()
    tokens: dict[str, str] = {}
    out: list[str] = []
    cursor = 0
    for p in chosen:
        norm = normalize(text[p.start : p.end])
        if norm not in tokens:
            numbers[p.span.type] += 1
            tokens[norm] = placeholders.render(f"{p.span.type}_{numbers[p.span.type]}")
        out.append(text[cursor : p.start])
        out.append(tokens[norm])
        cursor = p.end
    out.append(text[cursor:])
    return "".join(out), len(chosen)


def _chat_slots(messages: list[Any]) -> tuple[list[tuple[Any, Any, bool]], list[str]]:
    """(container, key, json_safe) for every text slot we rewrite, in message order."""
    slots: list[tuple[Any, Any, bool]] = []
    extra_reasons: list[str] = []
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
    return slots, extra_reasons


def _messages_for(body: dict[str, Any], session: VaultSession) -> list[Any]:
    messages = body.get("messages")
    if not isinstance(messages, list) or not messages:
        raise PayloadError("'messages' must be a non-empty array")
    messages = copy.deepcopy(messages)
    slots, _ = _chat_slots(messages)
    for container, key, _json_safe in slots:
        # Clients may send back older or altered placeholders ([[PERSON_1]], < PERSON_1 >).
        container[key] = placeholders.canonicalize(container[key], session.knows_key)
    return messages


class Sanitizer:
    def __init__(
        self,
        settings: Settings,
        detector: LLMDetector,
        vault: Vault,
        ensemble: Ensemble | None = None,
    ):
        self.settings = settings
        self.detector = detector
        self.vault = vault
        # Raises GlinerUnavailable at startup when AIRLOCK_GLINER=on cannot be honored.
        self.ensemble = ensemble or build_ensemble(settings, detector.model)

    # ---- protected strings the gate always enforces ------------------------
    def standing_protected(self) -> list[Protected]:
        items = [Protected(t.text, t.type, "declared_term") for t in self.vault.terms("sensitive")]
        items += [Protected(t.text, "CANARY", "canary") for t in self.vault.terms("canary")]
        items += [Protected(c, "CANARY", "canary") for c in self.settings.canaries]
        return items

    # ---- detection ----------------------------------------------------------
    def deterministic(self, text: str, session: VaultSession) -> tuple[list[Span], DetectStats]:
        stats = DetectStats()
        spans = detect_patterns(text)
        stats.pattern_spans = len(spans)
        declared = self.vault.terms("sensitive")
        vault_spans: list[Span] = []
        for term in declared:
            if find_term(text, term.text):
                vault_spans.append(Span(text=term.text, type=term.type, source="vault"))
        # Mask base64 blobs whose decoded content holds a secret, an ID or a known value.
        for tok in B64_TOKEN.finditer(text):
            decoded = try_base64(tok.group())
            if decoded and (
                detect_patterns(decoded)
                or any(find_term(decoded, t.text) for t in declared)
                or any(find_term(decoded, m.original) for m in session.mappings())
            ):
                vault_spans.append(
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
                vault_spans.append(
                    Span(
                        text=m.original,
                        type=m.type,
                        action=m.action,
                        replacement=m.value if m.action == "generalize" else None,
                        source="vault",
                    )
                )
        stats.vault_spans = len(vault_spans)
        return spans + vault_spans, stats

    async def detect(self, text: str, session: VaultSession) -> Detected:
        """All candidate spans for `text`. Raises LocalModelError if the local model fails."""
        det, stats = self.deterministic(text, session)
        stats.texts = 1
        rules = detect_rules(text)
        stats.rule_spans = len(rules)
        stats.semantic_cues = sum(1 for s in rules if s.type in ("QUASI_IDENTIFIER", "HEALTH"))

        masked, stats.masked_before_llm = mask_for_detector(text, det)
        spans = det + rules
        # Skip the model when nothing but placeholders, digits and punctuation is left.
        if any(ch.isalpha() for ch in placeholders.LENIENT_RE.sub("", masked)):
            llm = await self.detector.detect(masked, original=text)
            stats.llm_calls = llm.calls
            stats.llm_proposed = llm.proposed
            stats.llm_kept = len(llm.spans)
            stats.llm_discarded_ungrounded = llm.discarded_ungrounded
            stats.llm_discarded_invalid = llm.discarded_invalid
            spans += llm.spans
        return Detected(spans, stats)

    async def detect_many(self, texts: list[str], session: VaultSession) -> list[Detected]:
        """`detect` for each text, then the GLiNER ensemble merge step when it is enabled.

        GLiNER runs in parallel with the per-text detectors. Its request-level counters are
        added to the first text's stats, so summing the stats counts them once.
        """
        base = asyncio.gather(*(self.detect(t, session) for t in texts))
        if self.ensemble is None or not texts:
            return list(await base)
        detected, proposals = await asyncio.gather(base, self.ensemble.propose(texts))
        merged = await self.ensemble.merge(texts, [d.spans for d in detected], proposals)
        for d, extra in zip(detected, merged.accepted, strict=True):
            d.spans = d.spans + extra
        first = detected[0].stats
        for key, value in merged.counts.items():
            setattr(first, key, getattr(first, key) + int(value))
        return list(detected)

    def _policy(self, span: Span) -> Span:
        level = self.settings.protection_level
        if span.source not in ("llm", "rule"):
            return span
        if level is ProtectionLevel.MINIMAL and span.type == "QUASI_IDENTIFIER":
            return replace(span, action="keep")
        if level is ProtectionLevel.STRICT and span.action == "generalize":
            return replace(span, action="mask", replacement=None)
        return span

    def apply(
        self,
        text: str,
        spans: list[Span],
        session: VaultSession,
        *,
        json_safe: bool = False,
        rejected: Iterable[str] = (),
    ) -> TextResult:
        """Substitute spans in `text`. `rejected` holds normalized originals the user kept."""
        rejected = set(rejected)
        spans = [self._policy(s) for s in spans]
        if rejected:
            spans = [s for s in spans if normalize(s.text) not in rejected]
        kept = [s for s in spans if s.action == "keep"]
        active = [s for s in spans if s.action != "keep"]
        originals = [s.text for s in active]

        placements = [
            p
            for p in resolve_overlaps(locate(text, active))
            if normalize(text[p.start : p.end]) not in rejected
        ]
        out: list[str] = []
        cursor = 0
        out_len = 0
        detections: list[Detection] = []
        variants: list[Protected] = []
        applied: list[Applied] = []
        rejected_generalizations = 0
        for p in placements:
            original = text[p.start : p.end]
            span = p.span
            # A variant ("새론 다움물류") maps to the entry of the canonical term ("새론다움물류").
            key = original if span.start is not None else span.text
            existing = session.get(original) or session.get(key)
            if existing is not None:
                mapping = existing
            elif span.action == "generalize" and generalization_ok(
                original, span.replacement, originals, json_safe=json_safe
            ):
                mapping = session.generalize(key, span.type, span.replacement or "")
            else:
                if span.action == "generalize":
                    rejected_generalizations += 1
                mapping = session.mask(key, span.type)
            before = text[cursor : p.start]
            out.append(before)
            out_len += len(before)
            out.append(mapping.outbound)
            applied.append(
                Applied(
                    p.start,
                    p.end,
                    out_len,
                    out_len + len(mapping.outbound),
                    original,
                    span,
                    mapping,
                )
            )
            out_len += len(mapping.outbound)
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
        return TextResult(
            "".join(out),
            dedupe_detections(detections),
            protected,
            applied,
            rejected_generalizations,
        )

    async def sanitize_text(self, text: str, session: VaultSession) -> TextResult:
        [detected] = await self.detect_many([text], session)
        return self.apply(text, detected.spans, session)

    # ---- chat payloads ------------------------------------------------------
    async def analyze_chat(self, body: dict[str, Any], session: VaultSession) -> ChatAnalysis:
        """Detect spans in every text slot. Creates no vault mappings."""
        messages = _messages_for(body, session)
        slots, extra_reasons = _chat_slots(messages)
        unique_texts = list(dict.fromkeys(container[key] for container, key, _ in slots))
        detected = await self.detect_many(unique_texts, session)
        stats = DetectStats()
        for d in detected:
            stats.add(d.stats)
        spans_by_text = {t: d.spans for t, d in zip(unique_texts, detected, strict=True)}
        return ChatAnalysis(spans_by_text, stats, extra_reasons)

    def build_chat(
        self,
        body: dict[str, Any],
        analysis: ChatAnalysis,
        session: VaultSession,
        *,
        rejected: Iterable[str] = (),
        added: Iterable[Span] = (),
    ) -> ChatSanitized:
        """Apply the analysis: vault substitution, forwarded fields, placeholder note."""
        messages = _messages_for(body, session)
        slots, _ = _chat_slots(messages)
        rejected = {normalize(r) for r in rejected}
        added = list(added)
        stats = copy.copy(analysis.stats)

        detections: list[Detection] = []
        protected: list[Protected] = []
        applied: list[tuple[str, str, Applied]] = []
        for container, key, json_safe in slots:
            original = container[key]
            spans = list(analysis.spans_by_text.get(original, []))
            spans += [s for s in added if find_term(original, s.text)]
            result = self.apply(original, spans, session, json_safe=json_safe, rejected=rejected)
            container[key] = result.text
            detections += result.detections
            protected += result.protected
            stats.generalize_rejected += result.generalize_rejected
            applied += [(original, result.text, a) for a in result.applied]

        payload: dict[str, Any] = {"model": self.settings.upstream_model}
        for key in FORWARDED_KEYS:
            if key in body:
                payload[key] = messages if key == "messages" else copy.deepcopy(body[key])
        if any(m.action == "mask" for m in session.mappings()):
            _add_placeholder_note(payload["messages"])

        protected += [Protected(m.original, m.type, "vault_original") for m in session.mappings()]
        protected += self.standing_protected()
        return ChatSanitized(
            payload,
            dedupe_detections(detections),
            protected,
            list(analysis.extra_reasons),
            stats,
            applied,
        )

    async def sanitize_chat(self, body: dict[str, Any], session: VaultSession) -> ChatSanitized:
        return self.build_chat(body, await self.analyze_chat(body, session), session)

    # ---- review ---------------------------------------------------------------
    def propose(
        self, body: dict[str, Any], analysis: ChatAnalysis, session: VaultSession
    ) -> tuple[list[dict[str, Any]], DetectStats]:
        """Proposed redactions, computed on a scratch copy of the session (nothing is stored).

        The result is a local-only response: previews contain the originals.
        """
        preview = self.build_chat(body, analysis, session.scratch())
        by_original: dict[str, dict[str, Any]] = {}
        for original_text, outbound_text, a in preview.applied:
            norm = normalize(a.original)
            if norm in by_original:
                continue
            spans = analysis.spans_by_text.get(original_text, [])
            sources = _overlapping_sources(spans, a, original_text)
            by_original[norm] = {
                "span_id": f"s{len(by_original) + 1}",
                "type": a.mapping.type,
                "action": a.mapping.action,
                "text": a.original,
                "replacement": a.mapping.outbound,
                "preview_before": _snippet(original_text, a.start, a.end),
                "preview_after": _snippet(outbound_text, a.out_start, a.out_end),
                "source": a.span.source,
                "sources": sorted(sources),
                "confidence": _confidence(a.span, sources),
                "locked": a.span.source == "vault" or a.span.rule in _HIGH_CONFIDENCE_NAMES,
            }
        return list(by_original.values()), preview.stats

    def review_triggers(self, analysis: ChatAnalysis, preview_stats: DetectStats) -> list[str]:
        """Why `uncertain` review mode would stop this request (empty: confident enough)."""
        reasons = []
        llm_only = False
        for text, spans in analysis.spans_by_text.items():
            model_only = ("llm", "gliner")
            others = locate(text, [s for s in spans if s.source not in model_only])
            for p in locate(text, [s for s in spans if s.source in model_only]):
                if not any(p.start < o.end and o.start < p.end for o in others):
                    llm_only = True
                    break
        if llm_only:
            reasons.append("llm_only_spans")
        if analysis.stats.llm_discarded or preview_stats.generalize_rejected:
            reasons.append("discarded_spans")
        if analysis.stats.semantic_cues:
            reasons.append("semantic_cues")
        return reasons


def _snippet(text: str, start: int, end: int, context: int = 24) -> str:
    left = max(0, start - context)
    right = min(len(text), end + context)
    return ("…" if left else "") + text[left:right] + ("…" if right < len(text) else "")


def _overlapping_sources(spans: list[Span], applied: Applied, text: str) -> set[str]:
    sources = {applied.span.source}
    for p in locate(text, spans):
        if p.start < applied.end and applied.start < p.end:
            sources.add(p.span.source)
    return sources


_BASE_CONFIDENCE = {
    "vault": 1.0,
    "user": 1.0,
    "regex": 0.9,
    "entropy": 0.7,
    "rule": 0.6,
    "llm": 0.6,
    "gliner": 0.6,
}


def _confidence(span: Span, sources: set[str]) -> float:
    """Heuristic, not calibrated: agreement between independent detectors raises it."""
    if span.rule in _HIGH_CONFIDENCE_NAMES:
        return 0.99
    score = _BASE_CONFIDENCE.get(span.source, 0.5)
    if len(sources) > 1:
        score = min(0.95, score + 0.25)
    return round(score, 2)


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
