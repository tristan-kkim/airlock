"""Detection + vault substitution for chat payloads and free text.

Every path (chat, review, `/v1/search`, agent turns and the agent's search guard) detects through
one entry point, `Sanitizer.detect_many`, which takes all texts of a request or turn at once.

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
5. Refinement over the whole request: spans are trimmed (honorifics, titles, ID labels), local
   model spans must have the shape of their type (`airlock.detect.shape`), values the task
   operates on are kept at `balanced` (amounts, lab values, non-birth dates, common diagnoses),
   employer + unit + role combinations are linked into generalizations
   (`airlock.detect.org_rules`), generalizations are made entailed by their original
   (`airlock.generalize`), and a value detected in one slot is propagated to every slot.
6. Protection-level policy -> overlap resolution (longest wins) -> placeholders, surrogates
   (`AIRLOCK_SUBSTITUTION=surrogate`, `airlock.surrogate`) or validated generalizations.

`analyze_chat` runs steps 1-5 and `build_chat` runs step 6, so review mode can stop in between.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import re
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field, replace
from typing import Any

from airlock import generalize, placeholders, surrogate
from airlock.config import ProtectionLevel, Settings, Substitution
from airlock.detect import org_rules
from airlock.detect.gliner import Ensemble, build_ensemble
from airlock.detect.ko_rules import detect_rules
from airlock.detect.llm import LLMDetector, LocalModelError, LocalModelMalformed, load_prompt
from airlock.detect.patterns import HIGH_CONFIDENCE_RULES, detect_patterns, high_confidence_hits
from airlock.detect.shape import check_llm_span, trim
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

ENTAIL_PROMPT = load_prompt("entail.md")
DETERMINISTIC_SOURCES = frozenset({"regex", "entropy", "vault", "user"})

PLACEHOLDER_NOTE = (
    "Tokens like <PERSON_1> are placeholders for private values; copy them exactly. "
    "Do not guess or invent the hidden values."
)
# The S6 test runs showed the cloud model mishandling bare placeholders: it told the user that
# the number they typed "is a placeholder", base64-encoded `<SECRET_1>` into a "fixed" config,
# and wrote about "two people" behind two organization tokens. The note now says that each
# token stands for a real value the user gave and what kind of value it is. The kinds are the
# placeholder types already visible in the payload, so the legend reveals nothing new.
PLACEHOLDER_NOTE_DETAIL = (
    "Each token stands for a real value the user gave, and the user sees your reply with the "
    "real values restored. Treat a token as that value: use it where the value belongs and never "
    "tell the user that a value is a placeholder, hidden or missing. Do not compute anything "
    "from a token (encodings, checksums, arithmetic, digits); show the steps or the command "
    "instead."
)
TYPE_LEGEND = {
    "PERSON": "a person's name",
    "ORG": "an organization's name",
    "PROJECT": "a project or product codename",
    "TERM": "a private name the user declared",
    "CONTACT": "a phone number, e-mail address or handle",
    "ID_NUMBER": "an ID, account or reference number",
    "FINANCIAL": "a card number, bank account or money value",
    "SECRET": "a password, key, token or connection string, exactly as the user wrote it",
    "LOCATION": "an address or place",
    "HEALTH": "a health detail",
    "QUASI_IDENTIFIER": "an identifying personal detail",
    "CANARY": "a private marker",
}

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
    # Refinement, per request (see the module docstring, step 5).
    spans_trimmed: int = 0  # honorifics, titles or ID labels removed from a span
    llm_retyped: int = 0  # local model span whose shape matched another type
    llm_dropped_shape: int = 0  # local model span that cannot hold a value of its type
    kept_situation: int = 0  # amounts, lab values, non-birth dates, common diagnoses
    quasi_linked: int = 0  # employer/unit/site/role/age generalizations
    generalization_fixed: int = 0  # replacement recomputed to be entailed by the original
    entailment_calls: int = 0  # local model "does X imply Y?" calls for health generalizations
    propagated: int = 0  # spans copied to another slot of the same request
    surrogates: int = 0  # values replaced by a surrogate

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


_UNICODE_ESCAPE = re.compile(r"\\u[0-9a-fA-F]{4}")


def decode_json_text(value: str) -> str:
    """JSON text with `\\uXXXX` escapes decoded, so detectors read `강채원`, not escapes.

    The structure is unchanged: it is parsed and dumped again with `ensure_ascii=False`. Text that
    is not a JSON object or array is returned as is.
    """
    stripped = value.strip()
    if not stripped or stripped[0] not in "{[":
        return value
    try:
        parsed = json.loads(stripped)
    except (ValueError, RecursionError):
        return value
    if not isinstance(parsed, dict | list):
        return value
    return json.dumps(parsed, ensure_ascii=False)


def _messages_for(body: dict[str, Any], session: VaultSession) -> list[Any]:
    messages = body.get("messages")
    if not isinstance(messages, list) or not messages:
        raise PayloadError("'messages' must be a non-empty array")
    messages = copy.deepcopy(messages)
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        for call in msg.get("tool_calls") or []:
            fn = call.get("function") if isinstance(call, dict) else None
            if isinstance(fn, dict) and isinstance(fn.get("arguments"), str):
                fn["arguments"] = decode_json_text(fn["arguments"])
        fc = msg.get("function_call")
        if isinstance(fc, dict) and isinstance(fc.get("arguments"), str):
            fc["arguments"] = decode_json_text(fc["arguments"])
        content = msg.get("content")
        is_tool = msg.get("role") == "tool"
        if is_tool and isinstance(content, str) and _UNICODE_ESCAPE.search(content):
            msg["content"] = decode_json_text(content)
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
        self._entail_cache: dict[tuple[str, str], bool] = {}

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

    async def _detect_one(self, text: str, session: VaultSession) -> Detected:
        """Candidate spans for one text. Raises LocalModelError if the local model fails."""
        det, stats = self.deterministic(text, session)
        stats.texts = 1
        rules = detect_rules(text) + org_rules.en_orgs(text)
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
        """The single detection entry point: all texts of one request, turn or search.

        Per text: deterministic spans, rules and the local model; GLiNER runs in parallel over
        all texts and is merged by the ensemble policy when enabled. Then the request-level
        refinement (module docstring, step 5). Request-level counters are added to the first
        text's stats, so summing the stats counts them once. Raises LocalModelError when a
        local model call fails.
        """
        if not texts:
            return []
        base = asyncio.gather(*(self._detect_one(t, session) for t in texts))
        if self.ensemble is None:
            detected = list(await base)
        else:
            detected_t, proposals = await asyncio.gather(base, self.ensemble.propose(texts))
            detected = list(detected_t)
            merged = await self.ensemble.merge(texts, [d.spans for d in detected], proposals)
            for d, extra in zip(detected, merged.accepted, strict=True):
                d.spans = d.spans + extra
            first = detected[0].stats
            for key, value in merged.counts.items():
                setattr(first, key, getattr(first, key) + int(value))
        await self._refine(texts, detected, session)
        return detected

    # ---- refinement -----------------------------------------------------------------------
    def _keeps_situation(self, span: Span, text: str) -> bool:
        """Balanced and minimal keep what the task operates on, when it is not an identifier."""
        if self.settings.protection_level is ProtectionLevel.STRICT:
            return False
        if span.source in DETERMINISTIC_SOURCES or span.type in (
            "PERSON", "ORG", "CONTACT", "SECRET", "LOCATION"
        ):  # fmt: skip
            return False
        if span.type == "HEALTH" and (
            generalize.common_health_term(span.text) or generalize.diagnosis_term(span.text)
        ):
            return not generalize.SMALL_GROUP_CUE.search(text)
        return generalize.situation_value(span.text, span.type) and not generalize.is_birth_date(
            text, span.start, span.end, span.text
        )

    async def _refine(
        self, texts: list[str], detected: list[Detected], session: VaultSession
    ) -> None:
        first = detected[0].stats
        for text, d in zip(texts, detected, strict=True):
            kept: list[Span] = []
            for span in d.spans:
                if span.source in DETERMINISTIC_SOURCES:
                    kept.append(span)
                    continue
                trimmed = trim(span, text)
                if trimmed is None:
                    d.stats.spans_trimmed += 1
                    continue
                if trimmed is not span:
                    d.stats.spans_trimmed += 1
                span = trimmed
                if _code_identifier(span, text):
                    d.stats.llm_dropped_shape += 1
                    continue  # doc_id, orders_rw, PAYMENTS_API_KEY: code, not a private value
                if span.source in ("llm", "gliner") and generalize.arithmetic_number(
                    text, span.start, span.end, span.text
                ):
                    d.stats.llm_dropped_shape += 1
                    continue  # the number the task computes with, not an account
                if span.type == "QUASI_IDENTIFIER" and generalize.diagnosis_term(span.text):
                    # "HER2-positive", "요추 추간판탈출증": a diagnosis, handled as HEALTH (kept
                    # at balanced, category-level otherwise) instead of an invented phrase.
                    span = replace(span, type="HEALTH")
                    d.stats.llm_retyped += 1
                if span.source == "llm" or (
                    span.source == "gliner" and span.type in ("ID_NUMBER", "FINANCIAL", "SECRET")
                ):
                    # GLiNER spans that agreed with another source skipped GLiNER's own shape
                    # check: "직함 선임연구원" went out as an ID number.
                    checked, outcome = check_llm_span(span, text)
                    if checked is None:
                        d.stats.llm_dropped_shape += 1
                        continue
                    if outcome == "retyped":
                        d.stats.llm_retyped += 1
                    span = checked
                if span.action != "keep" and self._keeps_situation(span, text):
                    span = replace(span, action="keep", replacement=None)
                    d.stats.kept_situation += 1
                elif span.type == "HEALTH" and span.action == "generalize":
                    lang = generalize.text_lang(text)
                    better = generalize.category_replacement(span.text, span.replacement, lang)
                    if better:
                        span = replace(span, replacement=better, rule="entailed")
                        d.stats.generalization_fixed += 1
                kept.append(span)
            d.spans = _drop_wider_than_declared(text, kept, d.stats)

        # Employer + unit/site + role/age: link into generalizations (the organization stays
        # masked). An organization masked earlier in the conversation or run counts.
        org_known = any(m.type == "ORG" for m in session.mappings())
        for d, extra in zip(
            detected, org_rules.link(texts, [d.spans for d in detected], org_known=org_known),
            strict=True,
        ):
            if extra:
                d.spans = d.spans + extra
                first.quasi_linked += len(extra)

        await self._entail(texts, detected, first)
        if len(texts) > 1:
            self._propagate(texts, detected, first)

    async def _entail(self, texts: list[str], detected: list[Detected], stats: DetectStats) -> None:
        """Generalizations must be entailed by their original (`airlock.generalize`)."""
        pending: list[tuple[int, int, Span, str]] = []  # (text index, span index, span, lang)
        for ti, (text, d) in enumerate(zip(texts, detected, strict=True)):
            lang = generalize.text_lang(text)
            for si, span in enumerate(d.spans):
                if span.action != "generalize" or span.source in DETERMINISTIC_SOURCES:
                    continue
                if (span.rule or "").startswith("link:"):
                    continue
                fixed, outcome = generalize.fix_generalization(span, text)
                if outcome == "fixed":
                    stats.generalization_fixed += 1
                elif outcome == "rejected":
                    fixed = replace(span, action="mask", replacement=None)
                d.spans[si] = fixed
                if (
                    fixed.type == "HEALTH"
                    and fixed.action == "generalize"
                    and outcome is None
                    and fixed.source in ("llm", "gliner")
                ):
                    pending.append((ti, si, fixed, lang))
        if not pending:
            return
        pairs = [(span.text, span.replacement or "") for _, _, span, _ in pending]
        verdicts = await self._ask_entailment(pairs, stats)
        for (ti, si, span, lang), verdict in zip(pending, verdicts, strict=True):
            if verdict:
                continue
            category = generalize.health_category(span.text, lang)
            if category and category != span.replacement:
                detected[ti].spans[si] = replace(span, replacement=category, rule="entailed")
                stats.generalization_fixed += 1
            elif self.settings.protection_level is ProtectionLevel.STRICT:
                detected[ti].spans[si] = replace(span, action="mask", replacement=None)
            else:
                # Balanced/minimal: a diagnosis is the situation. A wrong generalization would
                # distort the answer; the identifiers around it are masked.
                detected[ti].spans[si] = replace(span, action="keep", replacement=None)
                stats.kept_situation += 1

    async def _ask_entailment(
        self, pairs: list[tuple[str, str]], stats: DetectStats
    ) -> list[bool]:
        """One batched local model call: does each original imply its replacement?"""
        answers: dict[tuple[str, str], bool] = {}
        todo = [p for p in dict.fromkeys(pairs) if p not in self._entail_cache]
        for start in range(0, len(todo), 16):
            batch = todo[start : start + 16]
            ids = [f"e{i + 1}" for i in range(len(batch))]
            lines = [
                f"[{i}] ORIGINAL {json.dumps(o, ensure_ascii=False)} REPLACEMENT "
                f"{json.dumps(r, ensure_ascii=False)}"
                for i, (o, r) in zip(ids, batch, strict=True)
            ]
            schema = {
                "type": "object",
                "properties": {i: {"type": "string", "enum": ["yes", "no"]} for i in ids},
                "required": ids,
                "additionalProperties": False,
            }
            try:
                data = await self.detector.model.chat_json(
                    ENTAIL_PROMPT,
                    "<items>\n" + "\n".join(lines) + "\n</items>",
                    schema,
                    "airlock_entailment",
                    max_tokens=16 + 10 * len(ids),
                    temperature=0.0,
                )
                stats.entailment_calls += 1
                if not isinstance(data, dict) or any(data.get(i) not in ("yes", "no") for i in ids):
                    raise LocalModelMalformed("schema")
                for i, pair in zip(ids, batch, strict=True):
                    self._entail_cache[pair] = data[i] == "yes"
            except LocalModelError:
                # Not a detection failure: without a verdict the generalization is not trusted.
                for pair in batch:
                    answers[pair] = False
        return [answers.get(p, self._entail_cache.get(p, False)) for p in pairs]

    def _propagate(self, texts: list[str], detected: list[Detected], stats: DetectStats) -> None:
        """A value detected in any slot is masked in every slot of the request before the gate."""
        active: dict[str, Span] = {}
        for d in detected:
            for span in d.spans:
                if span.action != "keep":
                    active.setdefault(normalize(span.text), span)
        if not active:
            return
        for text, d in zip(texts, detected, strict=True):
            have = {normalize(s.text) for s in d.spans if s.action != "keep"}
            for norm, span in active.items():
                if norm in have or not find_term(text, span.text):
                    continue
                d.spans.append(
                    Span(
                        text=span.text,
                        type=span.type,
                        action=span.action,
                        replacement=span.replacement,
                        source=span.source,
                        rule=span.rule if (span.rule or "").startswith("link:") else "propagated",
                    )
                )
                stats.propagated += 1

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
        context: Iterable[str] = (),
        context_originals: Iterable[str] = (),
    ) -> TextResult:
        """Substitute spans in `text`. `rejected` holds normalized originals the user kept.

        `context` holds every text of the request, which a surrogate must not collide with.
        """
        rejected = set(rejected)
        spans = [self._policy(s) for s in spans]
        if rejected:
            spans = [s for s in spans if normalize(s.text) not in rejected]
        kept = [s for s in spans if s.action == "keep"]
        active = [s for s in spans if s.action != "keep"]
        originals = [s.text for s in active]

        located = locate(text, active)
        if json_safe:
            # Never rewrite an object key of tool-call arguments ({"doc_id": ...}): the key is
            # schema, not data, and a placeholder there breaks the call.
            keys_only = {
                id(s)
                for s in active
                if (hits := [p for p in located if p.span is s])
                and all(_is_json_key(text, p.start, p.end) for p in hits)
            }
            located = [p for p in located if not _is_json_key(text, p.start, p.end)]
            active = [s for s in active if id(s) not in keys_only]
        placements = [
            p
            for p in resolve_overlaps(located)
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
            trusted = (span.rule or "").startswith(("link:", "entailed"))
            if existing is not None:
                mapping = existing
            elif span.action == "generalize" and generalization_ok(
                original, span.replacement, originals, json_safe=json_safe, check_tokens=not trusted
            ):
                mapping = session.generalize(key, span.type, span.replacement or "")
            else:
                if span.action == "generalize":
                    rejected_generalizations += 1
                mapping = self._substitute(
                    key, span, session, [text, *context], [*originals, *context_originals]
                )
            before = text[cursor : p.start]
            out.append(before)
            out_len += len(before)
            outbound = mapping.outbound
            if mapping.action == "generalize" and _DETERMINER_BEFORE.search(text[: p.start]):
                # "the tenure-track professor" -> "the senior professor", not "the a senior ..."
                outbound = _ARTICLE_HEAD.sub("", outbound) or outbound
            out.append(outbound)
            end = p.end
            if mapping.action != "mask":
                # "마흔다섯이야" -> "40대야": the particle follows the new last syllable.
                fix = surrogate.fix_particle(outbound, text[end : end + 4])
                if fix is not None and text[end : end + fix[0]] != fix[1]:
                    out.append(fix[1])
                    out_len += len(fix[1])
                    end += fix[0]
            applied.append(
                Applied(
                    p.start,
                    p.end,
                    out_len,
                    out_len + len(outbound),
                    original,
                    span,
                    mapping,
                )
            )
            out_len += len(outbound)
            cursor = end
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

    def _substitute(
        self, original: str, span: Span, session: VaultSession, texts: list[str], others: list[str]
    ) -> Mapping:
        """A surrogate when enabled and the value has a known shape; otherwise a placeholder."""
        if (
            self.settings.substitution is Substitution.SURROGATE
            and span.type in surrogate.SURROGATE_TYPES
        ):
            known_originals = [m.original for m in session.mappings()] + others

            def taken(value: str) -> bool:
                return (
                    session.surrogate_taken(value)
                    or bool(high_confidence_hits(value))
                    or surrogate.collides(value, texts, known_originals, ())
                )

            value = surrogate.generate(
                original,
                span.type,
                key=self.vault.surrogate_key,
                scope=session.conversation_id,
                taken=taken,
                known=[
                    surrogate.Known(m.original, m.type, m.value)
                    for m in session.mappings()
                    if m.action == "surrogate"
                ],
            )
            if value is not None:
                return session.surrogate(original, span.type, value)
        return session.mask(original, span.type)

    async def sanitize_texts(self, texts: list[str], session: VaultSession) -> list[TextResult]:
        detected = await self.detect_many(texts, session)
        originals = [s.text for d in detected for s in d.spans if s.action != "keep"]
        return [
            self.apply(text, d.spans, session, context=texts, context_originals=originals)
            for text, d in zip(texts, detected, strict=True)
        ]

    async def sanitize_text(self, text: str, session: VaultSession) -> TextResult:
        [result] = await self.sanitize_texts([text], session)
        return result

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
        texts = [container[key] for container, key, _ in slots]
        # A surrogate must not contain any value protected anywhere in the request.
        request_originals = [
            s.text for spans in analysis.spans_by_text.values() for s in spans if s.action != "keep"
        ] + [s.text for s in added]
        before = sum(1 for m in session.mappings() if m.action == "surrogate")
        for container, key, json_safe in slots:
            original = container[key]
            spans = list(analysis.spans_by_text.get(original, []))
            spans += [s for s in added if find_term(original, s.text)]
            result = self.apply(
                original,
                spans,
                session,
                json_safe=json_safe,
                rejected=rejected,
                context=texts,
                context_originals=request_originals,
            )
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
            _add_placeholder_note(payload["messages"], [c[k] for c, k, _ in slots])

        stats.surrogates += sum(1 for m in session.mappings() if m.action == "surrogate") - before
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


_IDENTIFIER = re.compile(r"[a-z]+(?:_[a-z]+)+")
# snake_case or UPPER_SNAKE with at most two digits: service accounts, env variable names.
_SNAKE = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)+|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")
_ACCOUNT_NAME_CUE = re.compile(
    r"(?:user(?:name)?|role|account|login|owner|db_user)\s*[\"'`=:]*\s*$|for user\s*[\"'`]?$",
    re.IGNORECASE,
)


def _code_identifier(span: Span, text: str) -> bool:
    """A code identifier the local models took for a value (`orders_rw` as a PERSON)."""
    t = span.text.strip()
    if span.type in ("SECRET", "ORG", "ID_NUMBER") and _IDENTIFIER.fullmatch(t):
        return True
    if not _SNAKE.fullmatch(t) or sum(ch.isdigit() for ch in t) > 2:
        return False
    if span.type in ("SECRET", "ORG", "ID_NUMBER", "PERSON"):
        return True
    if span.type == "CONTACT":
        # A messenger handle can be a snake_case name; a database or service account is code.
        idx = text.find(t) if span.start is None else span.start
        return idx >= 0 and bool(_ACCOUNT_NAME_CUE.search(text[max(0, idx - 24) : idx]))
    return False


def _drop_wider_than_declared(text: str, spans: list[Span], stats: DetectStats) -> list[Span]:
    """Drop a model span that strictly contains a declared term.

    The declared term is masked on its own. The wider span swallowed the words around it into
    one placeholder: "데이터 이관은 선우다온 담당" went out as "데이터 <PERSON_4> 담당", and two
    names with the period between them became one CONTACT.
    """
    declared = locate(text, [s for s in spans if s.source == "vault"])
    if not declared:
        return spans
    out = []
    for span in spans:
        if span.source in DETERMINISTIC_SOURCES or span.action == "keep":
            out.append(span)
            continue
        wider = any(
            p.start <= d.start and d.end <= p.end and (p.end - p.start) > (d.end - d.start)
            for p in locate(text, [span])
            for d in declared
        )
        if wider:
            stats.spans_trimmed += 1
            continue
        out.append(span)
    return out


_JSON_KEY_AFTER = re.compile(r'"\s*:')
_DETERMINER_BEFORE = re.compile(
    r"(?:\b(?:the|our|my|their|his|her|its|your|this|that)|['’]s)\s+$", re.IGNORECASE
)
_ARTICLE_HEAD = re.compile(r"^(?:a|an)\s+(?=\S)", re.IGNORECASE)


def _is_json_key(text: str, start: int, end: int) -> bool:
    return (
        start > 0
        and text[start - 1] == '"'
        and bool(_JSON_KEY_AFTER.match(text, end))
        and text[max(0, start - 3) : start - 1].strip()[-1:] in ("{", ",", "")
    )


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


def placeholder_note(texts: Iterable[str] = ()) -> str:
    """The system note: the base rule, what tokens stand for, and a legend of the types in use."""
    types: dict[str, None] = {}
    for text in texts:
        for m in placeholders.STRICT_RE.finditer(text):
            key = m.group(1) or m.group(2)
            types.setdefault(key.rsplit("_", 1)[0], None)
    legend = [f"<{t}_n> is {TYPE_LEGEND.get(t, 'a private value')}" for t in sorted(types)]
    note = f"{PLACEHOLDER_NOTE} {PLACEHOLDER_NOTE_DETAIL}"
    return f"{note} In this conversation: {'; '.join(legend)}." if legend else note


def _add_placeholder_note(messages: list[dict[str, Any]], texts: Iterable[str] = ()) -> None:
    note = placeholder_note(texts)
    first = messages[0] if messages else None
    if (
        first
        and first.get("role") in ("system", "developer")
        and isinstance(first.get("content"), str)
    ):
        first["content"] = f"{note}\n\n{first['content']}"
    else:
        messages.insert(0, {"role": "system", "content": note})
