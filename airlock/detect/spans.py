"""Span model, term matching and overlap resolution shared by every detector."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from typing import Literal

from airlock.placeholders import STRICT_RE
from airlock.placeholders import contains_placeholder as _contains_placeholder
from airlock.textnorm import fuzzy_find

SPAN_TYPES: tuple[str, ...] = (
    "PERSON",
    "ORG",
    "CONTACT",
    "ID_NUMBER",
    "FINANCIAL",
    "SECRET",
    "LOCATION",
    "HEALTH",
    "QUASI_IDENTIFIER",
)

# vault: declared terms and earlier conversation mappings; regex/entropy: deterministic patterns;
# rule: deterministic Korean/English semantic rules; llm: the local model; user: added in review;
# gliner: NVIDIA GLiNER-PII, accepted by the ensemble policy in airlock.detect.gliner.
Source = Literal["llm", "regex", "vault", "entropy", "rule", "user", "gliner"]
Action = Literal["mask", "generalize", "keep"]

# Lower value wins ties between equally long overlapping spans.
_SOURCE_PRIORITY: dict[str, int] = {
    "vault": 0,
    "user": 1,
    "regex": 2,
    "entropy": 3,
    "rule": 4,
    "llm": 5,
    "gliner": 6,
}
_ACTION_PRIORITY: dict[str, int] = {"mask": 0, "generalize": 1, "keep": 2}

PLACEHOLDER_RE = STRICT_RE  # <TYPE_N>, or legacy [[TYPE_N]]
MIN_SPAN_CHARS = 2


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize(text: str) -> str:
    """Canonical form used for identity and gate comparisons (format chars like ZWSP removed)."""
    nfkc = unicodedata.normalize("NFKC", text)
    visible = "".join(ch for ch in nfkc if unicodedata.category(ch) != "Cf")
    return re.sub(r"\s+", " ", visible).casefold().strip()


@dataclass(frozen=True)
class Span:
    text: str
    type: str
    action: Action = "mask"
    replacement: str | None = None
    source: Source = "llm"
    start: int | None = None  # set by regex detectors; LLM spans are located by text
    end: int | None = None
    rule: str | None = None  # regex rule name, for debugging only

    @property
    def sha256(self) -> str:
        return sha256_text(self.text)


def _is_word_char(ch: str) -> bool:
    return ch.isascii() and (ch.isalnum() or ch == "_")


@lru_cache(maxsize=4096)
def term_pattern(term: str, *, normalized: bool = False) -> re.Pattern[str]:
    """Case-insensitive pattern for `term`.

    Latin-script terms get word boundaries so "Ann" does not match "Annual". Hangul and other
    scripts do not, because Korean particles attach directly to names ("김민수는").
    """
    source = normalize(term) if normalized else term
    # Let any whitespace run in the term match any whitespace run in the text.
    body = r"\s+".join(re.escape(part) for part in source.split())
    prefix = r"(?<![A-Za-z0-9_])" if term and _is_word_char(term.strip()[:1]) else ""
    suffix = r"(?![A-Za-z0-9_])" if term and _is_word_char(term.strip()[-1:]) else ""
    return re.compile(prefix + body + suffix, re.IGNORECASE)


def find_term(text: str, term: str) -> list[tuple[int, int]]:
    """Every raw (start, end) where `term` occurs: exactly (case-insensitive), or as a variant.

    Variants come from `airlock.textnorm`: inserted spaces or separators, zero-width and
    full-width characters, and numbers written with separators or numerals.
    """
    term = term.strip()
    if len(term) < MIN_SPAN_CHARS:
        return []
    found = {(m.start(), m.end()) for m in term_pattern(term).finditer(text)}
    found.update(fuzzy_find(text, term))
    return sorted(found)


@dataclass(frozen=True)
class Placement:
    start: int
    end: int
    span: Span


def locate(text: str, spans: list[Span]) -> list[Placement]:
    """Turn spans into concrete intervals. Text-only spans match every occurrence."""
    out: list[Placement] = []
    for span in spans:
        if span.action == "keep":
            continue
        if span.start is not None and span.end is not None:
            out.append(Placement(span.start, span.end, span))
            continue
        for start, end in find_term(text, span.text):
            out.append(Placement(start, end, span))
    return out


def resolve_overlaps(placements: list[Placement]) -> list[Placement]:
    """Greedy interval selection: longest span wins, then source/action priority, then position."""
    ordered = sorted(
        placements,
        key=lambda p: (
            -(p.end - p.start),
            _SOURCE_PRIORITY.get(p.span.source, 9),
            _ACTION_PRIORITY.get(p.span.action, 9),
            p.start,
        ),
    )
    chosen: list[Placement] = []
    for cand in ordered:
        if cand.end <= cand.start:
            continue
        if any(cand.start < c.end and c.start < cand.end for c in chosen):
            continue
        chosen.append(cand)
    return sorted(chosen, key=lambda p: p.start)


def contains_placeholder(text: str) -> bool:
    return _contains_placeholder(text)
