"""Deterministic detection on the normalized text: values written so the ordinary rules miss them.

The gate already matches a *known* value in its variants (`airlock.textnorm`). A value nobody
declared has to be found first, and in the final measurement the adversarial Korean cases leaked
exactly where the text hid it from every detector:

* a name with its syllables apart (`정.민.준`, `김 민 지`) or in separated jamo;
* a phone number in Korean numerals: `공일공 공구일일 공구이오`;
* a card number in full-width digits, split over two lines.

This module runs the regex rules and the Korean name rules on `textnorm.detection_view` (NFKC,
homoglyphs folded, jamo composed, spaced syllables joined, spelled numbers as digits) and maps
every hit back to the raw text. A hit whose raw text is already what the rule matched is left to
the ordinary detectors, so the output only adds the hidden forms. Split numbers are joined line
by line. Everything here is a deterministic span: masked before the local model sees the text.
"""

from __future__ import annotations

import re

from airlock.detect.ko_rules import person_spans
from airlock.detect.patterns import _luhn_ok, _rrn_ok, detect_patterns
from airlock.detect.spans import Span
from airlock.textnorm import View, detection_view, view_to_raw

_SPLIT_LINE = re.compile(r"(?m)^[ \t]*(?P<num>\d[\d \t.\-]{1,24}\d)[ \t]*$")
_CARD_CUE = re.compile(r"카드|card|결제|payment", re.IGNORECASE)
_ACCOUNT_CUE = re.compile(r"계좌|account|acct|iban|송금|이체", re.IGNORECASE)
_ID_CUE = re.compile(r"주민|등록번호|외국인등록|resident|national id|ssn", re.IGNORECASE)


def _raw_span(text: str, view: View, start: int, end: int, type_: str, rule: str) -> Span:
    s, e = view_to_raw(view, start, end)
    return Span(text=text[s:e], type=type_, source="regex", start=s, end=e, rule=rule)


def _hidden(text: str, view: View, start: int, end: int) -> bool:
    """The raw text under view[start:end] is not what the view shows (the value was disguised)."""
    s, e = view_to_raw(view, start, end)
    return text[s:e] != view.text[start:end]


def split_numbers(text: str, view: View) -> list[Span]:
    """A card, account or ID number written over consecutive lines of digit groups."""
    lines = list(_SPLIT_LINE.finditer(view.text))
    out: list[Span] = []
    i = 0
    while i < len(lines):
        group = [lines[i]]
        while (
            i + len(group) < len(lines)
            and lines[i + len(group)].start() == group[-1].end() + 1  # the very next line
        ):
            group.append(lines[i + len(group)])
        i += len(group)
        if len(group) < 2:
            continue
        digits = "".join(re.sub(r"\D", "", m.group("num")) for m in group)
        start, end = group[0].start("num"), group[-1].end("num")
        if len(digits) == 13 and _rrn_ok(digits) and _ID_CUE.search(text):
            out.append(_raw_span(text, view, start, end, "ID_NUMBER", "split_rrn"))
        elif 13 <= len(digits) <= 19 and (_luhn_ok(digits) or _CARD_CUE.search(text)):
            out.append(_raw_span(text, view, start, end, "FINANCIAL", "split_card"))
        elif 10 <= len(digits) <= 16 and _ACCOUNT_CUE.search(text):
            out.append(_raw_span(text, view, start, end, "FINANCIAL", "split_account"))
    return out


def detect_obfuscated(text: str) -> list[Span]:
    """Spans for values the ordinary rules cannot see in the raw text. Raw offsets."""
    if not text.strip():
        return []
    view = detection_view(text)
    out = split_numbers(text, view)
    if view.text == text:
        return out
    for p in detect_patterns(view.text):
        if p.rule == "entropy" or not _hidden(text, view, p.start, p.end):
            continue
        out.append(_raw_span(text, view, p.start, p.end, p.type, f"normalized:{p.rule}"))
    for span in person_spans(view.text):
        start, end = span.start, span.end
        if _hidden(text, view, start, end):
            out.append(_raw_span(text, view, start, end, "PERSON", "normalized:ko_name"))
    return out
