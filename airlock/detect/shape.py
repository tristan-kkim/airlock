"""Type consistency for local-model spans, and trimming of titles and labels from every span.

The baseline showed confidently wrong answers after rehydration when a span had the wrong type:
a phone number masked as an affiliation, a seized account as a contact, `ci-runner` as an
organization, `체외수정 시술` as a secret. GLiNER spans already pass a shape check
(`airlock.detect.gliner.shape_ok`); the same idea is applied to Nemotron-3-Nano-4B spans:

1. If a deterministic pattern matches the whole span, its type wins (a phone is CONTACT).
2. Otherwise the span must look like its type, or it is re-typed when its shape is unambiguous,
   or dropped (counted) when it cannot hold a value of that type at all.

Trimming removes what a span picked up around the value: Korean honorifics and particles
(`정다은님` -> `정다은`, which rendered as `정다은님님`), English titles (`Dr. `), and ID labels
(`invoice 9UUT-9586` -> `9UUT-9586`, which rendered as `Invoice invoice 9UUT-9586`).
"""

from __future__ import annotations

import re
from dataclasses import replace

from airlock.detect.gliner import _HANDLE, _digit_count, code_token, ko_name, latin_name
from airlock.detect.patterns import _looks_like_secret, _password_like, detect_patterns
from airlock.detect.spans import MIN_SPAN_CHARS, Span

_HANGUL = re.compile(r"[가-힣]")
_KO_HONORIFIC_TAIL = re.compile(
    r"\s?(?:대표님|대표이사|팀장님|팀장|부장님|부장|과장님|과장|차장님|차장|대리님|대리|실장님|실장|"
    r"주임님|주임|상무님|전무님|이사님|본부장님|선생님|교수님|원장님|변호사님|고객님|환자분|기자님|"
    r"작가님|간호사님|약사님|사장님|회장님|님|씨)"
    r"(?:께서는|께서|께|에게|한테|이랑|랑|은|는|이|가|을|를|의|과|와|도|만|입니다|이에요|이고|이며|인데)?$"
)
# Particles, stripped only from Hangul spans of 4+ syllables: 정다은 ends in 은 and is a name.
_KO_PARTICLE_TAIL = re.compile(
    r"(?:께서는|께서|에게|한테|이랑|입니다|이에요|이고|이며|인데|이라고|라고|은|는|이|가|을|를|의|과|와|도|만)$"
)
_EN_TITLE_HEAD = re.compile(r"^(?:Mr|Mrs|Ms|Mx|Dr|Prof|Sir|Madam|Miss|Rev|Hon)\.?\s+")
_ID_LABEL_HEAD = re.compile(
    r"^(?:invoice|order|ticket|case|account|acct|policy|claim|member|employee|patient|customer|"
    r"reference|ref|booking|reservation|confirmation|tracking|document|doc|file|ID|No\.?|number|"
    r"사번|문서|계좌|계좌번호|증권번호|주문번호|예약번호|사건번호|환자번호|회원번호|고객번호|번호)"
    r"\s*(?:#|:|no\.?|number|번호)?\s*[:#]?\s*",
    re.IGNORECASE,
)
_ORG_KO_TAIL = re.compile(r"(?:에서는|에서|에게|에는|의|은|는|을|를|과|와|이|가|측|쪽|으로|로)$")


def trim(span: Span, text: str) -> Span | None:
    """The span without honorifics, titles, particles or ID labels. None if nothing is left."""
    raw = span.text
    new = raw.strip()
    if span.type == "PERSON":
        if _HANGUL.search(new):
            stripped = _KO_HONORIFIC_TAIL.sub("", new).strip()
            if len(stripped) >= 2:
                new = stripped
            if re.fullmatch(r"[가-힣]{4,6}", new):
                stripped = _KO_PARTICLE_TAIL.sub("", new)
                if len(stripped) >= 3 and ko_name(stripped) == stripped:
                    new = stripped
        else:
            new = _EN_TITLE_HEAD.sub("", new)
            new = re.sub(r"(?:['’]s)$", "", new)
    elif span.type in ("ID_NUMBER", "FINANCIAL", "CONTACT"):
        stripped = _ID_LABEL_HEAD.sub("", new)
        if stripped and re.search(r"\d", stripped) and len(stripped) >= MIN_SPAN_CHARS:
            new = stripped
    elif span.type == "ORG" and _HANGUL.search(new[-1:]):
        stripped = _ORG_KO_TAIL.sub("", new)
        if len(stripped) >= 2 and not _looks_like_particle_word(new):
            new = stripped
    new = new.strip(" \t\r\n,;:")
    if len(new) < MIN_SPAN_CHARS:
        return None
    if new == raw:
        return span
    if span.start is not None and span.end is not None:
        offset = raw.find(new)
        if offset < 0:
            return None
        start = span.start + offset
        return replace(span, text=new, start=start, end=start + len(new))
    return replace(span, text=new)


def _looks_like_particle_word(org: str) -> bool:
    # "대학교", "학교", "병원의" ... keep stems that end in a syllable that is part of the name:
    # a one-syllable tail on a name of 3 syllables or fewer is more likely part of the name.
    return len(org) <= 3


def check_llm_span(span: Span, text: str) -> tuple[Span | None, str]:
    """(span or None, outcome) with outcome "ok", "retyped" or "dropped"."""
    t = span.text.strip()
    if span.type != "SECRET" and len(t) > 80 and len(t) > 0.6 * len(text.strip()):
        return None, "dropped"  # a span that swallows the whole message
    for p in detect_patterns(t):
        if p.start == 0 and p.end == len(t) and p.rule != "entropy":
            if p.type == span.type:
                return span, "ok"
            if span.type in ("HEALTH", "QUASI_IDENTIFIER") and p.type == "LOCATION":
                return span, "ok"
            return replace(span, type=p.type, action="mask", replacement=None), "retyped"
    typ = span.type
    digits = _digit_count(t)
    hangul = bool(_HANGUL.search(t))
    latin = bool(re.search(r"[A-Za-z]", t))
    if typ == "SECRET":
        if hangul and not re.search(r"\d", t) and not latin:
            return None, "dropped"
        return span, "ok"
    if typ == "ORG":
        if digits >= 7 and digits / max(1, len(re.sub(r"\W", "", t))) >= 0.5:
            return replace(span, type="CONTACT" if _phone_like(t) else "ID_NUMBER"), "retyped"
        if not hangul and not any(ch.isupper() for ch in t):
            return None, "dropped"
        return span, "ok"
    if typ == "CONTACT":
        if "@" in t or digits >= 7 or (_HANDLE.match(t) and re.search(r"[\d_.]", t)):
            if digits >= 7 and not _phone_like(t) and "@" not in t:
                return replace(span, type="FINANCIAL" if digits >= 10 else "ID_NUMBER"), "retyped"
            return span, "ok"
        if _looks_like_secret(t):
            return replace(span, type="SECRET"), "retyped"
        if code_token(t):
            return replace(span, type="ID_NUMBER"), "retyped"
        if ko_name(t) or latin_name(t):
            return replace(span, type="PERSON"), "retyped"
        return None, "dropped"
    if typ == "ID_NUMBER":
        if (digits >= 3 and len(t) >= 4) or code_token(t):
            return span, "ok"
        if _looks_like_secret(t) or _password_like(t):
            return replace(span, type="SECRET"), "retyped"
        if ko_name(t) or latin_name(t):
            return replace(span, type="PERSON"), "retyped"
        return None, "dropped"
    if typ == "FINANCIAL":
        if digits >= 3:
            return span, "ok"
        return None, "dropped"
    if typ == "PERSON":
        if digits >= 4:
            return None, "dropped"
        return span, "ok"
    return span, "ok"


def _phone_like(text: str) -> bool:
    compact = re.sub(r"[\s().-]", "", text)
    return bool(
        re.fullmatch(r"\+?\d{9,15}", compact)
        and (
            re.match(r"(?:\+?82)?0?1[016789]", compact)
            or re.match(r"(?:\+?82)?0(?:2|[3-6][1-5])", compact)
            or re.match(r"\+?1?\d{10}$", compact)
            or compact.startswith("+")
        )
    )
