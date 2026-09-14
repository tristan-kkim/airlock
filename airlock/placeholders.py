"""Placeholder syntax: rendering, strict matching, and lenient matching for rehydration.

Canonical form is `<TYPE_N>` (for example `<PERSON_1>`). In the local-model spike, models kept
this form intact more often than `[[TYPE_N]]` when no instruction was given. The legacy
`[[TYPE_N]]` form is still recognised everywhere, so older vault rows and client histories work.

Rehydration is lenient because cloud models sometimes alter the brackets: `< PERSON_1 >`,
`&lt;PERSON_1&gt;`, `[[PERSON_1]]`, `[PERSON_1]`, `⟨PERSON_1⟩`, full-width brackets, lower-case
types. Only keys that exist in the conversation's vault are ever replaced.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable

KEY_PATTERN = r"[A-Z][A-Z_]*_\d+"


def render(key: str) -> str:
    return f"<{key}>"


CANONICAL_RE = re.compile(rf"<({KEY_PATTERN})>")
LEGACY_RE = re.compile(rf"\[\[\s*({KEY_PATTERN})\s*\]\]")
# Either strict form. Group 1 or 2 holds the key.
STRICT_RE = re.compile(rf"<({KEY_PATTERN})>|\[\[\s*({KEY_PATTERN})\s*\]\]")

_KEY_LENIENT = r"[A-Za-zＡ-Ｚａ-ｚ][A-Za-zＡ-Ｚａ-ｚ_＿]*[_＿][0-9０-９]+"
_OPEN = r"(?:&lt;|<|＜|⟨|〈|《|\[\[|\[|［［|［|⟦|\{\{|｛｛)"
_CLOSE = r"(?:&gt;|>|＞|⟩|〉|》|\]\]|\]|］］|］|⟧|\}\}|｝｝)"
LENIENT_RE = re.compile(rf"{_OPEN}\s*({_KEY_LENIENT})\s*{_CLOSE}")
# Wrapped (lenient) or bare upper-case key. Bare keys are only replaced when known.
_REHYDRATE_RE = re.compile(
    rf"{_OPEN}\s*(?P<wrapped>{_KEY_LENIENT})\s*{_CLOSE}"
    rf"|(?<![A-Za-z0-9_])(?P<bare>{KEY_PATTERN})(?![A-Za-z0-9_])"
)

# A possible *prefix* of a wrapped placeholder, used to hold back the end of a stream chunk.
OPENER_CHARS = frozenset("&<＜⟨〈《[［⟦{｛")
PARTIAL_RE = re.compile(
    r"(?:&(?:l(?:t;?)?)?|<|＜|⟨|〈|《|\[\[?|［［?|⟦|\{\{?|｛｛?)"
    r"\s*[A-Za-zＡ-Ｚａ-ｚ_＿0-9０-９]*\s*"
    r"(?:&(?:g(?:t)?)?|\]|］|\}|｝)?"
)
# Fragments of a placeholder cut by chunking ("<SECRET_" or "ET_1>").
_FRAGMENT_RE = re.compile(r"<[A-Z_]{2,}\d*$|^[A-Z_]*_\d+>")


def canonical_key(raw: str) -> str:
    return unicodedata.normalize("NFKC", raw).upper()


def contains_placeholder(text: str) -> bool:
    """True if `text` holds anything that looks like a placeholder, in any bracket style."""
    return bool(
        LENIENT_RE.search(text)
        or _FRAGMENT_RE.search(text)
        or "[[" in text
        or "]]" in text
        or re.search(rf"<\s*{KEY_PATTERN}|{KEY_PATTERN}\s*>", text)
    )


def intervals(text: str) -> list[tuple[int, int]]:
    """Raw (start, end) of every placeholder-looking token in `text`."""
    return [(m.start(), m.end()) for m in LENIENT_RE.finditer(text)]


# "last 4 digits: <FINANCIAL_1>", "ending in <FINANCIAL_1>", "끝자리 <FINANCIAL_1>": the cloud model
# meant a partial value, so restoring the full card number there contradicts the sentence.
_LAST_DIGITS_CUE = re.compile(
    r"(?:last\s*(?:4|four)(?:\s*digits)?|ending\s+(?:in|with)|ends\s+(?:in|with)|끝\s*자리|"
    r"뒷\s*자리|뒤\s*4\s*자리|마지막\s*4\s*자리)"
    r"(?:[\s:*()\[\]\-–—,_`'\"]|only|number|no\.|is|are|of|번호|는|은|가|이){0,12}$",
    re.IGNORECASE,
)
_PARTIAL_TYPES = ("FINANCIAL", "ID_NUMBER")


def last_digits(key: str, original: str, before: str) -> str | None:
    """The last four digits when `before` asks for them and the value is a long number."""
    if not key.startswith(_PARTIAL_TYPES) or not _LAST_DIGITS_CUE.search(before[-48:]):
        return None
    digits = re.sub(r"\D", "", original)
    return digits[-4:] if len(digits) >= 12 else None


def rehydrate(
    text: str,
    lookup: Callable[[str], str | None],
    transform: Callable[[str], str] = str,
    *,
    before: str = "",
) -> str:
    """Replace every placeholder whose key `lookup` knows. Unknown tokens are left untouched.

    Local only, so it may adapt to the sentence: a card number after "last 4 digits" is restored
    as its last four digits, and a Korean particle after the token follows the restored value's
    last syllable (`<PERSON_1>가` -> `남궁하람이`). `before` is text already released before
    `text` (streaming).
    """
    from airlock.surrogate import fix_particle  # local import: surrogate imports this module

    out: list[str] = []
    cursor = 0
    for m in _REHYDRATE_RE.finditer(text):
        if m.start() < cursor:
            continue
        raw = m.group("wrapped") or m.group("bare")
        key = canonical_key(raw)
        original = lookup(key)
        out.append(text[cursor : m.start()])
        cursor = m.end()
        if original is None:
            out.append(m.group(0))
            continue
        value = last_digits(key, original, before + "".join(out)) or original
        out.append(transform(value))
        fix = fix_particle(value, text[cursor : cursor + 4])
        if fix is not None and text[cursor : cursor + fix[0]] != fix[1]:
            out.append(fix[1])
            cursor += fix[0]
    out.append(text[cursor:])
    return "".join(out)


def canonicalize(text: str, known: Callable[[str], bool]) -> str:
    """Rewrite known placeholders in any lenient form to the canonical `<KEY>` form."""

    def sub(m: re.Match[str]) -> str:
        key = canonical_key(m.group(1))
        return render(key) if known(key) else m.group(0)

    return LENIENT_RE.sub(sub, text)
