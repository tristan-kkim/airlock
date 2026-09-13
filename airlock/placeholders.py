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


def rehydrate(
    text: str, lookup: Callable[[str], str | None], transform: Callable[[str], str] = str
) -> str:
    """Replace every placeholder whose key `lookup` knows. Unknown tokens are left untouched."""

    def sub(m: re.Match[str]) -> str:
        raw = m.group("wrapped") or m.group("bare")
        original = lookup(canonical_key(raw))
        return m.group(0) if original is None else transform(original)

    return _REHYDRATE_RE.sub(sub, text)


def canonicalize(text: str, known: Callable[[str], bool]) -> str:
    """Rewrite known placeholders in any lenient form to the canonical `<KEY>` form."""

    def sub(m: re.Match[str]) -> str:
        key = canonical_key(m.group(1))
        return render(key) if known(key) else m.group(0)

    return LENIENT_RE.sub(sub, text)
