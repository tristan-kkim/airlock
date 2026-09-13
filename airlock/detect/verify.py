"""Deterministic checks on what the local model proposes.

The local model is a proposer, not an authority. Two of its observed failure modes are handled
here:

* hallucinated spans: text that does not occur in the draft (e.g. an invented ID number), and
* generalizations that still carry the identifier (`유일하게 한국어-포르투갈어 통역사로 일하는`
  generalized to `한국어-포르투갈어 통역사`), or that switch language or contain junk.
"""

from __future__ import annotations

import re

from airlock.detect.spans import contains_placeholder, normalize

_HANGUL = re.compile(r"[가-힣]")
_DIGIT_RUN = re.compile(r"\d+")
_WORD = re.compile(r"[0-9A-Za-z가-힣][0-9A-Za-z가-힣'\-]*")
# Trailing particles and copulas stripped from Korean tokens before comparison.
_KO_TAIL = re.compile(
    r"(?:으로서|로서|으로|에서|에게|께서|이라서|이라|인데|이고|이며|이다|입니다|이에요|예요|"
    r"로|이|가|은|는|을|를|의|에|와|과|도|만|인|다)$"
)
_JUNK = re.compile(r"[{}\[\]<>`|\\]")
MAX_REPLACEMENT_CHARS = 120


def grounded(span_text: str, original: str) -> bool:
    """The span occurs in the original after the vault's normalization (NFKC, case, spaces)."""
    norm = normalize(span_text)
    return bool(norm) and norm in normalize(original)


def _identifying_tokens(original: str) -> set[str]:
    """Tokens of the original that must not survive into a generalization.

    Digit runs, capitalized or upper-case Latin words, and Korean words of 3+ syllables
    (after stripping particles). Short Korean words (여성, 남성) and lower-case English words
    (years, old) are allowed, so "34 years old" -> "in their 30s" stays valid.
    """
    tokens: set[str] = set(_DIGIT_RUN.findall(original))
    for word in _WORD.findall(original):
        if _HANGUL.search(word):
            for part in re.split(r"[-']", word):
                for candidate in (part, _KO_TAIL.sub("", part)):
                    if len(candidate) >= 3:
                        tokens.add(candidate)
        elif word[:1].isupper() and len(word) >= 2 and not word.isdigit():
            tokens.add(word.casefold())
    return tokens


def generalization_ok(
    original: str, replacement: str | None, others: list[str] = (), *, json_safe: bool = False
) -> bool:
    """Whether `replacement` may stand in for `original` in the outbound text."""
    repl = (replacement or "").strip()
    if not repl or len(repl) > MAX_REPLACEMENT_CHARS or contains_placeholder(repl):
        return False
    if any(ord(c) < 32 for c in repl) or _JUNK.search(repl):
        return False
    if json_safe and any(c in repl for c in '"\\'):
        return False
    norm_repl = normalize(repl)
    if norm_repl in normalize(original):
        return False  # a crop of the original is not a generalization
    for other in [original, *others]:
        norm = normalize(other)
        if norm and norm in norm_repl:
            return False
    # Same language: a Korean span needs a Korean replacement.
    if _HANGUL.search(original) and not _HANGUL.search(repl):
        return False
    repl_digits = set(_DIGIT_RUN.findall(repl))
    folded = repl.casefold()
    for token in _identifying_tokens(original):
        if token.isdigit():
            if token in repl_digits:
                return False
        elif token in folded:
            return False
    return True
