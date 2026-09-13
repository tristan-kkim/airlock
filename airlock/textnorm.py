"""Normalized views of text, with index maps back to raw offsets.

Both the vault matcher (to mask variants) and the gate (to block them) use these views, so a
declared term still matches when someone writes it with inserted spaces, zero-width characters,
full-width letters, separators inside numbers, other letter case, Korean or Hanja numerals, or
wraps it in base64, percent-encoding or a JSON string.

Views:

* basic:   NFKC per grapheme cluster, casefold, format characters (Cf, e.g. zero-width) removed.
* compact: basic with every non-alphanumeric character removed ("새론 다움물류" -> "새론다움물류").
* digits:  maximal runs of digits, where a digit may be written as 0-9 (any width), Korean
           numerals (공 일 이 ...), Hanja numerals (〇 一 二 ...) or English words (one, two ...),
           and runs may be broken by whitespace or - . ( ) / + _ , : separators.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import unquote

MIN_DIGITS = 6  # numeric matching only for needles with at least this many digits
MIN_COMPACT_ASCII = 8  # compact matching guard for Latin-only needles ("a very" vs "avery")
MIN_COMPACT_OTHER = 3  # ... and for needles with Hangul or other scripts


@dataclass(frozen=True)
class View:
    text: str
    starts: tuple[int, ...]  # raw start offset of the cluster that produced each char
    ends: tuple[int, ...]  # raw end offset of that cluster


def _is_attached(ch: str) -> bool:
    cp = ord(ch)
    return bool(unicodedata.combining(ch)) or 0x1160 <= cp <= 0x11FF or 0xD7B0 <= cp <= 0xD7FF


def _clusters(raw: str) -> list[tuple[int, int]]:
    bounds: list[tuple[int, int]] = []
    for i, ch in enumerate(raw):
        if bounds and _is_attached(ch):
            bounds[-1] = (bounds[-1][0], i + 1)
        else:
            bounds.append((i, i + 1))
    return bounds


@lru_cache(maxsize=4096)
def basic_view(raw: str) -> View:
    chars: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    for s, e in _clusters(raw):
        for c in unicodedata.normalize("NFKC", raw[s:e]).casefold():
            if unicodedata.category(c) == "Cf":
                continue
            chars.append(c)
            starts.append(s)
            ends.append(e)
    return View("".join(chars), tuple(starts), tuple(ends))


@lru_cache(maxsize=4096)
def compact_view(raw: str) -> View:
    v = basic_view(raw)
    keep = [i for i, c in enumerate(v.text) if c.isalnum()]
    return View(
        "".join(v.text[i] for i in keep),
        tuple(v.starts[i] for i in keep),
        tuple(v.ends[i] for i in keep),
    )


def fold(text: str) -> str:
    return basic_view(text).text


def compact(text: str) -> str:
    return compact_view(text).text


def compact_ok(needle_compact: str) -> bool:
    limit = MIN_COMPACT_ASCII if needle_compact.isascii() else MIN_COMPACT_OTHER
    return len(needle_compact) >= limit


# ---- digits ---------------------------------------------------------------------------------

NUMERAL_CHARS = {
    "공": "0", "영": "0", "일": "1", "이": "2", "삼": "3", "사": "4", "오": "5",
    "육": "6", "륙": "6", "칠": "7", "팔": "8", "구": "9",
    "〇": "0", "零": "0", "一": "1", "二": "2", "三": "3", "四": "4", "五": "5",
    "六": "6", "七": "7", "八": "8", "九": "9",
}  # fmt: skip
NUMERAL_WORDS = {
    "zero": "0", "oh": "0", "one": "1", "two": "2", "three": "3", "four": "4",
    "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9",
}  # fmt: skip
_NUM_TOKEN = re.compile(
    r"(?P<digit>\d)"
    rf"|(?P<char>[{''.join(NUMERAL_CHARS)}])"
    rf"|(?P<word>(?<![a-z])(?:{'|'.join(NUMERAL_WORDS)})(?![a-z]))"
    r"|(?P<sep>[\s\-.()/+_,:]+)"
    r"|(?P<other>.)",
    re.DOTALL,
)


@dataclass(frozen=True)
class DigitRun:
    digits: str
    starts: tuple[int, ...]
    ends: tuple[int, ...]


@lru_cache(maxsize=4096)
def digit_runs(raw: str) -> tuple[DigitRun, ...]:
    v = basic_view(raw)
    runs: list[DigitRun] = []
    digits: list[str] = []
    starts: list[int] = []
    ends: list[int] = []

    def flush() -> None:
        if len(digits) >= MIN_DIGITS:
            runs.append(DigitRun("".join(digits), tuple(starts), tuple(ends)))
        digits.clear()
        starts.clear()
        ends.clear()

    for m in _NUM_TOKEN.finditer(v.text):
        kind = m.lastgroup
        if kind == "sep":
            continue
        if kind == "other":
            flush()
            continue
        token = m.group()
        if kind == "digit":
            d = str(unicodedata.decimal(token, 0))
        elif kind == "char":
            d = NUMERAL_CHARS[token]
        else:
            d = NUMERAL_WORDS[token]
        digits.append(d)
        starts.append(v.starts[m.start()])
        ends.append(v.ends[m.end() - 1])
    flush()
    return tuple(runs)


def needle_digits(term: str) -> str | None:
    """The digit string to look for, if `term` is mostly a number (phone, ID, account)."""
    c = compact(term)
    digits = "".join(ch for ch in c if ch.isdigit())
    if len(digits) >= MIN_DIGITS and len(digits) / max(1, len(c)) >= 0.6:
        return "".join(str(unicodedata.decimal(ch, 0)) for ch in digits)
    return None


# ---- fuzzy matching --------------------------------------------------------------------------


def _ascii_alnum(ch: str) -> bool:
    return ch.isascii() and ch.isalnum()


def fuzzy_find(text: str, term: str) -> list[tuple[int, int]]:
    """Raw (start, end) spans where `term` occurs in a compact or numeric variant."""
    out: list[tuple[int, int]] = []
    needle = compact(term)
    if needle and compact_ok(needle):
        view = compact_view(text)
        latin_head, latin_tail = _ascii_alnum(needle[0]), _ascii_alnum(needle[-1])
        i = view.text.find(needle)
        while i != -1:
            s, e = view.starts[i], view.ends[i + len(needle) - 1]
            # Latin needles must start and end on word boundaries in the raw text.
            head_ok = not latin_head or s == 0 or not _ascii_alnum(text[s - 1])
            tail_ok = not latin_tail or e >= len(text) or not _ascii_alnum(text[e])
            if head_ok and tail_ok:
                out.append((s, e))
            i = view.text.find(needle, i + 1)
    digits = needle_digits(term)
    if digits:
        for run in digit_runs(text):
            k = run.digits.find(digits)
            while k != -1:
                out.append((run.starts[k], run.ends[k + len(digits) - 1]))
                k = run.digits.find(digits, k + 1)
    return out


# ---- decoding layers -------------------------------------------------------------------------

B64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/_\-])[A-Za-z0-9+/_\-]{16,}={0,2}")


def try_base64(token: str) -> str | None:
    core = token.rstrip("=")
    if len(core) < 16:
        return None
    urlsafe = "-" in core or "_" in core
    if urlsafe and ("+" in core or "/" in core):
        return None
    padded = core + "=" * (-len(core) % 4)
    try:
        raw = base64.b64decode(padded, altchars=b"-_" if urlsafe else None, validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if not text.strip():
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch.isspace())
    return text if printable / len(text) >= 0.9 else None


def _json_strings(obj: object) -> Iterable[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from _json_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _json_strings(v)


def decode_once(text: str) -> list[str]:
    """Embedded JSON strings, percent-encoding and base64 tokens found in `text`."""
    out: list[str] = []
    stripped = text.strip()
    if stripped[:1] in "{[" and stripped[-1:] in "}]":
        with contextlib.suppress(ValueError, RecursionError):
            out.extend(_json_strings(json.loads(stripped)))
    if "%" in text:
        decoded = unquote(text)
        if decoded != text:
            out.append(decoded)
    for m in B64_TOKEN.finditer(text):
        decoded = try_base64(m.group())
        if decoded:
            out.append(decoded)
    return out


def decoded_layers(texts: Iterable[str], depth: int = 2, limit: int = 2000) -> list[str]:
    out: list[str] = []
    frontier = list(texts)
    for _ in range(depth):
        nxt = [d for t in frontier for d in decode_once(t)]
        if not nxt:
            break
        out.extend(nxt)
        if len(out) > limit:
            break
        frontier = nxt
    return out
