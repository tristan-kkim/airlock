"""Normalized views of text, with index maps back to raw offsets.

Both the vault matcher (to mask variants) and the gate (to block them) use these views, so a
declared term still matches when someone writes it with inserted spaces, zero-width characters,
full-width letters, separators inside numbers, other letter case, Korean or Hanja numerals, or
wraps it in base64, percent-encoding or a JSON string.

Views:

* basic:   NFKC per grapheme cluster, casefold, format characters (Cf, e.g. zero-width) removed,
           Cyrillic/Greek homoglyphs folded to Latin, separated jamo composed ("ㄱㅣㅁ" -> "김").
* compact: basic with every non-alphanumeric character removed ("새론 다움물류" -> "새론다움물류").
* detection (`detection_view`): case and separators kept, with jamo composed, homoglyphs
           folded, spaced syllables and digits joined and spelled numbers as digits; detectors
           run on it to find values nobody declared.
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


# Cyrillic and Greek letters that render like Latin ones ("Jаne" with a Cyrillic а). Folded to
# Latin in the matching views only, so a declared Latin term still matches a homoglyph spelling.
HOMOGLYPHS = str.maketrans(
    "аеорсухіјѕԁһӏԛԝАВЕКМНОРСТХІЈЅΑΒΕΖΗΙΚΜΝΟΡΤΥΧοαειкνρτυχ",
    "aeopcyxijsdhlqwABEKMHOPCTXIJSABEZHIKMNOPTYXoaeikvptux",
)

# Conjoining jamo (what NFKC makes of compatibility jamo such as ㄱ, ㅣ).
_L_BASE, _V_BASE, _T_BASE, _S_BASE = 0x1100, 0x1161, 0x11A7, 0xAC00
# Final-consonant index for each initial consonant, in order ㄱ ㄲ ㄴ ㄷ ㄸ ㄹ ㅁ ㅂ ㅃ ㅅ ㅆ
# ㅇ ㅈ ㅉ ㅊ ㅋ ㅌ ㅍ ㅎ (0: cannot end a syllable).
_L_TO_T = (1, 2, 4, 7, 0, 8, 16, 17, 0, 19, 20, 21, 22, 0, 23, 24, 25, 26, 27)


def _is_l(ch: str) -> bool:
    return 0x1100 <= ord(ch) <= 0x1112


def _is_v(ch: str) -> bool:
    return 0x1161 <= ord(ch) <= 0x1175


def _final_index(ch: str) -> int:
    cp = ord(ch)
    if 0x1100 <= cp <= 0x1112:
        return _L_TO_T[cp - _L_BASE]
    if 0x11A8 <= cp <= 0x11C2:
        return cp - _T_BASE
    return 0


def compose_jamo(chars: list[str], starts: list[int], ends: list[int]) -> None:
    """Compose jamo sequences in place ("ㄱㅣㅁㅁㅣㄴㅈㅣ" -> "김민지"), keeping raw offsets.

    Only initial + vowel (+ final, when no vowel follows it) sequences are composed, so "ㅋㅋ"
    and a jamo written after a finished syllable stay as they are.
    """
    i = 0
    out_c: list[str] = []
    out_s: list[int] = []
    out_e: list[int] = []
    n = len(chars)
    while i < n:
        c = chars[i]
        if i + 1 < n and _is_l(c) and _is_v(chars[i + 1]):
            index = (ord(c) - _L_BASE) * 21 + (ord(chars[i + 1]) - _V_BASE)
            end = ends[i + 1]
            j = i + 2
            if j < n and (t := _final_index(chars[j])) and not (j + 1 < n and _is_v(chars[j + 1])):
                index = index * 28 + t
                end = ends[j]
                j += 1
            else:
                index *= 28
            out_c.append(chr(_S_BASE + index))
            out_s.append(starts[i])
            out_e.append(end)
            i = j
            continue
        out_c.append(c)
        out_s.append(starts[i])
        out_e.append(ends[i])
        i += 1
    chars[:], starts[:], ends[:] = out_c, out_s, out_e


@lru_cache(maxsize=4096)
def basic_view(raw: str) -> View:
    chars: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    for s, e in _clusters(raw):
        for c in unicodedata.normalize("NFKC", raw[s:e]).casefold().translate(HOMOGLYPHS):
            if unicodedata.category(c) == "Cf":
                continue
            chars.append(c)
            starts.append(s)
            ends.append(e)
    compose_jamo(chars, starts, ends)
    return View("".join(chars), tuple(starts), tuple(ends))


@lru_cache(maxsize=4096)
def compact_view(raw: str) -> View:
    v = basic_view(raw)
    keep = [i for i, c in enumerate(v.text) if c.isalnum()]
    chars = [v.text[i] for i in keep]
    starts = [v.starts[i] for i in keep]
    ends = [v.ends[i] for i in keep]
    compose_jamo(chars, starts, ends)  # "ㄱ ㅣ ㅁ" with separators
    return View("".join(chars), tuple(starts), tuple(ends))


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
    # formal Hanja numerals (financial documents)
    "壹": "1", "貳": "2", "參": "3", "肆": "4", "伍": "5",
    "陸": "6", "柒": "7", "捌": "8", "玖": "9",
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


# ---- detection view --------------------------------------------------------------------------

# Separators someone puts between the syllables of a name ("김 민 지", "정.민.준", "박·서·연").
_SYLLABLE_SEPARATORS = frozenset(" \t.·・‧-_/,'’")
_NUMERAL_SEP = frozenset(" \t-.()/+_,:")
# What may follow a number written in Korean numerals without a space ("공구이오이고").
_NUMERAL_TAIL = re.compile(
    r"(?:입니다|이에요|이고요|이고|이며|이다|이야|이라고|이라|이었|이지|이니|번|으로|로|은|는|이|가|을|를|"
    r"에|도|만|고|요|야|라고|다)"
)
# ... and what may follow the last syllable of a name written apart ("김 민 지한테").
_SYLLABLE_TAIL = re.compile(
    _NUMERAL_TAIL.pattern
    + r"|(?:께서는|께서|에게서|에게|한테|이랑|랑|하고|님|씨|께|와|과|의|이나|나)"
)
MIN_SPELLED_DIGITS = 7


def _hangul_syllable(ch: str) -> bool:
    return "가" <= ch <= "힣"


def _collapse_spaced_syllables(chars: list[str], starts: list[int], ends: list[int]) -> None:
    """Drop the separators inside a run of single Hangul syllables ("김 민 지" -> "김민지").

    A run is at least three single syllables with spaces between them, or two with a dot,
    middle dot, hyphen or slash. The last syllable may carry a particle ("김 민 지는").
    """
    n = len(chars)
    drop: set[int] = set()
    i = 0
    while i < n:
        if not _hangul_syllable(chars[i]) or (i > 0 and _hangul_syllable(chars[i - 1])):
            i += 1
            continue
        singles = [i]
        seps: list[range] = []
        j = i + 1
        while True:
            k = j
            while k < n and k - j < 3 and chars[k] in _SYLLABLE_SEPARATORS:
                k += 1
            if k == j or k >= n or not _hangul_syllable(chars[k]):
                break
            if seps and chars[j:k] != chars[seps[0].start : seps[0].stop]:
                break  # "정.민.준, 메일": the comma ends the run
            seps.append(range(j, k))
            end = k
            while end < n and _hangul_syllable(chars[end]):
                end += 1
            if end - k == 1:
                singles.append(k)
                j = k + 1
                continue
            if _SYLLABLE_TAIL.fullmatch("".join(chars[k + 1 : end])):
                singles.append(k)  # the last syllable with its particle ("지는", "연입니다")
            else:
                seps.pop()
            break
        spaced = all(chars[r.start] in " \t" for r in seps)
        if seps and (len(singles) >= 3 or (not spaced and len(singles) >= 2)):
            for r in seps:
                drop.update(r)
        i = max(j, i + 1)
    if drop:
        keep = [x for x in range(n) if x not in drop]
        chars[:] = [chars[x] for x in keep]
        starts[:] = [starts[x] for x in keep]
        ends[:] = [ends[x] for x in keep]


_SPACED_DIGITS = re.compile(
    r"(?<![\dA-Za-z])\d(?:[ \t]\d){5,}(?:[ \t]?-[ \t]?\d(?:[ \t]\d)*)?(?![\dA-Za-z])"
)


def _collapse_spaced_digits(chars: list[str], starts: list[int], ends: list[int]) -> None:
    """ "9 6 1 8 2 1 - 2 8 4 9 3 4 7" -> "961821-2849347": digits read out one at a time."""
    text = "".join(chars)
    drop = {
        m.start() + i
        for m in _SPACED_DIGITS.finditer(text)
        for i, c in enumerate(m.group())
        if c in " \t"
    }
    if drop:
        keep = [x for x in range(len(chars)) if x not in drop]
        chars[:] = [chars[x] for x in keep]
        starts[:] = [starts[x] for x in keep]
        ends[:] = [ends[x] for x in keep]


_SPELLED = re.compile(
    rf"(?P<char>[{''.join(NUMERAL_CHARS)}])"
    rf"|(?P<word>(?<![A-Za-z])(?:{'|'.join(NUMERAL_WORDS)})(?![A-Za-z]))"
    r"|(?P<digit>[0-9])",
    re.IGNORECASE,
)


def _spell_out_digits(chars: list[str], starts: list[int], ends: list[int]) -> None:
    """Numbers spelled in Korean, Hanja or English numerals, rewritten as ASCII digits.

    Only runs of at least `MIN_SPELLED_DIGITS` numerals (separators allowed) that start and end
    at a word boundary and contain a spelled numeral: "공일공 공구일일 공구이오이고" -> "010 0911
    0925이고". Short runs inside words ("사이", "일이") are never touched.
    """
    text = "".join(chars)
    tokens: list[tuple[int, int, str, bool]] = []  # (start, end, digit, spelled)
    for m in _SPELLED.finditer(text):
        kind = m.lastgroup
        value = m.group()
        if kind == "char":
            tokens.append((m.start(), m.end(), NUMERAL_CHARS[value], True))
        elif kind == "word":
            tokens.append((m.start(), m.end(), NUMERAL_WORDS[value.lower()], True))
        else:
            tokens.append((m.start(), m.end(), value, False))
    runs: list[list[tuple[int, int, str, bool]]] = []
    for tok in tokens:
        if runs:
            prev = runs[-1][-1]
            gap = text[prev[1] : tok[0]]
            if len(gap) <= 3 and all(c in _NUMERAL_SEP for c in gap):
                runs[-1].append(tok)
                continue
        runs.append([tok])
    replace: dict[int, tuple[int, str]] = {}  # view start -> (view end, digit)
    for run in runs:
        # A Korean copula after the number ("공구이오이고"): the last 이 belongs to it.
        while run and run[-1][2] == "2" and text[run[-1][0]] == "이" and len(run) > 1:
            after = text[run[-1][1] : run[-1][1] + 1]
            if not after or not _hangul_syllable(after):
                break
            if not _NUMERAL_TAIL.match(text, run[-1][0]):
                break
            run = run[:-1]
        if len(run) < MIN_SPELLED_DIGITS or not any(t[3] for t in run):
            continue
        first, last = run[0], run[-1]
        before = text[first[0] - 1] if first[0] else ""
        after_pos = last[1]
        if before and (_hangul_syllable(before) or before.isalnum()):
            continue
        if (
            after_pos < len(text)
            and text[after_pos].isalnum()
            and not (_hangul_syllable(text[after_pos]) and _NUMERAL_TAIL.match(text, after_pos))
        ):
            continue
        for s, e, digit, spelled in run:
            if spelled:
                replace[s] = (e, digit)
    if not replace:
        return
    out_c: list[str] = []
    out_s: list[int] = []
    out_e: list[int] = []
    i = 0
    while i < len(chars):
        if i in replace:
            e, digit = replace[i]
            out_c.append(digit)
            out_s.append(starts[i])
            out_e.append(ends[e - 1])
            i = e
            continue
        out_c.append(chars[i])
        out_s.append(starts[i])
        out_e.append(ends[i])
        i += 1
    chars[:], starts[:], ends[:] = out_c, out_s, out_e


@lru_cache(maxsize=1024)
def detection_view(raw: str) -> View:
    """The text as a reader sees it, for detectors, with offsets back into `raw`.

    Unlike `basic_view` it keeps letter case and word separators, so the ordinary rules still
    apply. It undoes the encodings that hide a value from them: full-width characters, format
    characters, Cyrillic or Greek homoglyphs, separated jamo ("ㄱㅣㅁ"), syllables written apart
    ("김 민 지", "정.민.준"), digits read out one by one ("9 6 1 8 2 1") and numbers spelled in
    Korean, Hanja or English numerals.
    """
    chars: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    for s, e in _clusters(raw):
        for c in unicodedata.normalize("NFKC", raw[s:e]).translate(HOMOGLYPHS):
            if unicodedata.category(c) == "Cf":
                continue
            chars.append(c)
            starts.append(s)
            ends.append(e)
    compose_jamo(chars, starts, ends)
    _collapse_spaced_syllables(chars, starts, ends)
    _spell_out_digits(chars, starts, ends)
    _collapse_spaced_digits(chars, starts, ends)
    return View("".join(chars), tuple(starts), tuple(ends))


def view_to_raw(view: View, start: int, end: int) -> tuple[int, int]:
    """Raw (start, end) covered by view[start:end]."""
    return view.starts[start], view.ends[end - 1]


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
