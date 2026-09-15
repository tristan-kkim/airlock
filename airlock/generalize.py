"""Fact-preserving generalization and the values a task operates on.

Two failure modes from the f0ba569 baseline are handled here:

* **Distortion.** A generalization must be entailed by the original. `1999-05-21` as "in their
  30s", `성남시` as "a district in Seoul" and a disc herniation as "back pain" all made the cloud
  model answer about a different person. Ages and birth years are computed from the text and
  today's date, places are generalized to a containing region from `airlock.detect.regions`, and
  a health generalization that is not in the category table is checked by the local model
  ("does X imply Y?"). The replacement stays in the language of the text.
* **Masking the task.** Amounts, lab values, dosages, durations and dates that are not a birth
  date are the situation, not the identity. At `balanced` they are kept, and so are common
  diagnoses and medications once the identifiers around them are masked.
"""

from __future__ import annotations

import re
from dataclasses import replace
from datetime import date

from airlock.detect import regions
from airlock.detect.ko_rules import _EN_HEALTH, _KO_CANCER, _KO_HEALTH
from airlock.detect.spans import Span

_HANGUL = re.compile(r"[가-힣]")
_LATIN = re.compile(r"[A-Za-z]")


def text_lang(text: str) -> str:
    """ "ko" when Hangul makes up at least a fifth of the letters, else "en"."""
    hangul = len(_HANGUL.findall(text))
    latin = len(_LATIN.findall(text))
    return "ko" if hangul and hangul * 4 >= latin else "en"


# ---- ages and birth dates ---------------------------------------------------------------------

_KO_TENS = {"스물": 20, "스무": 20, "서른": 30, "마흔": 40, "쉰": 50, "예순": 60, "일흔": 70,
            "여든": 80, "아흔": 90}  # fmt: skip
_KO_ONES = {"하나": 1, "한": 1, "둘": 2, "두": 2, "셋": 3, "세": 3, "넷": 4, "네": 4, "다섯": 5,
            "여섯": 6, "일곱": 7, "여덟": 8, "아홉": 9}  # fmt: skip
_KO_NUM_AGE = re.compile(
    rf"({'|'.join(_KO_TENS)})({'|'.join(sorted(_KO_ONES, key=len, reverse=True))})?(?:\s*살)?"
)
_AGE_PATTERNS = (
    re.compile(r"(?:만\s*)?(\d{1,3})\s*(?:세|살)(?![가-힣])|(?:만\s*)?(\d{1,3})\s*(?:세|살)"),
    re.compile(r"(?<![\d])(\d{1,3})\s*-?\s*years?\s*-?\s*old", re.IGNORECASE),
    re.compile(r"\b(?:aged?|turned|turning|turns)\s+(\d{1,3})\b", re.IGNORECASE),
    re.compile(r"\b(\d{1,3})\s*(?:yo|y/o|yrs?)\b", re.IGNORECASE),
    re.compile(r"(?:올해|나이는?|나이가)\s*(\d{1,3})(?!\d)"),
)
_MONTHS = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"]
_DATE_PATTERNS = (
    re.compile(r"(?<!\d)((?:19|20)\d{2})\s*[-./년]\s*(\d{1,2})\s*[-./월]\s*(\d{1,2})"),
    re.compile(
        r"\b("
        + "|".join(_MONTHS)
        + r")[a-z]*\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+((?:19|20)\d{2})\b",
        re.IGNORECASE,
    ),
    re.compile(r"(?<!\d)(\d{1,2})[/.](\d{1,2})[/.]((?:19|20)\d{2})(?!\d)"),
)
_BORN_YEAR = re.compile(
    r"((?:19|20)\d{2})\s*년\s*생|(?<!\d)(\d{2})년생|\bborn\s+(?:in\s+)?((?:19|20)\d{2})\b",
    re.IGNORECASE,
)
DOB_CUE = re.compile(
    r"생년월일|생일|출생|태어났|태어난|년생|\bDOB\b|date of birth|birth\s*date|\bborn\b|birthday",
    re.IGNORECASE,
)


def age_of(text: str) -> int | None:
    """An age stated in `text` ("45세", "마흔다섯", "turned 52", "52-year-old")."""
    for pattern in _AGE_PATTERNS:
        m = pattern.search(text)
        if m:
            value = next(g for g in m.groups() if g)
            age = int(value)
            if 0 < age < 120:
                return age
    m = _KO_NUM_AGE.search(text)
    if m:
        return _KO_TENS[m.group(1)] + (_KO_ONES.get(m.group(2) or "", 0))
    return None


def date_in(text: str) -> date | None:
    for i, pattern in enumerate(_DATE_PATTERNS):
        m = pattern.search(text)
        if not m:
            continue
        try:
            if i == 0:
                return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            if i == 1:
                month = _MONTHS.index(m.group(1)[:3].lower()) + 1
                return date(int(m.group(3)), month, int(m.group(2)))
            return date(int(m.group(3)), int(m.group(1)), int(m.group(2)))
        except ValueError:
            continue
    return None


def birth_year(text: str) -> int | None:
    m = _BORN_YEAR.search(text)
    if m:
        if m.group(1):
            return int(m.group(1))
        if m.group(2):
            yy = int(m.group(2))
            return 1900 + yy if yy > date.today().year % 100 else 2000 + yy
        return int(m.group(3))
    d = date_in(text)
    return d.year if d else None


_DOB_DATE = re.compile(
    r"(?:생년월일|\bDOB\b|\bD\.O\.B\.?|date of birth|birth\s*date|birthday|\bborn(?:\s+on)?)"
    r"\s*(?:is|was|:|-)?\s*(?P<date>(?:19|20)\d{2}\s*[-./년]\s*\d{1,2}\s*[-./월]\s*\d{1,2}(?:\s*일)?"
    r"|\d{1,2}[/.]\d{1,2}[/.](?:19|20)\d{2}"
    r"|(?:" + "|".join(_MONTHS) + r")[a-z]*\.?\s+\d{1,2}(?:st|nd|rd|th)?,?\s+(?:19|20)\d{2})",
    re.IGNORECASE,
)


def birth_dates(text: str) -> list[Span]:
    """Exact birth dates next to their label ("DOB 1953-01-15"), masked as DATE_OF_BIRTH.

    Deterministic, so a birth date does not depend on the local model noticing it (a dev run of
    `hlt-en-08` sent "DOB 1953-01-15" when the model proposed nothing there). A placeholder, not
    a birth decade: a form the user fills in gets the real date back after rehydration.
    """
    return [
        Span(
            text=m.group("date"),
            type="DATE_OF_BIRTH",
            source="rule",
            start=m.start("date"),
            end=m.end("date"),
            rule="birth_date",
        )
        for m in _DOB_DATE.finditer(text)
        if birth_year(m.group("date"))
    ]


def age_from_birth(born: date, today: date | None = None) -> int:
    today = today or date.today()
    return today.year - born.year - ((today.month, today.day) < (born.month, born.day))


def decade_phrase(age: int, lang: str, pronoun: str = "their") -> str:
    decade = age // 10 * 10
    if lang == "ko":
        return "10대" if decade == 10 else f"{decade}대" if decade else "10세 미만"
    if decade == 10:
        return f"in {pronoun} teens"
    return f"in {pronoun} {decade}s" if decade >= 10 else "under 10"


def birth_decade_phrase(year: int, lang: str) -> str:
    decade = year // 10 * 10
    return f"{decade}년대생" if lang == "ko" else f"born in the {decade}s"


# ---- fitting an age phrase to its slot ---------------------------------------------------------
#
# The demo recording `chat-medical-en` sent "I'm age": the model proposed the bare "34" with a
# free-form replacement, and nothing checked it because an age was only recognized with its unit
# inside the span. A bare number is an age when its slot says so (a copula, "aged", "나이는",
# or a unit right after it), and the replacement is built for that slot: the span takes in its
# unit or cue ("34 years old", "aged 34", "만 34세"), the pronoun comes from the subject before
# it ("I'm 34" -> "I'm in my 30s", "she's 34" -> "she's in her 30s"), an adjective stays one
# ("34-year-old" -> "30-something"), and Korean keeps the particle rules ("34살입니다" ->
# "30대입니다").

_BARE_AGE = re.compile(r"^\s*(\d{1,3})\s*$")
_AGE_CUE_BEFORE = re.compile(
    r"(?:\b(?:I'?m|I am|I was|you'?re|you are|she'?s|he'?s|she is|he is|she was|he was|"
    r"is|was|am|are|aged?|turned|turning|turns)\b\s*:?|나이는|나이가|나이|올해|만)\s*$",
    re.IGNORECASE,
)
_NOT_AN_AGE_AFTER = re.compile(
    r"^\s*(?:%|percent|kg|lbs?|cm|mm|km|miles?|hours?|minutes?|seconds?|days?|weeks?|months?|"
    r"years?\s+(?:of|in|at|ago)|dollars?|won|원|만원|명|개|시간|분|일|주|개월|년|회|건|장|점)",
    re.IGNORECASE,
)
_AGE_UNIT_AFTER = re.compile(
    r"^\s*(?:(?:-?\s*years?\s*-?\s*old\b|-?\s*yrs?\b|-?\s*y/?o\b)(?![가-힣A-Za-z])|살|세(?![대기]))",
    re.IGNORECASE,
)  # "34살입니다" keeps its copula; "34세대" (households) and "34세기" are not ages
_BARE_YEAR = re.compile(r"^\s*((?:19|20)\d{2})\s*$")
_BIRTH_CUE_BEFORE = re.compile(
    r"(?:\bborn(?:\s+(?:in|on))?|생년월일|출생\s*연도|태어난\s*해는?|출생)\s*(?:is|was|:|：|-|=)?\s*$",
    re.IGNORECASE,
)
_BIRTH_CUE_AFTER = re.compile(r"^\s*년\s*생")
_AGE_CUE_IN_SPAN = re.compile(r"^(?P<cue>aged?|turned|turning|turns)\s+", re.IGNORECASE)
_AGE_CUE_ENDS_BEFORE = re.compile(r"\b(?P<cue>aged?|turned|turning|turns)\s*:?\s*$", re.IGNORECASE)
_ADJECTIVAL_AGE = re.compile(r"-\s*year\s*-\s*old\s*$", re.IGNORECASE)
# A span that is (nearly) only the age: "34", "34 years old", "turned 52", "만 34세", "서른넷".
_AGE_ONLY = re.compile(r"\s*(?:만\s*)?(?:올해\s*)?[\w\s\-'/]{0,14}\s*$")
_KO_MAN_BEFORE = re.compile(r"만\s*$")
_SUBJECT_CUES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b(?:I'?m|I am|I was|I|my|me|myself)\b", re.I), "my"),
    (re.compile(r"\b(?:she|her|hers|wife|mother|mom|daughter|sister|girlfriend)\b", re.I), "her"),
    (re.compile(r"\b(?:he|his|him|husband|father|dad|son|brother|boyfriend)\b", re.I), "his"),
    (re.compile(r"\b(?:you|your)\b", re.I), "your"),
)
_VERB_FOR = {"my": "am", "your": "are", "her": "is", "his": "is", "their": "is"}


def _pronoun(before: str) -> str:
    """The possessive that fits the subject closest before the span; "their" without one."""
    best, pronoun = -1, "their"
    for pattern, pron in _SUBJECT_CUES:
        for m in pattern.finditer(before[-48:]):
            if m.start() > best:
                best, pronoun = m.start(), pron
    return pronoun


def _span_bounds(span: Span, text: str) -> tuple[int, int] | None:
    """The span's offsets, or the first occurrence whose slot says the bare number is an age."""
    if span.start is not None and span.end is not None:
        return span.start, span.end
    hits = [(s, e) for s, e in _occurrences(text, span.text)]
    if not hits:
        return None
    if not _BARE_AGE.match(span.text):
        return hits[0]
    for s, e in hits:
        if _age_slot(text[:s], text[e:]):
            return s, e
    return None


def _occurrences(text: str, needle: str) -> list[tuple[int, int]]:
    needle = needle.strip()
    if not needle:
        return []
    return [(m.start(), m.end()) for m in re.finditer(re.escape(needle), text)]


def _age_slot(before: str, after: str) -> bool:
    if _NOT_AN_AGE_AFTER.match(after):
        return False
    return bool(_AGE_CUE_BEFORE.search(before[-24:]) or _AGE_UNIT_AFTER.match(after))


def age_in_context(span: Span, text: str) -> int | None:
    """The age a span states, with its unit inside ("34세", "turned 52") or from its slot ("34"
    after "I'm" or before "살")."""
    age = age_of(span.text)
    if age is not None:
        return age
    m = _BARE_AGE.match(span.text)
    if not m:
        return None
    bounds = _span_bounds(span, text)
    if bounds is None:
        return None
    n = int(m.group(1))
    return n if 0 < n < 120 else None


def fit_age(span: Span, text: str, lang: str) -> Span | None:
    """The age span widened to its unit or cue, with a decade phrase that reads in its slot.

    None when the span states no age. The result carries offsets when the span was widened or
    was a bare number, so only that occurrence is replaced.
    """
    age = age_in_context(span, text)
    if age is None or not _AGE_ONLY.match(span.text) or len(span.text) > 24:
        return None  # an age inside a longer phrase ("... 통역사로 일하는 58세 남성") is not refit
    bounds = _span_bounds(span, text)
    if bounds is None:
        return None
    start, end = bounds
    original = span.text
    widened = False
    before, after = text[:start], text[end:]
    if _BARE_AGE.match(original) and (unit := _AGE_UNIT_AFTER.match(after)):
        end += unit.end()
        widened = True
    ko = lang == "ko" or bool(_HANGUL.search(text[start:end]))
    if ko:
        if m := _KO_MAN_BEFORE.search(before):
            start -= len(m.group())  # "만 34세" -> "30대", not "만 30대"
            widened = True
        replacement = decade_phrase(age, "ko")
    elif _ADJECTIVAL_AGE.search(text[start:end]):
        # "a 34-year-old woman" -> "a 30-something woman": the adjective stays one
        replacement = f"{age // 10 * 10}-something"
    else:
        cue = _AGE_CUE_IN_SPAN.match(text[start:end])
        if cue is None and (m := _AGE_CUE_ENDS_BEFORE.search(before)):
            start -= len(m.group())  # "aged 34" / "turned 34": the cue joins the span
            widened = True
            cue = m
        pronoun = _pronoun(text[:start])
        replacement = decade_phrase(age, "en", pronoun)
        if cue is not None and cue.group("cue").lower().startswith("turn"):
            replacement = f"{_VERB_FOR[pronoun]} {replacement}"  # "I turned 52" -> "I am in my 50s"
    new = replace(span, replacement=replacement, rule="entailed")
    if widened or _BARE_AGE.match(original) or span.start is not None:
        new = replace(new, text=text[start:end], start=start, end=end)
    return new


def dedupe_prefix(before: str, replacement: str) -> str:
    """Drop the leading words of `replacement` that the text before the slot already ends with.

    "born in " + "born in the 1990s" -> "the 1990s"; "born " + "born in the 1990s" ->
    "in the 1990s". Word-wise and case-insensitive; the replacement keeps at least one word.
    """
    words = replacement.split()
    tail = before.rstrip().casefold()
    for n in range(len(words) - 1, 0, -1):
        head = " ".join(words[:n]).casefold()
        if tail.endswith(head) and (len(tail) == len(head) or not tail[-len(head) - 1].isalnum()):
            return " ".join(words[n:])
    return replacement


_KO_DECADE = re.compile(r"(\d)0\s*대")
_EN_DECADE = re.compile(
    r"(?<!\d)(\d)0\s*(?:'?s\b|-\s*something\b)|\b(?:in (?:my|your|his|her|their) )?(?P<word>"
    r"teens|twenties|thirties|forties|fifties|sixties|seventies|eighties|nineties)\b",
    re.IGNORECASE,
)  # noqa: E501
_EN_DECADE_WORDS = {"teens": 10, "twenties": 20, "thirties": 30, "forties": 40, "fifties": 50,
                    "sixties": 60, "seventies": 70, "eighties": 80, "nineties": 90}  # fmt: skip
_RANGE = re.compile(r"(?<!\d)(\d{1,3})\s*(?:-|~|–|to|에서)\s*(\d{1,3})(?!\d)")


def stated_ranges(replacement: str) -> list[tuple[int, int]]:
    """Age ranges a replacement states: "40대" (40-49), "mid-40s", "30-something", "35-44"."""
    out = []
    for m in _KO_DECADE.finditer(replacement):
        lo = int(m.group(1)) * 10
        out.append((lo, lo + 9))
    for m in _EN_DECADE.finditer(replacement):
        lo = int(m.group(1)) * 10 if m.group(1) else _EN_DECADE_WORDS[m.group("word").lower()]
        if lo >= 10:
            out.append((lo, lo + 9))
    for m in _RANGE.finditer(replacement):
        lo, hi = int(m.group(1)), int(m.group(2))
        if lo <= hi < 130:
            out.append((lo, hi))
    return out


def _swap_decades(replacement: str, age: int, lang: str) -> str:
    decade = age // 10 * 10
    out = _KO_DECADE.sub(f"{decade}대", replacement)
    out = re.sub(r"(?<!\d)\d0\s*'?s\b", f"{decade}s", out)
    out = re.sub(r"(?<!\d)\d0\s*-\s*something\b", f"{decade}-something", out)
    return re.sub(
        r"(?<!\d)(\d{1,3})\s*(?:-|~|–|to)\s*(\d{1,3})(?!\d)", f"{decade}-{decade + 9}", out
    )


# ---- values the task operates on ---------------------------------------------------------------

_MONEY = re.compile(
    r"^(?:약\s*|about\s+|~)?[$€£₩¥]\s*[\d,.]+\s*(?:[kKmMbB]|million|billion|thousand)?$"
    r"|^(?:약\s*)?[\d,.]+\s*(?:만|억|천|백)?\s*(?:만\s*)?(?:원|달러|엔|유로|dollars?|usd|krw|eur|won)$"
    r"|^(?:약\s*)?[\d,.]+\s*(?:만|억|천)\s*원?$",
    re.IGNORECASE,
)
_MEASURE = re.compile(
    r"^(?:[A-Za-z가-힣][\w가-힣()/\-]{0,15}[\s:]+){0,3}[<>≤≥~]?\s*\d+(?:[.,]\d+)?\s*"
    r"(?:%|퍼센트|mg|㎎|g|kg|mcg|μg|ug|ml|mL|㎖|l|L|IU|units?|mmHg|mmol/L|mg/dL|g/dL|bpm|회|정|알|"
    r"cm|mm|km|kcal|도|℃|°C|°F|pt|포인트|점|배)(?:/(?:일|day|d|회|kg|L|dL))?\s*$",
    re.IGNORECASE,
)
# Lab values usually written without a unit ("eGFR 88", "HbA1c 7.9").
_LAB_NO_UNIT = re.compile(
    r"^(?:eGFR|GFR|HbA1c|A1c|LDL|HDL|BMI|PSA|TSH|INR|CRP|AST|ALT|ESR|WBC|RBC|PLT|Hb|Hgb|"
    r"공복\s*혈당|혈당|당화혈색소|혈압)\s*[:=]?\s*[<>≤≥~]?\s*\d+(?:[.,/]\d+)?\s*%?$",
    re.IGNORECASE,
)
# An amount with a short label: "월 소득 290만원", "annual salary $84,300".
_LABELED_MONEY = re.compile(r"^(?:[A-Za-z가-힣]{1,10}\s*){1,3}[:=]?\s*(?P<amount>.+)$")
_DURATION = re.compile(
    r"^(?:약\s*)?\d+(?:\.\d+)?\s*(?:주|개월|달|년|일|시간|분|weeks?|months?|years?|days?|hours?)(?:\s*(?:간|째|차|분))?$"
    r"|^(?:one|two|three|four|five|six|seven|eight|nine|ten|twelve)\s+(?:weeks?|months?|years?|days?)$",
    re.IGNORECASE,
)
_PLAIN_DATE = re.compile(
    r"^(?:(?:19|20)\d{2}\s*[-./년]\s*)?\d{1,2}\s*[-./월]\s*\d{1,2}\s*일?$|^\d{1,2}\s*월(?:\s*\d{1,2}\s*일)?$"
    r"|^(?:19|20)\d{2}\s*년(?:\s*\d{1,2}\s*월)?(?:\s*\d{1,2}\s*일)?$"
    r"|^(?:" + "|".join(_MONTHS) + r")[a-z]*\.?\s+\d{1,2}(?:st|nd|rd|th)?(?:,?\s+\d{4})?$"
    r"|^\d{1,2}(?:st|nd|rd|th)?\s+(?:of\s+)?(?:" + "|".join(_MONTHS) + r")[a-z]*(?:,?\s+\d{4})?$"
    r"|^(?:19|20)\d{2}[-/.]\d{2}(?:[-/.]\d{2})?$",
    re.IGNORECASE,
)


def is_birth_date(text: str, start: int | None, end: int | None, span_text: str) -> bool:
    """A date span next to a birth cue ("생년월일", "DOB", "born on")."""
    if start is None:
        idx = text.find(span_text)
        start, end = (idx, idx + len(span_text)) if idx >= 0 else (0, 0)
    window = text[max(0, start - 24) : (end or start) + 6]
    return bool(DOB_CUE.search(window))


def situation_value(span_text: str, span_type: str | None = None) -> bool:
    """An amount, measurement, dosage, duration or (non-birth) date.

    With a type, only the shapes that type can legitimately hold count: an ID_NUMBER is kept
    only when it is really a date, a FINANCIAL span only when it is an amount.
    """
    t = span_text.strip().strip(".,;:()")
    if _SCHEDULE.match(t):
        return True  # "7시, 11시, 15시, 19시", "8:30 a.m.": a schedule, never an account number
    if span_type == "ID_NUMBER":
        return bool(_PLAIN_DATE.match(t))
    if span_type == "FINANCIAL":
        return _money(t)
    return bool(
        _money(t)
        or _MEASURE.match(t)
        or _LAB_NO_UNIT.match(t)
        or _DURATION.match(t)
        or _PLAIN_DATE.match(t)
    )


_MONEY_INNER = re.compile(
    r"[$€£₩¥]\s*\d[\d,]*(?:\.\d+)?(?:\s*(?:[kKmMbB]\b|million|billion|thousand))?"
    r"|\d[\d,]*(?:\.\d+)?\s*(?:만|억|천)?\s*(?:원|달러|dollars?|usd|krw|eur|won)",
    re.IGNORECASE,
)
_DURATION_INNER = re.compile(
    r"\d+\s*(?:일|주|개월|달|년|시간|days?|weeks?|months?|years?|hours?)", re.IGNORECASE
)
_COUNT_INNER = re.compile(
    r"\d[\d,]*\s*(?:shares?|units?|times|people|주|건|명|회|개|장|%)", re.IGNORECASE
)


def _money(t: str) -> bool:
    if _MONEY.match(t):
        return True
    m = _LABELED_MONEY.match(t)
    if m and _MONEY.match(m.group("amount").strip()):
        return True
    # "90 days overdue, $46,500", "90일째 안 주고 있어(4,650만원)": an amount inside a short
    # phrase, with no other number that could be an account.
    if len(t) > 100 or not _MONEY_INNER.search(t):
        return False
    rest = _COUNT_INNER.sub(" ", _DURATION_INNER.sub(" ", _MONEY_INNER.sub(" ", t)))
    # No other number (an account) and no capitalized name inside the phrase.
    return not re.search(r"\d|[A-Z][a-z]+\s+[A-Z][a-z]+", rest)


_CLOCK = (
    r"(?:(?:오전|오후|새벽|저녁|밤|아침)\s*)?\d{1,2}\s*시(?:\s*\d{1,2}\s*분|\s*반)?"
    r"|\d{1,2}:\d{2}(?:\s*[ap]\.?m\.?)?|\d{1,2}\s*[ap]\.?m\.?"
)
_SCHEDULE = re.compile(
    rf"^(?:{_CLOCK})(?:\s*(?:,|/|·|~|-|–|to|and|및|와|과|\s)\s*(?:{_CLOCK}))*$", re.IGNORECASE
)

# A bare number the request computes with ("Is 479001600 equal to 12 factorial?").
_MATH_CUE = re.compile(
    r"factorial|팩토리얼|\bequal(?:s)?\b|\bprime\b|소수|\bdivisible\b|약수|배수|제곱|"
    r"\bsquare root\b|\bsum of\b|곱하기|나누기|더하기|빼기|계산|\bcalculate\b|\bcompute\b|[×÷=^]",
    re.IGNORECASE,
)
_ACCOUNT_CUE = re.compile(
    r"account|acct|card|routing|iban|계좌|카드|번호|\bID\b|number|#|no\.", re.IGNORECASE
)


def arithmetic_number(text: str, start: int | None, end: int | None, span_text: str) -> bool:
    """A plain digit run in a sentence that computes with it, with no account or ID label."""
    t = span_text.strip()
    if not re.fullmatch(r"\d{4,}", t):
        return False
    if start is None:
        idx = text.find(t)
        start, end = (idx, idx + len(t)) if idx >= 0 else (0, 0)
    before = text[max(0, start - 30) : start]
    window = text[max(0, start - 60) : (end or start) + 60]
    return bool(_MATH_CUE.search(window)) and not _ACCOUNT_CUE.search(before)


# Small-group markers: a diagnosis next to them narrows the person down ("3학년 2반 쌍둥이").
SMALL_GROUP_CUE = re.compile(
    r"\d+\s*학년\s*\d+\s*반|쌍둥이|유일|하나뿐|단\s*한\s*명|혼자만|\bonly\b|\bsole\b|\btwins?\b|"
    r"\bclass of \d+|\b\d+-(?:person|member|employee|student)\b|\bour (?:class|ward|unit|floor)\b",
    re.IGNORECASE,
)


# ---- health --------------------------------------------------------------------------------------

_HEALTH_CATEGORIES: tuple[tuple[re.Pattern[str], str, str], ...] = tuple(
    (re.compile(p, re.IGNORECASE), ko, en)
    for p, ko, en in (
        (
            r"추간판|디스크|disc herniation|herniated disc|slipped disc",
            "척추 질환",
            "a spinal disc condition",
        ),
        (r"양극성|조울|bipolar", "기분장애", "a mood disorder"),
        (r"우울|depress", "우울장애", "a depressive disorder"),
        (r"공황|불안장애|panic|anxiety", "불안장애", "an anxiety disorder"),
        (r"조현|schizophren|psychosis", "정신질환", "a psychiatric disorder"),
        (r"ADHD|자폐|autism|발달장애", "신경발달장애", "a neurodevelopmental condition"),
        (
            r"파킨슨|치매|알츠하이머|parkinson|dementia|alzheimer",
            "신경퇴행성 질환",
            "a neurodegenerative disease",
        ),
        (r"뇌전증|간질|epilep|seizure", "신경계 질환", "a neurological condition"),
        (r"HIV|AIDS|에이즈|간염|hepatitis", "만성 감염 질환", "a chronic infection"),
        (r"암|cancer|leukemia|lymphoma|백혈병|림프종|종양|tumou?r", "암", "cancer"),
        (r"당뇨|diabet|insulin|인슐린", "당뇨병", "diabetes"),
        (
            r"고혈압|심근경색|협심증|부정맥|심부전|hypertension|heart",
            "심혈관 질환",
            "a cardiovascular condition",
        ),
        (r"천식|asthma|COPD|폐렴|pneumonia", "호흡기 질환", "a respiratory condition"),
        (r"난임|불임|체외수정|시험관|IVF|infertil", "난임 치료", "fertility treatment"),
        (r"임신|pregnan", "임신", "pregnancy"),
        (r"중독|addiction|alcoholism|substance use", "중독 질환", "a substance use disorder"),
        (r"섭식|거식|폭식|anorexia|bulimia|eating disorder", "섭식장애", "an eating disorder"),
    )
)


VAGUE_HEALTH = frozenset({"건강 문제", "질병", "a health condition", "a medical condition"})


def category_replacement(original: str, replacement: str | None, lang: str) -> str | None:
    """The category-level term instead of a vague one ("ADHD 진단" -> "신경발달장애 진단")."""
    if replacement not in VAGUE_HEALTH and replacement:
        return None
    category = health_category(original, lang)
    if category is None:
        return None
    care = re.search(r"(진단|수술|처방|치료)$", original.strip())
    return f"{category} {care.group(1)}" if care and lang == "ko" else category


def health_category(text: str, lang: str) -> str | None:
    for pattern, ko, en in _HEALTH_CATEGORIES:
        if pattern.search(text):
            return ko if lang == "ko" else en
    return None


_DIAGNOSIS_SHAPE = re.compile(
    r"^[\w\s\-'’+/]{0,30}?(?:증후군|탈출증|증|병|염|암|장애|질환|종양|감염|결핍|양성|음성)$"
    r"|^[\w\s\-'’+/]{0,30}?(?:disease|syndrome|disorder|deficiency|infection|herniation|itis|"
    r"carcinoma|lymphoma|melanoma|sarcoma|glaucoma|myeloma|blastoma|glioma|"
    r"[-\s]positive|[-\s]negative)$",
    re.IGNORECASE,
)
# Documents and cards that end like a diagnosis ("자격증", "신분증").
_NOT_A_DIAGNOSIS_TAIL = re.compile(
    r"(?:자격|영수|신분|학생|사원|면허|등록|수료|보|인|확인|허가|합격|졸업|출입|공무원|회원|이용|증명)증$"
)
# Words that turn a diagnosis into a description of one person ("the only ... with X").
_NOT_JUST_A_DIAGNOSIS = re.compile(
    r"\b(?:only|sole|first|youngest|oldest|with|at|in|of|my|her|his|their|who)\b|유일|최초|하나뿐|"
    r"에서|의\s",
    re.IGNORECASE,
)


def diagnosis_term(span_text: str) -> bool:
    """The span is only a diagnosis or a finding ("HER2-positive", "요추 추간판탈출증", "Fabry
    disease"), not a phrase that describes a person through one."""
    t = span_text.strip().strip(".,;:()")
    if not t or len(t) > 48 or len(t.split()) > 6 or re.search(r"\d{3,}", t):
        return False
    if _NOT_JUST_A_DIAGNOSIS.search(t) or _NOT_A_DIAGNOSIS_TAIL.search(t):
        return False
    return common_health_term(t) or bool(_DIAGNOSIS_SHAPE.match(t))


_HEALTH_TERM_CUE = re.compile(
    r"\b(?:only|sole|first|youngest|oldest|who|that|which|whose|my|her|his|their|our)\b|"
    r"유일|최초|하나뿐|혼자|우리|내가|제가",
    re.IGNORECASE,
)


def health_term(span_text: str) -> bool:
    """A short health term ("체외수정 시술", "도수치료", "요추", "Fabry disease"): the situation
    at balanced, kept as written. Rewording it locally is where distortion came from ("요추" as
    "등심", "체외수정" as "수술"). Descriptive phrases still go through generalization."""
    t = span_text.strip().strip(".,;:()")
    if not t or len(t) > 32 or len(t.split()) > 4 or re.search(r"\d{3,}", t):
        return False
    return not _HEALTH_TERM_CUE.search(t)


def common_health_term(span_text: str) -> bool:
    """A diagnosis, condition or medication from the rule lexicons, stated without identifiers."""
    t = span_text.strip()
    if len(t) > 40 or re.search(r"\d{3,}", t):
        return False
    return bool(_KO_HEALTH.search(t) or re.search(_KO_CANCER, t) or _EN_HEALTH.search(t))


# ---- places --------------------------------------------------------------------------------------

_KO_PLACE_ONLY = re.compile(
    r"^(?:[가-힣]+(?:특별자치시|특별자치도|특별시|광역시|도|시|군|구|읍|면|동|리)?\s*){1,4}"
    r"(?:에서|에|의|쪽|소재)?$"
)


def place_generalization(span_text: str, lang: str) -> str | None:
    """A containing region for a place-only span ("성남시" -> "경기도의 한 도시"), or None."""
    t = span_text.strip()
    if lang == "ko" or _HANGUL.search(t):
        places = regions.ko_places(t)
        if not places or not _KO_PLACE_ONLY.match(t):
            return None
        # every token must be a place: "새내군에서 사과 농사" is not place-only
        if len(t.split()) != len(places):
            return None
        smallest = places[-1]
        noun = regions.KO_SUFFIX_GENERIC.get(smallest.suffix, "한 지역")
        top = regions.ko_container(t)
        if top and top == smallest.name:
            return None  # already a top-level region: nothing coarser to say
        if top:
            return f"{top}의 {noun}" if noun.startswith("한 ") else top
        return noun
    places = regions.en_places(t)
    if not places:
        return None
    covered = " ".join(p.name for p in places)
    rest = re.sub(r"[\s,]+", " ", t)
    for p in places:
        rest = rest.replace(p.name, "")
    rest = re.sub(r"\b[A-Z]{2}\b", "", rest).strip(" ,")
    if rest:
        return None
    top = regions.en_container(covered)
    if top and top not in t:
        return f"a city in {top}"
    return "a city" if top else None


def places_consistent(original: str, replacement: str) -> bool:
    """False when the replacement names a region that does not contain the original's places."""
    named = regions.named_regions(replacement)
    if not named:
        return True
    ko = [p for p in regions.ko_places(original) if p.top]
    en = [p for p in regions.en_places(original) if p.top]
    if not ko and not en:
        # A fictional or unknown place generalized to a named region cannot be verified.
        return False
    tops = {p.top for p in ko + en}
    return all(n in tops or any(n == p.name for p in ko + en) for n in named)


# ---- fixing a proposed generalization -----------------------------------------------------------


def fix_generalization(span: Span, text: str) -> tuple[Span, str | None]:
    """Make a generalize span entailed by its original.

    Returns (span, outcome). outcome is None when nothing changed, "fixed" when the replacement
    was recomputed, and "rejected" when no entailed replacement is available (the span is then
    masked by the caller).
    """
    if span.action != "generalize":
        return span, None
    original = span.text
    lang = text_lang(text)
    repl = (span.replacement or "").strip()

    # Birth dates and birth years: say the birth decade, fitted after "born in" or a label.
    if DOB_CUE.search(original) or (
        date_in(original) and is_birth_date(text, span.start, span.end, original)
    ):
        year = birth_year(original)
        if year:
            want = _fit_birth_decade(span, text, year, lang)
            return (span if repl == want else _set(span, want)), (None if repl == want else "fixed")
    if m := _BARE_YEAR.match(original):
        fitted = _fit_birth_year(span, text, int(m[1]), lang)
        if fitted is not None:
            return fitted, "fixed"
    if date_in(original) and (d := date_in(original)) is not None:
        age = age_from_birth(d)
        if not any(lo <= age <= hi for lo, hi in stated_ranges(repl)) and stated_ranges(repl):
            return _set(span, decade_phrase(age, lang)), "fixed"

    # Ages: the phrase built for the slot ("I'm 34" -> "I'm in my 30s"), unless the model's is
    # already that phrase.
    fitted = fit_age(span, text, lang)
    if fitted is not None:
        if fitted.text == original and fitted.replacement == repl:
            return span, None
        return fitted, "fixed"
    age = age_of(original)
    if age is not None:
        # An age inside a longer phrase: the stated range must contain the value.
        ranges = stated_ranges(repl)
        if ranges and all(lo <= age <= hi for lo, hi in ranges) and _lang_ok(repl, lang, original):
            return span, None
        if ranges and _lang_ok(repl, lang, original):
            return _set(span, _swap_decades(repl, age, lang)), "fixed"
        if not _lang_ok(repl, lang, original):
            return _set(span, decade_phrase(age, lang)), "fixed"

    # Places: a named region must contain the original; place-only spans get a container.
    place = place_generalization(original, lang)
    if place is not None:
        if (
            repl
            and places_consistent(original, repl)
            and _lang_ok(repl, lang, original)
            and (regions.named_regions(repl))
        ):
            return span, None
        return _set(span, place), "fixed"
    if repl and not places_consistent(original, repl):
        return span, "rejected"

    if repl and not _lang_ok(repl, lang, original):
        if span.type == "HEALTH" and (cat := health_category(original, lang)):
            return _set(span, cat), "fixed"
        return span, "rejected"
    return span, None


_DOB_LABEL_BEFORE = re.compile(
    r"(?:생년월일|생일|출생(?:일|연도)?|\bDOB\b|\bD\.O\.B\.?|date of birth|birth\s*date|birthday)"
    r"\s*(?:is|was|:|：|-|=)?\s*$",
    re.IGNORECASE,
)


def _fit_birth_decade(span: Span, text: str, year: int, lang: str) -> str:
    """ "born in the 1990s" fitted to its slot: after "born in" only "the 1990s" remains, after a
    label ("DOB:", "생년월일:") the decade alone ("the 1990s", "1990년대")."""
    phrase = birth_decade_phrase(year, lang)
    bounds = _span_bounds(span, text)
    if bounds is None:
        return phrase
    before = text[: bounds[0]]
    if _DOB_LABEL_BEFORE.search(before[-24:]):
        return f"{year // 10 * 10}년대" if lang == "ko" else f"the {year // 10 * 10}s"
    return dedupe_prefix(before, phrase)


def _fit_birth_year(span: Span, text: str, year: int, lang: str) -> Span | None:
    """A bare year in a birth slot ("born in 1992", "1992년생", "출생: 1992") as its decade.

    The span takes in a following "년생", so "1992년생" becomes "1990년대생" and not "1990년대년생".
    """
    bounds = _span_bounds(span, text)
    if bounds is None:
        return None
    start, end = bounds
    before, after = text[:start], text[end:]
    if m := _BIRTH_CUE_AFTER.match(after):
        end += m.end()
        return replace(
            span, text=text[start:end], start=start, end=end,
            replacement=birth_decade_phrase(year, "ko"), rule="entailed",
        )  # fmt: skip
    if not _BIRTH_CUE_BEFORE.search(before[-24:]):
        return None
    ko = lang == "ko" or bool(_HANGUL.search(before[-24:]))
    want = _fit_birth_decade(replace(span, start=start, end=end), text, year, "ko" if ko else "en")
    return replace(span, start=start, end=end, replacement=want, rule="entailed")


def _lang_ok(replacement: str, lang: str, original: str) -> bool:
    if lang == "ko" or _HANGUL.search(original):
        return bool(_HANGUL.search(replacement))
    return not _HANGUL.search(replacement)


def _set(span: Span, replacement: str) -> Span:
    return replace(span, replacement=replacement, rule="entailed")
