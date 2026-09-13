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


def age_from_birth(born: date, today: date | None = None) -> int:
    today = today or date.today()
    return today.year - born.year - ((today.month, today.day) < (born.month, born.day))


def decade_phrase(age: int, lang: str) -> str:
    decade = age // 10 * 10
    if lang == "ko":
        return "10대" if decade == 10 else f"{decade}대" if decade else "10세 미만"
    return f"in their {decade}s" if decade >= 10 else "under 10"


def birth_decade_phrase(year: int, lang: str) -> str:
    decade = year // 10 * 10
    return f"{decade}년대생" if lang == "ko" else f"born in the {decade}s"


_KO_DECADE = re.compile(r"(\d)0\s*대")
_EN_DECADE = re.compile(
    r"(?<!\d)(\d)0\s*'?s\b|\b(twenties|thirties|forties|fifties|sixties|seventies|eighties|nineties)\b",
    re.IGNORECASE,
)  # noqa: E501
_EN_DECADE_WORDS = {"twenties": 20, "thirties": 30, "forties": 40, "fifties": 50, "sixties": 60,
                    "seventies": 70, "eighties": 80, "nineties": 90}  # fmt: skip
_RANGE = re.compile(r"(?<!\d)(\d{1,3})\s*(?:-|~|–|to|에서)\s*(\d{1,3})(?!\d)")


def stated_ranges(replacement: str) -> list[tuple[int, int]]:
    """Age ranges a replacement states: "40대" (40-49), "mid-40s", "35-44"."""
    out = []
    for m in _KO_DECADE.finditer(replacement):
        lo = int(m.group(1)) * 10
        out.append((lo, lo + 9))
    for m in _EN_DECADE.finditer(replacement):
        lo = int(m.group(1)) * 10 if m.group(1) else _EN_DECADE_WORDS[m.group(2).lower()]
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


def _money(t: str) -> bool:
    if _MONEY.match(t):
        return True
    m = _LABELED_MONEY.match(t)
    if m and _MONEY.match(m.group("amount").strip()):
        return True
    # "90 days overdue, $46,500", "90일째 안 주고 있어(4,650만원)": an amount inside a short
    # phrase, with no other number that could be an account.
    if len(t) > 48 or not _MONEY_INNER.search(t):
        return False
    rest = _DURATION_INNER.sub(" ", _MONEY_INNER.sub(" ", t))
    return not re.search(r"\d", rest)


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

    # Birth dates and birth years: say the birth decade.
    if DOB_CUE.search(original) or (
        date_in(original) and is_birth_date(text, span.start, span.end, original)
    ):
        year = birth_year(original)
        if year:
            want = birth_decade_phrase(year, lang)
            return (span if repl == want else _set(span, want)), (None if repl == want else "fixed")
    if date_in(original) and (d := date_in(original)) is not None:
        age = age_from_birth(d)
        if not any(lo <= age <= hi for lo, hi in stated_ranges(repl)) and stated_ranges(repl):
            return _set(span, decade_phrase(age, lang)), "fixed"

    # Ages: the stated range must contain the value.
    age = age_of(original)
    if age is not None:
        ranges = stated_ranges(repl)
        if ranges and all(lo <= age <= hi for lo, hi in ranges) and _lang_ok(repl, lang, original):
            return span, None
        age_only = (
            re.fullmatch(r"\s*(?:만\s*)?(?:올해\s*)?[\w\s\-']{0,14}\s*", original)
            and len(original) <= 24
        )
        if ranges and _lang_ok(repl, lang, original):
            return _set(span, _swap_decades(repl, age, lang)), "fixed"
        if age_only or not _lang_ok(repl, lang, original):
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


def _lang_ok(replacement: str, lang: str, original: str) -> bool:
    if lang == "ko" or _HANGUL.search(original):
        return bool(_HANGUL.search(replacement))
    return not _HANGUL.search(replacement)


def _set(span: Span, replacement: str) -> Span:
    return replace(span, replacement=replacement, rule="entailed")
