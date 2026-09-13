"""Surrogate substitution: realistic, format-preserving fake values instead of `<TYPE_N>` tokens.

With placeholders, about 16 baseline answers told the user that their own value "is a
placeholder" or could not be processed. Research on prompt privacy (PromptPET-style decoys)
favours plausible surrogates: the cloud model reads a normal-looking document and answers
normally, and nothing in the text says which values are fake. `AIRLOCK_SUBSTITUTION=surrogate`
enables it; the vault keeps the mapping and rehydration maps the surrogate back.

Rules:

* Only identity values get surrogates: PERSON, ORG, CONTACT, ID_NUMBER, FINANCIAL account and
  card numbers, and street addresses. Secrets and credentials always keep `<SECRET_N>`, and a
  value whose shape is not recognised (a declared term typed PERSON that is not a name) falls
  back to a placeholder.
* Korean names keep the syllable count and come from a curated pool that excludes public
  figures. English names keep the token count. Organizations keep their suffix type
  (`…물류`, `… Logistics`). Phones, emails, IDs, cards and accounts keep their shape but use
  reserved or invalid values: `010-0000-xxxx`, `@example.com`, an RRN with month 00, an SSN in
  area 000, a card that fails Luhn. Addresses keep the region and replace the street and numbers.
* Surrogates are consistent within a conversation or agent run (stored in the vault), drawn with
  a keyed hash (not predictable from the original), and checked for collisions against the
  request text, every other original and every other surrogate.
* Rehydration finds surrogates in the answer (also reformatted numbers and a name's first or last
  part alone), restores the original, and fixes the Korean particle after it (`새론다움물류과의` ->
  `새론다움물류와의`). English possessives carry over unchanged.
"""

from __future__ import annotations

import hashlib
import hmac
import random
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from airlock.detect.gliner import latin_name
from airlock.detect.ko_rules import _PUBLIC_FIGURES
from airlock.detect.spans import find_term, normalize

SURROGATE_TYPES = frozenset({"PERSON", "ORG", "CONTACT", "ID_NUMBER", "FINANCIAL", "LOCATION"})
MAX_ATTEMPTS = 16

# ---- pools ------------------------------------------------------------------------------------


def _words(block: str) -> list[str]:
    return block.split()


KO_SURNAMES = tuple(
    "김이박최정강조윤장임한오서신권황안송홍유전고문손배백허남심노하곽성차주우구민나진지엄채원천방"
)
KO_COMPOUND_SURNAMES = ("남궁", "선우", "독고", "황보", "제갈")
KO_GIVEN_2 = tuple(
    _words(
        """
        서연 민준 지우 하윤 도윤 서준 예은 시우 수아 지호 하은 준우 채원 은우 유나 건우 다은
        현우 소윤 지안 윤서 태윤 가은 민재 서아 준서 나연 시현 예린 도현 수빈 재윤 하린 이안
        유진 승민 채은 지환 서윤 연우 다인 은서 한결 세아 주원 소율 태린 예준 지유 로운 해솔
        윤아 도하 나은 시온 라희 이서
        """
    )
)
KO_GIVEN_1 = tuple(
    _words(
        """
        준 윤 현 진 솔 결 온 빈 율 담 란 휘 찬 훈 혁 은 연 원 슬 경
        """
    )
)
# Real public figures a surrogate must never be (in addition to ko_rules._PUBLIC_FIGURES).
_KO_EXCLUDED = _PUBLIC_FIGURES | frozenset(
    _words(
        """
        김민재 이강인 손흥민 김하성 이정후 유재석 이서진 김태리 박서준 한지민 윤아 김유정
        이도현 정해인 송강 김지원 박은빈 서현진 이준호 김수현 이하늬 박보검 김고은 한소희
        차은우 이지은 김민주 이재명 한동훈 조국 이준석 안철수 김건희 정은경 백종원 김연경
        이상화 황희찬 조규성
        """
    )
)
EN_FIRST = tuple(
    _words(
        """
        Avery Jordan Casey Morgan Riley Quinn Harper Rowan Emerson Parker Reese Hayden
        Dakota Skyler Elliot Marlowe Sawyer Blake Cameron Devon Ellis Finley Greer Hollis
        Jules Kendall Lane Micah Noel Oakley Peyton Reagan Sage Tatum Wren Arden Blair
        Carey Drew Emery Frankie Jamie Kai Logan Marley Oakes Remy Robin Rory Shawn Taylor
        """
    )
)
EN_LAST = tuple(
    _words(
        """
        Ashdown Brightwell Calloway Dunmore Everly Fairbanks Galloway Hartwell Ingleby
        Jessop Kettering Langford Marchetti Northam Oakridge Pembrook Quigley Rainsford
        Sutcliffe Thornbury Upton Vandermeer Whitcombe Yardley Ellsworth Carrow Delacroix
        Fenwick Gresham Holloway Ivers Kinsella Lockhart Merriwether Norcott Ostrander
        Prescott Radcliffe Selwyn Tolliver Ambrose Blackwood Crenshaw Dalby Eastman Faraday
        Garrick Huxley Kilbride Loxley
        """
    )
)
KO_ORG_STEMS = tuple(
    _words(
        """
        한결 가온 누리온 새빛 다온 라온 미르 온빛 해솔 도담 늘봄 이음 채움 두리 푸른솔
        빛나래 한울림 세움 별하 여울 은가람 늘해랑 새솔 다솜 가람 해온 한빛누리 초롱 온새미
        윤슬 마루온 너울 소담 하람
        """
    )
)
EN_ORG_STEMS = tuple(
    _words(
        """
        Larkmoor Tidewell Ashgrove Quillon Brambleton Marrowfield Stonereach Fernhaven
        Oakhollow Silverbirch Wrenfield Harborline Northwind Bellmere Copperfield Duskwood
        Elmstead Foxbourne Glenrock Hollowbrook Ironvale Juniper_Ridge Kestrel_Point
        Lindenhall Moorgate Nettleby Orchard_Bay Pinecrest Redwater Saltmarsh
        """
    )
)
KO_ORG_SUFFIXES = tuple(
    sorted(
        _words(
            """
            주식회사 저축은행 은행 병원 의원 대학교 학교 초등학교 중학교 고등학교 유치원 어린이집
            내과 연합내과 재단 협회 공사 그룹 물류 리테일 전자 제약 증권 보험 신협 새마을금고
            캐피탈 물산 상사 바이오 로지스틱스 로지스 정밀 솔루션즈 솔루션 소프트 테크 텍
            시스템즈 시스템 에너지솔루션 에너지 건설 산업 화학 식품 푸드 유통 법률사무소 법무법인
            회계법인 세무회계 컨설팅 디자인 엔터테인먼트 모빌리티 중공업 통신 네트웍스 랩 연구소
            클리닉 한의원 치과 약국 인터내셔널 코리아 파트너스 벤처스 홀딩스 미디어 스튜디오
            게임즈 헬스케어 메디컬 로보틱스 커머스
            """
        ),
        key=len,
        reverse=True,
    )
)
EN_ORG_SUFFIXES = tuple(
    sorted(
        [
            "Inc.", "Inc", "LLC", "Ltd.", "Ltd", "Corp.", "Corp", "Corporation", "Co.", "Company",
            "Systems", "Freight Systems", "Logistics", "Analytics", "Architects", "Associates",
            "Holdings", "Partners", "Labs", "Laboratories", "Technologies", "Solutions",
            "Industries", "Freight", "Pharmaceuticals", "Pharma", "Pharmacy Group", "Group", "Bank",
            "Credit Union", "Community Credit Union", "Capital", "Ventures", "Consulting",
            "Hospital", "Clinic", "Health", "Energy", "Foods", "Motors", "Manufacturing", "Studios",
            "Media", "Software", "Robotics", "Biotech", "Insurance", "Networks", "Dynamics",
            "Devices", "Therapeutics", "Outfitters", "University", "College", "School", "LLP",
            "Law Group", "Medical Center", "Harbour Logistics", "Harbor Logistics",
            "Semiconductors", "Semiconductor", "Electronics", "Retail", "Dental", "Pharmacy",
            "Aerospace", "Automotive", "Chemicals", "Textiles", "Publishing", "Airlines",
            "Shipping",
            "Construction", "Engineering", "Bakery", "Brewery", "Brewing", "Realty", "Legal",
            "Township", "Township Board", "Community Hospital", "Township Council",
        ],
        key=len,
        reverse=True,
    )
)  # fmt: skip
KO_ROADS = tuple(
    _words(
        """
        은빛로 새솔길 푸른숲로 한빛로 다온길 가람로 별하길 여울로 늘봄길 온새로 해솔길
        채움로
        """
    )
)
EN_STREETS = tuple(
    _words(
        """
        Juniper Alder Maplewood Kestrel Hawthorn Linden Briar Willowmere Foxglove Heron
        Sparrow Thistle Aspen Cobble Wren
        """
    )
)
EN_STREET_SUFFIX = (
    r"Street|St\.?|Lane|Ln\.?|Avenue|Ave\.?|Road|Rd\.?|Drive|Dr\.?|Boulevard|Blvd\.?|Way|Court|"
    r"Ct\.?|Place|Pl\.?|Terrace|Circle|Parkway|Pkwy"
)
_UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
_LOWER = "abcdefghjkmnpqrstuvwxyz"


# ---- generation ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class Known:
    """A mapping already in the session (original and its outbound value)."""

    original: str
    type: str
    outbound: str


def _rng(key: bytes, *parts: str) -> random.Random:
    digest = hmac.new(key, "\x00".join(parts).encode("utf-8"), hashlib.sha256).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


def _batchim(ch: str) -> int | None:
    """Final consonant index of a Hangul syllable (0 = none), None if not a syllable."""
    if "가" <= ch <= "힣":
        return (ord(ch) - 0xAC00) % 28
    return None


def _ko_name(rng: random.Random, syllables: int) -> str:
    if syllables >= 4:
        return rng.choice(KO_COMPOUND_SURNAMES) + rng.choice(KO_GIVEN_2)
    if syllables == 2:
        return rng.choice(KO_SURNAMES) + rng.choice(KO_GIVEN_1)
    return rng.choice(KO_SURNAMES) + rng.choice(KO_GIVEN_2)


_NOT_NAME_WORDS = frozenset(
    _words(
        """
        Project Team Operation Program Programme Initiative Plan Protocol Product Platform
        Service Contract Deal Account Fund Portfolio Campaign Codename Task Squad Group The
        """
    )
)


def _person(original: str, rng: random.Random, known: Sequence[Known]) -> str | None:
    t = original.strip()
    if re.fullmatch(r"[가-힣]{2,4}", t):
        if len(t) == 4 and not t.startswith(KO_COMPOUND_SURNAMES):
            return None
        if t[0] not in KO_SURNAMES and t[0] not in "황남제선독사서":
            return None
        for _ in range(8):
            name = _ko_name(rng, len(t))
            if name not in _KO_EXCLUDED and name != t:
                return name
        return None
    if not latin_name(t) or t.split()[0] in _NOT_NAME_WORDS:
        return None
    tokens = t.split()
    # Reuse the parts of a related name mapped earlier ("Jordan Albright", then "Albright").
    token_map: dict[str, str] = {}
    for k in known:
        if k.type != "PERSON" or not latin_name(k.original) or not latin_name(k.outbound):
            continue
        ko, kv = k.original.split(), k.outbound.split()
        if len(ko) == len(kv):
            token_map.update(zip(ko, kv, strict=True))
        elif len(kv) >= 1 and ko:
            token_map[ko[-1]] = kv[-1]
    out = []
    for i, token in enumerate(tokens):
        if token in token_map:
            out.append(token_map[token])
        elif re.fullmatch(r"[A-Z]\.", token):
            out.append(rng.choice(_UPPER) + ".")
        elif i == len(tokens) - 1 and (len(tokens) > 1 or token not in EN_FIRST):
            out.append(rng.choice(EN_LAST))
        else:
            out.append(rng.choice(EN_FIRST))
    name = " ".join(out)
    return None if normalize(name) == normalize(t) else name


def _org(original: str, rng: random.Random) -> str | None:
    t = original.strip()
    if re.search(r"[가-힣]", t):
        prefix = ""
        for mark in ("(주)", "㈜", "주식회사"):
            if t.startswith(mark):
                prefix, t = mark, t[len(mark) :].strip()
        tail = ""
        for mark in ("(주)", "㈜"):
            if t.endswith(mark):
                tail, t = mark, t[: -len(mark)].strip()
        suffix = next((s for s in KO_ORG_SUFFIXES if t.endswith(s) and len(t) > len(s)), None)
        if suffix is None:
            return None
        stem = rng.choice(KO_ORG_STEMS)
        sep = " " if f" {suffix}" in t else ""
        return f"{prefix}{' ' if prefix == '주식회사' else ''}{stem}{sep}{suffix}{tail}"
    suffix = next((s for s in EN_ORG_SUFFIXES if re.search(rf"(?:^|\s){re.escape(s)}$", t)), None)
    if suffix is None:
        return None
    stem_tokens = len(t[: -len(suffix)].split())
    stem = rng.choice(EN_ORG_STEMS).replace("_", " ")
    if stem_tokens >= 2 and " " not in stem:
        stem = f"{stem} {rng.choice(EN_STREETS)}"
    return f"{stem} {suffix}"


def _digits(rng: random.Random, n: int, first_nonzero: bool = False) -> str:
    out = [str(rng.randrange(10)) for _ in range(n)]
    if first_nonzero and out:
        out[0] = str(rng.randrange(1, 10))
    return "".join(out)


def _shape(original: str, rng: random.Random, keep_prefix: bool = True) -> str:
    """Same shape: letters and digits replaced; separators, Hangul and a short prefix kept."""
    t = original
    keep = 0
    m = re.match(r"^(?:[A-Z]{1,5}-|(?:19|20)\d{2}(?=[가-힣])|[A-Z]{2,5}(?=\d))", t)
    if keep_prefix and m:
        keep = m.end()
    out = list(t[:keep])
    for ch in t[keep:]:
        if ch.isdigit():
            out.append(str(rng.randrange(10)))
        elif "A" <= ch <= "Z":
            out.append(rng.choice(_UPPER))
        elif "a" <= ch <= "z":
            out.append(rng.choice(_LOWER))
        else:
            out.append(ch)
    return "".join(out)


def _keep_last_digits(value: str, original: str, n: int) -> str:
    want = re.sub(r"\D", "", original)[-n:]
    out = list(value)
    positions = [i for i, ch in enumerate(out) if ch.isdigit()][-n:]
    for i, d in zip(positions, want, strict=True):
        out[i] = d
    return "".join(out)


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _contact(original: str, rng: random.Random) -> str | None:
    t = original.strip()
    m = re.fullmatch(r"([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", t)
    if m:
        first, last = rng.choice(EN_FIRST).lower(), rng.choice(EN_LAST).lower()
        local = rng.choice((f"{first}.{last}", f"{first[0]}{last}", f"{first}{_digits(rng, 2)}"))
        return f"{local}@example.com"
    compact = re.sub(r"\D", "", t)
    kr = re.fullmatch(
        r"(\+82[\s-]?|0)(1[016789]|2|[3-6][1-5])([\s.)-]?)(\d{3,4})([\s.-]?)(\d{4})", t
    )
    if kr:
        lead, area, sep1, mid, sep2, _last = kr.groups()
        return f"{lead}{area}{sep1}{'0' * len(mid)}{sep2}{_digits(rng, 4, True)}"
    us = re.fullmatch(r"(\+?1[\s.-]?)?(\(?)(\d{3})(\)?[\s.-]?)(\d{3})([\s.-]?)(\d{4})", t)
    if us:
        cc, op, area, sep1, _ex, sep2, _line = us.groups()
        return f"{cc or ''}{op}{area}{sep1}555{sep2}01{_digits(rng, 2)}"
    if t.startswith("+") and 8 <= len(compact) <= 15:
        head = re.match(r"\+\d{1,3}[\s.-]?", t)
        keep = head.end() if head else 1
        body = re.sub(r"\d", lambda _m: "0", t[keep:])
        return t[:keep] + body[:-4] + _digits(rng, 4, True) if len(body) > 4 else None
    return None


def _id_number(original: str, rng: random.Random) -> str | None:
    t = original.strip()
    rrn = re.fullmatch(r"(\d{2})(\d{2})(\d{2})(-?)([1-8])(\d{6})", t)
    if rrn:
        # Month 00 is not a date: never a valid resident registration number.
        sep, gender = rrn.group(4), rng.randrange(1, 5)
        return f"{_digits(rng, 2)}00{_digits(rng, 2)}{sep}{gender}{_digits(rng, 6)}"
    ssn = re.fullmatch(r"\d{3}([\s-]?)\d{2}([\s-]?)\d{4}", t)
    if ssn:
        return f"000{ssn.group(1)}{_digits(rng, 2)}{ssn.group(2)}{_digits(rng, 4)}"
    if not re.search(r"\d", t) or len(re.sub(r"[\W_]", "", t)) < 4:
        return None
    if re.search(r"[가-힣]", t) and not re.fullmatch(r"(?:19|20)\d{2}\s?[가-힣]{1,2}\s?\d{2,7}", t):
        return None
    return _shape(t, rng)


def _financial(original: str, rng: random.Random) -> str | None:
    t = original.strip()
    compact = re.sub(r"[\s-]", "", t)
    iban = re.fullmatch(r"([A-Z]{2})(\d{2})([A-Z0-9]{8,30})", compact)
    if iban:
        body = _shape(t[4:], rng, keep_prefix=False)
        return f"{iban.group(1)}00{body}"  # check digits 00 are never valid
    if not re.fullmatch(r"[\d\s-]{6,40}", t) or len(compact) < 6:
        return None
    card = 13 <= len(re.sub(r"\D", "", t)) <= 19
    for _ in range(10):
        value = re.sub(r"\d", lambda _m: str(rng.randrange(10)), t)
        if card:
            # Keep the last four digits (displayable under PCI DSS): an answer that says "the card
            # ending in 7109" must stay true after rehydration.
            value = _keep_last_digits(value, t, 4)
        digits = re.sub(r"\D", "", value)
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            continue  # a surrogate card number must fail Luhn
        if digits[0] == "0" and len(digits) >= 10:
            value = re.sub(r"\d", str(rng.randrange(1, 10)), value, count=1)
            if 13 <= len(digits) <= 19 and _luhn_ok(re.sub(r"\D", "", value)):
                continue
        return value
    return None


_KO_ADDR = re.compile(
    r"^(?P<region>(?:[가-힣]+(?:특별시|광역시|특별자치시|특별자치도|도|시|군|구|읍|면)\s+)+)"
    r"(?P<road>[가-힣0-9]+(?:로|길))\s*(?P<num>\d{1,5}(?:-\d{1,4})?)(?P<rest>.*)$"
)
_KO_JIBUN = re.compile(
    r"^(?P<region>(?:[가-힣]+(?:특별시|광역시|특별자치시|특별자치도|도|시|군|구|읍|면)\s+)+)"
    r"(?P<dong>[가-힣0-9]+(?:동|리|가))\s+(?P<num>\d{1,5}(?:-\d{1,4})?)(?P<rest>.*)$"
)
_EN_ADDR = re.compile(
    rf"^(?P<num>\d{{1,6}})\s+(?P<street>(?:[A-Z][A-Za-z'’.-]*\s+){{1,3}})(?P<suffix>{EN_STREET_SUFFIX})"
    r"(?P<rest>.*)$"
)


def _location(original: str, rng: random.Random) -> str | None:
    t = original.strip()
    for pattern in (_KO_ADDR, _KO_JIBUN):
        m = pattern.match(t)
        if m:
            rest = re.sub(r"\d+", lambda d: _digits(rng, len(d.group()), True), m.group("rest"))
            if "road" in m.groupdict() and m.group("road"):
                road = rng.choice([r for r in KO_ROADS if r != m.group("road")])
            else:
                road = m.group("dong")
            return f"{m.group('region')}{road} {rng.randrange(1, 200)}{rest}"
    m = _EN_ADDR.match(t)
    if m:
        rest = m.group("rest")
        unit = re.sub(
            r"(?i)(unit|apt\.?|apartment|suite|#)\s*[\w-]+",
            lambda u: f"{u.group(1)} {rng.randrange(1, 30)}{rng.choice('ABCD')}",
            rest,
        )
        return f"{rng.randrange(10, 9900)} {rng.choice(EN_STREETS)} {m.group('suffix')}{unit}"
    m = re.fullmatch(r"(?i)(unit|apt\.?|apartment|suite|#)\s*([\w-]+)", t)
    if m:
        return f"{m.group(1)} {rng.randrange(1, 30)}{rng.choice('ABCD')}"
    return None


_GENERATORS: dict[str, Callable[..., str | None]] = {
    "ORG": _org,
    "CONTACT": _contact,
    "ID_NUMBER": _id_number,
    "FINANCIAL": _financial,
    "LOCATION": _location,
}


def generate(
    original: str,
    type_: str,
    *,
    key: bytes,
    scope: str,
    taken: Callable[[str], bool],
    known: Sequence[Known] = (),
) -> str | None:
    """A surrogate for `original`, or None (the caller uses a placeholder).

    `taken(value)` returns True when the value collides with the request text, another
    original or another surrogate.
    """
    if type_ not in SURROGATE_TYPES:
        return None
    for attempt in range(MAX_ATTEMPTS):
        rng = _rng(key, scope, type_, normalize(original), str(attempt))
        if type_ == "PERSON":
            value = _person(original, rng, known)
        else:
            value = _GENERATORS[type_](original, rng)
        if value is None:
            return None
        if any(c in value for c in '"\\<>') or normalize(value) == normalize(original):
            continue
        if not taken(value):
            return value
    return None


def collides(
    value: str, texts: Iterable[str], originals: Iterable[str], outbound: Iterable[str]
) -> bool:
    """The surrogate occurs in the request, contains an original, or equals another surrogate."""
    norm = normalize(value)
    if any(norm == normalize(o) for o in outbound):
        return True
    if any(find_term(t, value) for t in texts):
        return True
    return any(len(o.strip()) >= 2 and find_term(value, o) for o in originals)


# ---- rehydration -------------------------------------------------------------------------------

# (form after a final consonant, form after a vowel); ㄹ-final takes the vowel form of 으로.
_PARTICLE_PAIRS: tuple[tuple[str, str], ...] = (
    ("이라고", "라고"), ("이라는", "라는"), ("이라서", "라서"),
    ("이었다", "였다"), ("이었고", "였고"), ("이에요", "예요"),
    ("이랑", "랑"), ("이나", "나"), ("이며", "며"), ("이고", "고"), ("이야", "야"),
    ("으로", "로"), ("과", "와"), ("은", "는"), ("을", "를"), ("이", "가"), ("아", "야"),
)  # fmt: skip
_PARTICLE_CONT = ("의", "는", "도", "만", "서", "써", "부터", "")


def fix_particle(original: str, following: str) -> tuple[int, str] | None:
    """(length to replace, corrected particle) for the particle right after `original`."""
    last = original.rstrip()[-1:]
    b = _batchim(last)
    if b is None:
        digit_finals = {"0": 21, "1": 8, "3": 16, "6": 1, "7": 8, "8": 8}
        if last.isdigit():
            b = digit_finals.get(last, 0)
        else:
            return None
    for consonant, vowel in _PARTICLE_PAIRS:
        for cont in _PARTICLE_CONT:
            for form in (consonant, vowel):
                token = form + cont
                if not following.startswith(token):
                    continue
                nxt = following[len(token) : len(token) + 1]
                if nxt and "가" <= nxt <= "힣":
                    continue
                if consonant == "으로":
                    want = vowel if b in (0, 8) else consonant
                else:
                    want = consonant if b else vowel
                return len(form), want
    return None


@dataclass(frozen=True)
class Alias:
    surrogate: str
    original: str
    part: bool = False  # a name's first or last token, or an organization without its suffix


def aliases(pairs: Iterable[tuple[str, str, str]]) -> list[Alias]:
    """(surrogate, original, type) -> surrogates to look for, longest first, with name parts."""
    out = [Alias(s, o) for s, o, _ in pairs]
    seen = {normalize(a.surrogate) for a in out}
    for s, o, t in pairs:
        if t != "PERSON":
            continue
        st, ot = s.split(), o.split()
        if len(st) >= 2 and len(st) == len(ot):
            for sp, op in ((st[-1], ot[-1]), (st[0], ot[0])):
                if len(sp) >= 3 and normalize(sp) not in seen:
                    seen.add(normalize(sp))
                    out.append(Alias(sp, op, part=True))
    for s, o, t in pairs:
        if t != "ORG":
            continue
        # "Duskwood Foxglove Clinic" written as "Duskwood Foxglove": the stem maps to the stem.
        for suffixes in (EN_ORG_SUFFIXES, KO_ORG_SUFFIXES):
            suffix = next((x for x in suffixes if s.endswith(x) and o.endswith(x)), None)
            if suffix is None:
                continue
            ss, os_ = s[: -len(suffix)].strip(), o[: -len(suffix)].strip()
            long_enough = len(ss) >= 3 if re.search(r"[가-힣]", ss) else len(ss) >= 4
            if ss and os_ and long_enough and normalize(ss) not in seen:
                seen.add(normalize(ss))
                out.append(Alias(ss, os_, part=True))
            break
    return sorted(out, key=lambda a: -len(a.surrogate))


def rehydrate(
    text: str, pairs: Sequence[tuple[str, str, str]], transform: Callable[[str], str] = str
) -> str:
    """Replace every surrogate in `text` by its original; fix Korean particles after it."""
    if not pairs or not text:
        return text
    found: list[tuple[int, int, Alias]] = []
    for alias in aliases(pairs):
        for start, end in find_term(text, alias.surrogate):
            if alias.part and re.search(r"[가-힣]", alias.surrogate) and len(alias.surrogate) < 3:
                continue
            if any(start < e and s < end for s, e, _ in found):
                continue
            found.append((start, end, alias))
    if not found:
        return text
    out: list[str] = []
    cursor = 0
    for start, end, alias in sorted(found, key=lambda f: f[0]):
        if start < cursor:
            continue
        out.append(text[cursor:start])
        out.append(transform(alias.original))
        cursor = end
        fix = fix_particle(alias.original, text[end : end + 4])
        if fix is not None:
            length, particle = fix
            out.append(particle)
            cursor = end + length
    out.append(text[cursor:])
    return "".join(out)


def pending_tail(buffer: str, surrogates: Sequence[str], max_particle: int = 3) -> int:
    """How many trailing characters of a stream buffer may still become (part of) a surrogate.

    A tail that is a prefix of a surrogate, or a whole surrogate followed by up to
    `max_particle` Hangul characters (the particle may still change), is held back.
    """
    hold = 0
    folded = buffer.casefold()
    for s in surrogates:
        sf = s.casefold()
        for k in range(min(len(folded), len(sf) + max_particle), 0, -1):
            tail = folded[-k:]
            if sf.startswith(tail) or (
                tail.startswith(sf) and re.fullmatch(r"[가-힣]*", tail[len(sf) :] or "")
            ):
                hold = max(hold, k)
                break
    return hold
