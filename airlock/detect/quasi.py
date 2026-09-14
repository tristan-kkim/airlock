"""Quasi-identifier combinations: a k-anonymity-style scorer over the attributes of one message.

In the final measurement every remaining linkable disclosure was a quasi-identifier prompt. Each
attribute looked harmless on its own and was kept as situation (a role, a cohort year, a small
town, a rank), and the attacker returned the combination verbatim:
`달무리도 보건의료원의 유일한 산부인과 전문의(여, 41세)`, `2022년 행정고시 재경직 수석`,
`the only Korean-speaking pediatric cardiologist in Merrow Falls, Idaho`.

This module finds attributes in seven categories with deterministic lexicons and patterns:

| Category | Examples | Coarsened to |
|---|---|---|
| place | 달무리도, 가온시, 연수구, Merrow Falls, Idaho | a containing region or kind of place |
| org | 새벽별리버뷰 아파트, 누리별함, Tillbrook High | the kind of institution |
| cohort | 2022년 행정고시, 06학번, class of 2011 | the decade |
| rare | 수석, 은메달리스트, 75kg급, twin, the only | a band ("상위권", "입상자"), or kept |
| role | 산부인과 전문의, 5급 사무관, pediatric cardiologist | the profession (의사, physician) |
| age | 41세, 마흔다섯, 52-year-old, I'm 29 | the decade |
| family | 한부모, 삼남매, single mom | kept (counted only) |

The score of a message is the sum, over categories, of the weight of its most specific attribute
that is still in the outbound text (not masked or generalized by another detector): a fine place,
a named institution, a cohort and a rare fact weigh 2, a role, an age and a family structure 1.
Categories count once, so a district and the apartment complex inside it are one place. When the
score reaches k (3 at `balanced`, 2 at `strict`; `minimal` keeps quasi-identifiers), attributes
are coarsened, most identifying first, until the score is below k. Coarsening is deterministic
and entailed by the original (small town -> province, cohort year -> decade, specialty -> the
profession), so the task keeps its facts at a coarser grain instead of losing them to a mask.

Two guards keep ordinary text untouched and keep the task:

* **Subject.** Only a message about a private person scores: first person or a relative, a
  Korean self-description ending right after an attribute (`사무관이고`, `체육교사야`), or a
  request for anonymity. Roles of other people (`원장 갑질`, `my sergeant's retaliation`) are
  not the subject's attributes.
* **Task relevance.** An attribute whose content word appears elsewhere in the message outside
  every attribute (the question is about it) is never coarsened.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from airlock import generalize
from airlock.config import ProtectionLevel
from airlock.detect import regions
from airlock.detect.spans import Span, locate

WEIGHTS = {"place": 2, "org": 2, "cohort": 2, "rare": 2, "role": 1, "age": 1, "family": 1}
# Coarsening order among equal weights: the categories least likely to be the task come first.
_ORDER = ("place", "org", "cohort", "rare", "age", "role", "family")
K_BY_LEVEL = {ProtectionLevel.BALANCED: 3, ProtectionLevel.STRICT: 2}


@dataclass(frozen=True)
class Attribute:
    start: int
    end: int
    category: str
    ko: str | None  # coarsened phrase for Korean text; None: counted, never coarsened
    en: str | None
    rule: str
    weight: int | None = None  # overrides the category weight

    @property
    def score(self) -> int:
        return WEIGHTS[self.category] if self.weight is None else self.weight

    def coarse(self, lang: str) -> str | None:
        return self.ko if lang == "ko" else self.en


def _words(block: str) -> list[str]:
    return block.split()


def _alt(words: Sequence[str]) -> str:
    return "|".join(re.escape(w) for w in sorted(words, key=len, reverse=True))


_KO_TAIL = (
    r"(?=(?:이었고|이었어|이었는데|였고|였어|였는데|이고|인데|이야|이며|입니다|이에요|예요|에서|에게|"
    r"으로|이|가|은|는|을|를|의|과|와|도|로|에|고|야)?(?![가-힣A-Za-z0-9]))"
)
# Endings that describe the subject right after an attribute.
_KO_SELF = re.compile(
    r"^\s?(?:\(|,|이었고|이었어|이었는데|였고|였어|였는데|이고|인데|이야|이며|입니다|이에요|예요|고\s|야\b|야$|"
    r"출신)"
)
_KO_PERSON = re.compile(
    r"(?<![가-힣])(?:저는|저도|제가|저의|저희|제|내가|나는|난|내|우리|본인)(?=\s|$)"
    r"|(?:엄마|어머니|아빠|아버지|남편|아내|와이프|아들|딸|오빠|언니|누나|동생|할머니|할아버지|부모님|"
    r"부부)(?=께서|가|이|는|은|의|를|을|도|랑|와|과|한테|에게|고|야|인데|\s|$|\()"
)
_EN_PERSON = re.compile(
    r"\b(?:I|I'm|I've|I'd|me|my|we|our)\b|\b(?:dad|mom|father|mother|wife|husband|son|daughter|"
    r"brother|sister|partner)\b",
    re.IGNORECASE,
)
_ANONYMITY = re.compile(
    r"익명|티\s?안\s?나|못\s?알아보|신원|이름은\s?빼|anonymous|anonymously|without naming|"
    r"can't be traced|cannot be traced|not be traced|keep me anonymous|identify me",
    re.IGNORECASE,
)

# ---- places ----------------------------------------------------------------------------------

_KO_TOP_ALIASES = sorted(
    {alias for aliases in regions.KO_TOP.values() for alias in aliases}, key=len, reverse=True
)
_KO_PLACE_STOP = frozenset(
    _words(
        """
        도시 당시 동시 역시 표시 지시 즉시 수시 임시 잠시 필요시 비상시 평상시 유사시 사용시 발생시
        연구 친구 도구 가구 입구 출구 요구 지구 욕구 탐구 공구 기구 전구 항구 소구 선구
        활동 운동 행동 이동 노동 자동 공동 변동 감동 작동 충동 연동 가동 소동 진동 출동 발동 부동
        정도 온도 속도 제도 태도 지도 시도 의도 용도 각도 강도 밀도 농도 습도 인도 보도 복도 포도
        효도 기도 부도 난이도 만족도 신뢰도 선호도 인지도 완성도 정확도 민감도 중요도 참여도 기여도
        집중도 활용도 해상도 적합도 우리 이곳 저곳 그곳 어느 한
        """
    )
)
_KO_PLACE_NOUN = {"시": "한 도시", "군": "한 군 지역", "구": "한 자치구", "동": "한 동네",
                  "읍": "한 읍 지역", "면": "한 면 지역", "리": "한 마을", "마을": "한 마을",
                  "도": "한 섬"}  # fmt: skip
# What follows a place name when it is where someone lives or works.
_KO_PLACE_CONTEXT = (
    r"(?:의|에서|에|에서도)?\s?(?:보건의료원|보건지소|보건소|의료원|초등학교|중학교|고등학교|분교|"
    r"주민센터|파출소|지구대|우체국|아파트|마을|시청|군청|구청|살|사는|거주|근무|출신|주민|토박이|"
    r"농사|어촌|섬마을)"
)
_KO_QUALIFIED_PLACE = re.compile(
    rf"(?<![가-힣])(?P<top>{_alt(_KO_TOP_ALIASES)})\s+"
    r"(?P<place>(?P<stem>[가-힣]{1,6}?)(?P<suffix>시|군|구|동|읍|면|리|마을))" + _KO_TAIL
)
_KO_CONTEXT_PLACE = re.compile(
    r"(?<![가-힣])(?P<place>(?P<stem>[가-힣]{2,5}?)(?P<suffix>시|군|구|동|도))"
    rf"(?={_KO_PLACE_CONTEXT})"
)


def _ko_place_weight(place: str) -> int:
    parent = regions.KO_PARENT.get(place)
    if parent is None:
        return 2  # a small or unlisted place
    return 0 if place.endswith("시") or place in regions.KO_PARENT and len(place) <= 2 else 1


def _ko_places(text: str) -> list[Attribute]:
    out: list[Attribute] = []
    for m in _KO_QUALIFIED_PLACE.finditer(text):
        place, stem, suffix = m.group("place"), m.group("stem"), m.group("suffix")
        if place in _KO_PLACE_STOP or stem in _KO_TOP_ALIASES or len(place) < 2:
            continue
        weight = _ko_place_weight(place)
        if not weight:
            continue
        top = m.group("top")
        noun = _KO_PLACE_NOUN[suffix]
        ko = top if weight == 1 else f"{top}의 {noun}"
        top_en = regions.ko_container(top) or "Korea"
        out.append(Attribute(m.start(), m.end("place"), "place", ko, f"a town in {top_en}",
                             "ko_place", weight))  # fmt: skip
    for m in _KO_CONTEXT_PLACE.finditer(text):
        place, stem, suffix = m.group("place"), m.group("stem"), m.group("suffix")
        if place in _KO_PLACE_STOP or place in _KO_TOP_ALIASES or stem in _KO_TOP_ALIASES:
            continue
        if suffix == "도" and (len(stem) < 2 or place in regions.KO_TOP):
            continue
        weight = _ko_place_weight(place)
        if not weight:
            continue
        parent = regions.KO_PARENT.get(place)
        ko = parent if parent and weight == 1 else _KO_PLACE_NOUN[suffix]
        out.append(Attribute(m.start(), m.end("place"), "place", ko, "a town", "ko_place", weight))
    return out


_EN_PLACE_KIND = (
    r"Township|County|Village|Borough|Parish|Falls|Springs|Heights|Harbor|Harbour|Hills|Creek|"
    r"Valley|Junction|Flats|Crossing|Ridge|Point|Bay|Beach|Grove|Lake|Mills|Hollow|Bluffs"
)
_EN_CAP = r"[A-Z][\w'’\-]*"
_EN_STATES = sorted(regions.EN_REGIONS | set(regions.US_STATE_CODES), key=len, reverse=True)
_EN_TOWN_STATE = re.compile(
    rf"(?P<town>(?:{_EN_CAP}[ \t]){{0,2}}{_EN_CAP}),[ \t]*(?P<state>{_alt(_EN_STATES)})\b"
)
_EN_NAMED_PLACE = re.compile(
    rf"\b(?:in|at|near|from|outside|of|born in)[ \t]+"
    rf"(?P<place>(?:{_EN_CAP}[ \t]){{0,2}}(?:{_EN_PLACE_KIND})"
    rf"|(?:Port|Fort|Mount|Lake)[ \t]{_EN_CAP})\b"
)
_EN_BORN_IN = re.compile(rf"\bborn in[ \t]+(?P<place>{_EN_CAP}(?:[ \t]{_EN_CAP})?)")
_EN_NOT_PLACE = frozenset(
    _words(
        """
        January February March April May June July August September October November December
        Monday Tuesday Wednesday Thursday Friday Saturday Sunday The A An My Our This That
        """
    )
)


def _en_places(text: str) -> list[Attribute]:
    out: list[Attribute] = []
    for m in _EN_TOWN_STATE.finditer(text):
        town = m.group("town")
        words = town.split()
        while words and words[0] in _EN_NOT_PLACE:
            words = words[1:]
        if not words or " ".join(words) in regions.EN_PARENT or " ".join(words) in _EN_STATES:
            continue
        start = m.start("town") + (len(town) - len(" ".join(words)))
        state = regions.US_STATE_CODES.get(m.group("state"), m.group("state"))
        out.append(Attribute(start, m.end("state"), "place", "한 지역", f"a town in {state}",
                             "en_town_state"))  # fmt: skip
    for m in _EN_NAMED_PLACE.finditer(text):
        place = m.group("place")
        kind = place.split()[-1]
        noun = {"Township": "a township", "County": "a county", "Parish": "a parish"}.get(
            kind, "a small town"
        )
        out.append(Attribute(m.start("place"), m.end("place"), "place", "한 지역", noun,
                             "en_named_place"))  # fmt: skip
    for m in _EN_BORN_IN.finditer(text):
        place = m.group("place")
        if place.split()[0] in _EN_NOT_PLACE or place in _EN_STATES:
            continue
        region = regions.EN_PARENT.get(place)
        en = f"a city in {region}" if region else "a city"
        out.append(Attribute(m.start("place"), m.end("place"), "place", "한 도시", en,
                             "en_birthplace"))  # fmt: skip
    return out


# ---- named institutions ----------------------------------------------------------------------

# Institution kind -> what a named one is coarsened to ("한 <kind>" unless listed).
_KO_INSTITUTIONS = {
    kind: f"한 {kind}"
    for kind in _words(
        """
        보건의료원 보건지소 보건소 의료원 교회 성당 초등학교 중학교 고등학교 분교 유치원 어린이집
        파출소 지구대 경찰서 소방서 우체국 주민센터 도서관 복지관 요양원 아파트 빌라 오피스텔 부대
        """
    )
} | {"성결교회": "한 교회", "함": "한 함정", "처": "한 정부 기관"}
_KO_INSTITUTION = re.compile(
    r"(?<![가-힣A-Za-z0-9])(?P<name>[가-힣A-Za-z0-9]{2,10}?)(?P<sep>\s?)"
    rf"(?P<kind>{_alt(list(_KO_INSTITUTIONS))})" + _KO_TAIL
)
_KO_INSTITUTION_STOP = frozenset(
    _words(
        """
        우리 저희 동네 근처 인근 옆 이 그 저 한 여러 같은 다른 해당 모든 새 큰 작은 대형 소형 시립
        국립 공립 사립 도립 군립 구립 지역 지방 임대 주공 행복주택 신축 구축 고급 오래된 거래 연락
        근무
        출 대 판매 사용 접수 문의 처리 보관 해결 거주 소속 담당 방문 공공 초등 중 고등 사회복지 노인
        요양 어린이 전체 일반 주변 가까운 유명한 서울 부산 대구 인천 광주 대전 울산 세종 경기 강원
        충북 충남 전북 전남 경북 경남 제주 해군 육군 공군 해병대 군 국방 포 기 합 조 전 특수
        """
    )
)


_KO_CLASS = re.compile(r"(?<!\d)(?P<grade>\d{1,2}\s?학년)\s?\d{1,2}\s?반(?![가-힣])")


# The size of a small group ("직원 12명인 스타트업", "a five-member planning commission").
_KO_HEADCOUNT = re.compile(
    r"(?<![가-힣])(?P<who>직원|팀원|구성원|회원|교인|학생|부원)\s?(?P<n>\d{1,3})\s?명"
)
_EN_NUMBER_WORDS = {
    w: n
    for n, w in enumerate(
        [
            "two",
            "three",
            "four",
            "five",
            "six",
            "seven",
            "eight",
            "nine",
            "ten",
            "eleven",
            "twelve",
        ],
        start=2,
    )
}
_EN_SMALL_GROUP = re.compile(
    rf"\b(?P<n>\d{{1,3}}|{_alt(list(_EN_NUMBER_WORDS))})-(?:member|person|people|employee|staff|"
    r"student|bed|seat)[ \t]+(?P<body>(?:[a-z][a-z\-]*[ \t]+){0,2}?"
    r"(?P<kind>commission|board|council|committee|team|company|firm|brewery|startup|practice|"
    r"clinic|office|department|unit|lab|crew|squad|band|school|church|congregation|restaurant|"
    r"shop|store|bakery|agency|nonprofit))\b"
)
_EN_GROUP_BAND = (
    dict.fromkeys(["commission", "board", "council"], "a local board")
    | dict.fromkeys(
        [
            "company",
            "firm",
            "brewery",
            "startup",
            "restaurant",
            "shop",
            "store",
            "bakery",
            "agency",
        ],
        "a small business",
    )
    | dict.fromkeys(["practice", "clinic"], "a medical practice")
    | dict.fromkeys(["church", "congregation"], "a congregation")
    | {"committee": "a committee", "nonprofit": "a nonprofit", "school": "a small school"}
)


def _headcount_band(n: int) -> str:
    return "10명 미만" if n < 10 else f"{n // 10 * 10}여 명"


def _groups(text: str) -> list[Attribute]:
    out = [
        Attribute(
            m.start("n"), m.end(), "org", _headcount_band(int(m.group("n"))), None, "ko_headcount"
        )  # fmt: skip
        for m in _KO_HEADCOUNT.finditer(text)
        if int(m.group("n")) < 100
    ]
    for m in _EN_SMALL_GROUP.finditer(text):
        n = m.group("n")
        size = int(n) if n.isdigit() else _EN_NUMBER_WORDS[n.lower()]
        if size >= 100:
            continue
        en = _EN_GROUP_BAND.get(m.group("kind"), "a small team")
        out.append(Attribute(m.start(), m.end(), "org", None, en, "en_small_group"))
    return out


def _ko_institutions(text: str) -> list[Attribute]:
    out = [
        Attribute(m.start(), m.end(), "org", m.group("grade"), None, "ko_school_class")
        for m in _KO_CLASS.finditer(text)
    ]
    for m in _KO_INSTITUTION.finditer(text):
        name, kind = m.group("name"), m.group("kind")
        if name in _KO_INSTITUTION_STOP or re.fullmatch(r"\d+", name):
            continue
        if m.group("sep") and (name[-1] in "은는이가을를의에도서로와과께" or len(name) < 2):
            continue  # "저는 초등학교 교사": a particle, not a name
        if kind in ("함", "처", "부대") and (m.group("sep") or len(name) < 3):
            continue  # "누리별함", "미래기반처": attached, a name of 3+ syllables
        if kind == "아파트" and name.endswith(("주공", "임대")):
            continue
        ko = _KO_INSTITUTIONS[kind]
        out.append(Attribute(m.start(), m.end("kind"), "org", ko, "a local institution",
                             "ko_institution"))  # fmt: skip
    return out


_EN_INSTITUTIONS = {
    "High School": "a high school",
    "High": "a high school",
    "Elementary School": "an elementary school",
    "Elementary": "an elementary school",
    "Middle School": "a middle school",
    "Academy": "a school",
    "Church": "a church",
    "Medical Center": "a hospital",
    "Hospital": "a hospital",
    "Clinic": "a clinic",
    "Library": "a library",
    "Precinct": "a precinct",
    "Air Force Base": "a military base",
    "Base": "a military base",
    "Apartments": "an apartment complex",
}
_EN_INSTITUTION = re.compile(
    rf"(?P<name>(?:{_EN_CAP}[ \t]){{1,3}})(?P<kind>{_alt(list(_EN_INSTITUTIONS))})\b"
    r"|(?P<camp>\b(?:Camp|Fort)[ \t][A-Z][a-z]+\b)"
    r"|(?P<unit>\b\d+(?:st|nd|rd|th)[ \t](?:[A-Z][a-z]+[ \t]){0,3}"
    r"(?:Company|Battalion|Squadron|Brigade|Regiment|Wing|Platoon)\b)"
)
_EN_INSTITUTION_STOP = frozenset(
    _words(
        """
        The A An Our My Their Your His Her This That Every Each Local Public Private State National
        Community Regional General Children's Harvard Stanford Yale Princeton Mayo Cleveland Johns
        """
    )
)


def _en_institutions(text: str) -> list[Attribute]:
    out = []
    for m in _EN_INSTITUTION.finditer(text):
        if m.group("camp"):
            out.append(Attribute(m.start(), m.end(), "org", "한 군부대", "a military base",
                                 "en_institution"))  # fmt: skip
            continue
        if m.group("unit"):
            out.append(Attribute(m.start(), m.end(), "org", "한 부대", "a military unit",
                                 "en_institution"))  # fmt: skip
            continue
        words = m.group("name").split()
        start = m.start("name")
        while words and words[0] in _EN_INSTITUTION_STOP:
            start = text.index(words[1], start) if len(words) > 1 else start
            words = words[1:]
        if not words:
            continue
        en = _EN_INSTITUTIONS[m.group("kind")]
        out.append(Attribute(start, m.end("kind"), "org", "한 기관", en, "en_institution"))
    return out


# ---- roles -----------------------------------------------------------------------------------

_KO_ROLE_BANDS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("전문의", "의사", "치과의사", "한의사", "전공의", "레지던트"), "의사"),
    (("수간호사", "간호사", "간호조무사", "조산사"), "의료인"),
    (("교사", "교감", "교장", "강사", "교수", "부교수", "조교수", "정교수"), "교원"),
    (("사무관", "서기관", "주무관", "행정관", "이사관", "부이사관", "공무원"), "공무원"),
    (
        ("부사관", "장교", "하사", "중사", "원사", "소위", "중위", "대위", "소령", "중령", "대령"),
        "군인",
    ),
    (("변호사", "판사", "법무사", "변리사"), "법조인"),
    (("목사", "전도사", "신부", "수녀", "스님", "장로"), "종교인"),
    (("관리사무소장", "관리소장", "경비원"), "관리 직원"),
    (("CTO", "CEO", "CFO", "COO", "대표이사", "부사장", "전무", "상무"), "임원"),
    (("선수", "코치"), "체육인"),
    (("기자", "아나운서", "PD"), "언론인"),
    (("박사과정", "석사과정", "대학원생"), "대학원생"),
    (("회계사", "세무사", "노무사", "약사", "수의사"), "전문직"),
)
_KO_ROLE_BAND = {w: band for words, band in _KO_ROLE_BANDS for w in words}
KO_JOB_TITLES = frozenset(_KO_ROLE_BAND) | frozenset(
    _words(
        """
        선임연구원 책임연구원 수석연구원 연구원 주임연구원 전임연구원 팀장 파트장 실장 부장 차장
        과장 대리 주임 사원 매니저 본부장 센터장 그룹장 지점장 사무장 원장 직함 직급 직책
        """
    )
)
_KO_ROLE = re.compile(
    r"(?<![가-힣A-Za-z])(?P<phrase>"
    r"(?:(?P<mod>[가-힣A-Za-z0-9]{1,8}(?:과|급|직|학과|전공)|전직|현직)\s?)?"
    rf"(?P<pre>[가-힣]{{0,3}}?)(?P<head>{_alt(list(_KO_ROLE_BAND))}))" + _KO_TAIL
)


def _ko_roles(text: str) -> list[Attribute]:
    out = []
    for m in _KO_ROLE.finditer(text):
        after = text[m.end() : m.end() + 6]
        if not _KO_SELF.match(after) and not re.match(r"^(?:이었|였|출신)", after):
            continue  # "원장 갑질", "지도교수 폭언": another person's role
        head, mod, pre = m.group("head"), m.group("mod") or "", m.group("pre")
        band = _KO_ROLE_BAND[head]
        if len(pre) == 1:
            continue  # "당기자" (let's pull), not a reporter
        former = "전직 " if "전직" in mod else ""
        ko = f"{former}{band}"
        if not (mod or pre) and head == band:
            continue  # "공무원", "의사" alone: already the band
        out.append(Attribute(m.start("phrase"), m.end("head"), "role", ko, None, "ko_role"))
    return out


_EN_ROLE_BANDS: tuple[tuple[tuple[str, ...], str], ...] = (
    (
        tuple(
            _words(
                """
                cardiologist oncologist surgeon physician doctor pediatrician psychiatrist
                neurologist dermatologist radiologist anesthesiologist obstetrician gynecologist
                urologist internist hospitalist
                """
            )
        ),
        "a physician",
    ),
    (("nurse",), "a nurse"),
    (("pharmacist",), "a pharmacist"),
    (("professor", "lecturer", "postdoc"), "a professor"),
    (("teacher",), "a teacher"),
    (("CFO", "CEO", "CTO", "COO", "CIO", "founder", "co-founder", "VP"), "an executive"),
    (("lawyer", "attorney", "paralegal", "judge", "prosecutor"), "a legal professional"),
    (("mechanic", "technician"), "a technician"),
    (("sergeant", "detective", "lieutenant", "firefighter"), "a public-safety worker"),
    (("goalkeeper", "quarterback", "pitcher", "striker"), "an athlete"),
    (("pilot", "captain"), "a pilot"),
    (("pastor", "priest", "rabbi", "imam", "chaplain"), "a member of the clergy"),
)
_EN_ROLE_BAND = {w: band for words, band in _EN_ROLE_BANDS for w in words}
_EN_ROLE = re.compile(rf"\b(?P<head>{_alt(list(_EN_ROLE_BAND))})s?\b")
_EN_MOD_STOP = frozenset(
    _words(
        """
        the a an my our his her their your only sole and or of at in on who is was as to for with
        by from i i'm am are be been being that this these those one first new every each any
        """
    )
)
_EN_OTHER_PERSON = re.compile(r"\b(?:my|our|his|her|their|your|a|the)\s+$", re.IGNORECASE)


def _en_roles(text: str) -> list[Attribute]:
    out = []
    for m in _EN_ROLE.finditer(text):
        head = m.group("head")
        start = m.start("head")
        mods: list[str] = []
        before = text[:start]
        chain = re.search(r"((?:[\w'’\-]+[ \t]){1,3})$", before[-60:])
        words = chain.group(1).split() if chain else []
        for w in reversed(words):
            if w.lower() in _EN_MOD_STOP or w[:1].isupper() and w not in ("ER", "ICU", "AP"):
                break
            mods.insert(0, w)
        if head == "captain" and not any(w.lower() in ("airline", "flight") for w in mods):
            continue  # a team or army captain
        if mods:
            start = start - len(" ".join(mods)) - 1
        if text[m.end() : m.end() + 2] in ("'s", "’s"):
            continue  # "my sergeant's retaliation"
        if (
            not mods
            and _EN_OTHER_PERSON.search(before[-8:])
            and not re.search(r"\b(?:I'm|I am|is|was|as)\s+(?:a|an|the)\s+$", before[-16:])
        ):
            continue
        band = _EN_ROLE_BAND[head]
        if any(mod.lower() in ("former", "retired", "ex") for mod in mods):
            band = band.replace("a ", "a former ", 1).replace("an ", "a former ", 1)
        out.append(Attribute(start, m.end("head"), "role", None, band, "en_role"))
    return out


# ---- cohorts ---------------------------------------------------------------------------------

_KO_COHORT_NOUNS = _words(
    """
    공채 공개채용 입사 입학 졸업 임용 행정고시 행시 사법시험 외무고시 입법고시 기술고시 수능 신입생
    등단 데뷔 창업 귀농 귀촌 전역 제대 합격 임관 수료
    """
)
_KO_COHORT = re.compile(
    r"(?<!\d)(?P<year>(?:19|20)\d{2})\s*년(?:도)?\s*(?:(?:상반기|하반기|신입|경력)\s*)?"
    rf"(?P<what>{_alt(_KO_COHORT_NOUNS)})"
    r"|(?<![\d가-힣])(?P<yy>\d{2})\s*학번"
)
_EN_COHORT = re.compile(
    r"\bclass of (?P<cls>(?:19|20)\d{2})\b"
    r"|\b(?P<verb>joined|hired|started|enrolled|graduated|retired|promoted)[ \t]+(?:in[ \t]+)?"
    r"(?:(?:January|February|March|April|May|June|July|August|September|October|November|"
    r"December)[ \t]+)?(?P<year>(?:19|20)\d{2})\b"
    r"|\b(?P<champ>(?:19|20)\d{2})[ \t]+(?P<event>(?:state|national|regional|world|conference|"
    r"league|district)[ \t]+champion(?:ship)?s?)\b"
)


def _ko_cohorts(text: str) -> list[Attribute]:
    out = []
    for m in _KO_COHORT.finditer(text):
        if m.group("yy"):
            yy = int(m.group("yy"))
            year = 1900 + yy if yy > 50 else 2000 + yy
            ko = f"{year // 10 * 10}년대 학번"
        else:
            ko = f"{int(m.group('year')) // 10 * 10}년대 {m.group('what')}"
        out.append(Attribute(m.start(), m.end(), "cohort", ko, None, "ko_cohort"))
    return out


def _en_cohorts(text: str) -> list[Attribute]:
    out = []
    for m in _EN_COHORT.finditer(text):
        if m.group("cls"):
            en = f"a class of the {int(m.group('cls')) // 10 * 10}s"
        elif m.group("verb"):
            en = f"{m.group('verb')} in the {int(m.group('year')) // 10 * 10}s"
        else:
            en = m.group("event")
        out.append(Attribute(m.start(), m.end(), "cohort", None, en, "en_cohort"))
    return out


# ---- rare facts ------------------------------------------------------------------------------

_COUNTRIES_KO = frozenset(
    _words(
        """
        몽골 베트남 중국 일본 미국 필리핀 우즈베키스탄 네팔 캄보디아 태국 인도네시아 러시아 미얀마
        스리랑카 파키스탄 방글라데시 카자흐스탄 키르기스스탄 인도 이란 이집트 나이지리아 가나 케냐
        에티오피아 브라질 페루 멕시코 캐나다 호주 영국 프랑스 독일 이탈리아 스페인 터키 튀르키예
        """
    )
)
_KO_RARE = re.compile(
    r"(?<![가-힣])(?P<rank>수석|차석)(?=이었|이었어|이었고|으로|이야|이고|입학|졸업|합격|\s|$|[,.])"
    r"|(?P<medal>[금은동]메달리스트|[금은동]메달|준우승자|우승자)"
    r"|(?<![\d.])(?P<wclass>\d{2,3}\s?kg\s?급)"
    r"|(?P<event>(?:제\s?\d{1,3}\s?회\s?)?[가-힣A-Za-z0-9]{2,10}배\s?[가-힣]{0,8}?"
    r"(?P<ekind>대회|선수권대회|선수권|리그|컵))"
    rf"|(?P<origin>(?:{_alt(sorted(_COUNTRIES_KO))})\s?출신)"
    r"|(?P<unique>유일한|유일하게|하나뿐인|단\s?한\s?명(?:뿐인|의|인)?|혼자만)"
    r"|(?P<twin>쌍둥이|세쌍둥이)"
    r"|(?P<migrant>귀농|귀촌|탈북민|새터민)"
)


def _ko_rare(text: str) -> list[Attribute]:
    out = []
    for m in _KO_RARE.finditer(text):
        kind = m.lastgroup if m.lastgroup != "ekind" else "event"
        if m.group("rank"):
            ko, en = "상위권", None
        elif m.group("medal"):
            ko, en = "입상자", None
        elif m.group("wclass"):
            ko, en = "한 체급", None
        elif m.group("event"):
            ko, en = f"한 {m.group('ekind')}", None
        elif m.group("origin"):
            ko, en = "외국 출신", None
        else:
            ko, en = None, None  # a uniqueness claim, a twin: counted, kept
        out.append(Attribute(m.start(), m.end(), "rare", ko, en, f"ko_rare_{kind}"))
    return out


_EN_RARE = re.compile(
    r"\b(?P<medal>(?:gold|silver|bronze)[ \t]+medal(?:ist)?|record[- ]holder|valedictorian)\b"
    r"|\b(?P<speaking>[A-Z][a-z]+-speaking)\b"
    r"|\b(?P<unique>(?:the|my|our|his|her)[ \t]+only|sole)\b"
    r"|\b(?P<twin>a twin|twins|triplets)\b"
    r"|\b(?P<hand>left-handed)\b"
)


def _en_rare(text: str) -> list[Attribute]:
    out = []
    for m in _EN_RARE.finditer(text):
        en = "a prize winner" if m.group("medal") else None
        out.append(Attribute(m.start(), m.end(), "rare", None, en, f"en_rare_{m.lastgroup}"))
    return out


# ---- ages and family -------------------------------------------------------------------------

_KO_AGE = re.compile(
    r"(?<![\d가-힣])(?:만\s?)?(?P<n>\d{1,2})\s?(?:세|살)(?![가-힣])"
    r"|(?<![가-힣])(?:올해\s?)?(?P<word>(?:스물|서른|마흔|쉰|예순|일흔|여든)"
    r"(?:하나|한|둘|두|셋|세|넷|네|다섯|여섯|일곱|여덟|아홉)?)(?:\s?살)?"
    r"(?=이야|이고|인데|이에요|입니다|이|야|\)|,|\s|$)"
    r"|(?<!\d)(?P<born>(?:19|20)?\d{2})\s?년생"
)
_EN_AGE = re.compile(
    r"\b(?P<old>(?P<n1>\d{2})-year-old)\b"
    r"|\b(?P<im>I'?m|I am)[ \t]+(?P<n2>\d{2})\b"
    r"(?![ \t]*(?:%|percent|years? (?:of|in)|kg|lbs|minutes|hours|days|weeks|months|miles|km))"
    r"|\b(?P<rel>dad|mom|father|mother|wife|husband|son|daughter|brother|sister|partner),[ \t]+"
    r"(?P<n3>\d{2}),"
    r"|\b(?P<pron>she|he)['’]s[ \t]+(?P<n4>\d{2})\b"
    r"(?![ \t]*(?:%|percent|kg|lbs|minutes|weeks|days))"
    r"|\bborn in (?P<year>(?:19|20)\d{2})\b"
)
_HIS = frozenset({"dad", "father", "husband", "son", "brother"})
_HER = frozenset({"mom", "mother", "wife", "daughter", "sister"})


def _ko_ages(text: str) -> list[Attribute]:
    out = []
    for m in _KO_AGE.finditer(text):
        if m.group("born"):
            yy = m.group("born")
            year = int(yy) if len(yy) == 4 else 1900 + int(yy) if int(yy) > 30 else 2000 + int(yy)
            ko = generalize.birth_decade_phrase(year, "ko")
        else:
            age = generalize.age_of(m.group())
            if not age:
                continue
            ko = generalize.decade_phrase(age, "ko")
        out.append(Attribute(m.start(), m.end(), "age", ko, None, "ko_age"))
    return out


def _en_ages(text: str) -> list[Attribute]:
    out = []
    for m in _EN_AGE.finditer(text):
        if m.group("old"):
            decade = int(m.group("n1")) // 10 * 10
            out.append(Attribute(m.start(), m.end(), "age", None, f"{decade}-something", "en_age"))
        elif m.group("im"):
            decade = int(m.group("n2")) // 10 * 10
            out.append(Attribute(m.start(), m.end(), "age", None,
                                 f"{m.group('im')} in my {decade}s", "en_age"))  # fmt: skip
        elif m.group("rel"):
            decade = int(m.group("n3")) // 10 * 10
            rel = m.group("rel").lower()
            pron = "his" if rel in _HIS else "her" if rel in _HER else "their"
            out.append(Attribute(m.start("n3"), m.end("n3"), "age", None,
                                 f"in {pron} {decade}s", "en_age"))  # fmt: skip
        elif m.group("pron"):
            decade = int(m.group("n4")) // 10 * 10
            pron = m.group("pron").lower()
            en = f"in {'her' if pron == 'she' else 'his'} {decade}s"
            out.append(Attribute(m.start("n4"), m.end("n4"), "age", None, en, "en_age"))
        else:
            decade = int(m.group("year")) // 10 * 10
            out.append(Attribute(m.start(), m.end(), "age", None, f"born in the {decade}s",
                                 "en_age"))  # fmt: skip
    return out


_FAMILY = re.compile(
    r"다둥이|삼남매|사남매|오남매|외동(?:딸|아들)?|한부모|싱글맘|싱글대디|미혼모|미혼부|입양아?"
    r"|조손가정"
    r"|\b(?:single (?:mom|mother|dad|father|parent)|only child|widow(?:ed|er)?|adoptive)\b"
)


def _family(text: str) -> list[Attribute]:
    return [
        Attribute(m.start(), m.end(), "family", None, None, "family")
        for m in _FAMILY.finditer(text)
    ]


# ---- scoring ---------------------------------------------------------------------------------


def attributes(text: str) -> list[Attribute]:
    """Every quasi-identifier attribute in `text`; nested attributes keep the longest."""
    found = (
        _ko_places(text) + _en_places(text) + _ko_institutions(text) + _en_institutions(text)
        + _ko_roles(text) + _en_roles(text) + _ko_cohorts(text) + _en_cohorts(text)
        + _ko_rare(text) + _en_rare(text) + _ko_ages(text) + _en_ages(text) + _family(text)
        + _groups(text)
    )  # fmt: skip
    found.sort(key=lambda a: (-(a.end - a.start), a.start))
    chosen: list[Attribute] = []
    for a in found:
        if any(a.start < c.end and c.start < a.end for c in chosen):
            continue
        chosen.append(a)
    return sorted(chosen, key=lambda a: a.start)


def about_a_person(text: str, attrs: Sequence[Attribute]) -> bool:
    """The message describes a private person: the user, a relative, or someone to protect."""
    if _KO_PERSON.search(text) or _EN_PERSON.search(text) or _ANONYMITY.search(text):
        return True
    return any(_KO_SELF.match(text[a.end : a.end + 6]) for a in attrs)


_CONTENT_KO = re.compile(r"[가-힣]{2,}")
_CONTENT_EN = re.compile(r"[A-Za-z][A-Za-z\-]{3,}")
_GENERIC_CONTENT = frozenset(
    _words(
        """
        학교 중학교 고등학교 초등학교 아파트 교회 부대 지역 마을 도시 공무원 의사 교사 선수 대회
        school high church town city county state team company university teacher doctor
        """
    )
)
_PARTICLE_END = re.compile(
    r"(?:이었고|이었어|이었는데|였고|였어|였는데|이고|인데|이야|이며|입니다|이에요|예요|에서|에게|으로|이|가|"
    r"은|는|을|를|의|과|와|도|로|에|고|야)$"
)


def _content_words(fragment: str) -> set[str]:
    words = {_PARTICLE_END.sub("", w) for w in _CONTENT_KO.findall(fragment)}
    words |= {w.lower() for w in _CONTENT_EN.findall(fragment)}
    return {w for w in words if len(w) >= 2 and w not in _GENERIC_CONTENT}


def _relevant(text: str, attr: Attribute, attrs: Sequence[Attribute]) -> bool:
    """A content word of the attribute appears in the message outside every attribute."""
    rest, cursor = [], 0
    for a in attrs:
        rest.append(text[cursor : a.start])
        cursor = a.end
    rest.append(text[cursor:])
    outside = _content_words(" ".join(rest))
    return bool(_content_words(text[attr.start : attr.end]) & outside)


def score(attrs: Sequence[Attribute]) -> int:
    best: dict[str, int] = {}
    for a in attrs:
        best[a.category] = max(best.get(a.category, 0), a.score)
    return sum(best.values())


def coarsen(text: str, spans: Sequence[Span], level: ProtectionLevel) -> list[Span]:
    """Generalization spans that bring the message's quasi-identifier score below k."""
    k = K_BY_LEVEL.get(level)
    if k is None or not text.strip():
        return []
    attrs = attributes(text)
    if not attrs:
        return []
    covered = [p for p in locate(text, [s for s in spans if s.action != "keep"])]
    live = [a for a in attrs if not any(a.start < p.end and p.start < a.end for p in covered)]
    if score(live) < k or not about_a_person(text, live):
        return []
    lang = generalize.text_lang(text)
    order = sorted(
        (a for a in live if a.coarse(lang) and not _relevant(text, a, attrs)),
        key=lambda a: (-a.score, _ORDER.index(a.category), a.start),
    )
    chosen: list[Attribute] = []
    remaining = list(live)
    for a in order:
        if score(remaining) < k:
            break
        chosen.append(a)
        remaining.remove(a)
    out = []
    for a in sorted(chosen, key=lambda a: a.start):
        start, repl = _fit_article(text, a.start, a.coarse(lang) or "")
        out.append(
            Span(
                text=text[start : a.end],
                type="QUASI_IDENTIFIER",
                action="generalize",
                replacement=repl,
                source="rule",
                start=start,
                end=a.end,
                rule=f"link:qi_{a.category}",
            )
        )
    return out


_ARTICLE_BEFORE = re.compile(r"\b(?:a|an)[ \t]+$", re.IGNORECASE)
_NO_ARTICLE_AFTER = re.compile(
    r"(?:\b(?:the|my|our|his|her|their|your|this|that|its|only|sole)|['’]s|[a-z]-[a-z]+)[ \t]+$",
    re.IGNORECASE,
)


def _fit_article(text: str, start: int, replacement: str) -> tuple[int, str]:
    """ "I'm a left-handed helicopter mechanic" -> "I'm a technician", not "a a technician";
    "the only Korean-speaking pediatric cardiologist" -> "... Korean-speaking physician"."""
    if not re.match(r"(?:a|an)\s", replacement):
        return start, replacement
    before = text[max(0, start - 24) : start]
    if m := _ARTICLE_BEFORE.search(before):
        return start - (len(before) - m.start()), replacement
    if _NO_ARTICLE_AFTER.search(before):
        return start, re.sub(r"^(?:a|an)\s+", "", replacement)
    return start, replacement


def is_job_title(text: str, *, exact: bool = False) -> bool:
    """A job title, not a name or an organization ("선임연구원", "직함 선임연구원").

    `exact`: the title alone, so "김대리" (a surname and a title) is not one.
    """
    t = _PARTICLE_END.sub("", text.strip())
    t = re.sub(r"^(?:직함|직급|직책)\s*[:：]?\s*", "", t)
    if exact:
        return t in KO_JOB_TITLES
    return t in KO_JOB_TITLES or bool(
        re.fullmatch(rf"[가-힣]{{0,4}}(?:{_alt(sorted(KO_JOB_TITLES))})", t)
    )
