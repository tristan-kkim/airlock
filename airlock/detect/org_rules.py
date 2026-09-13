"""Employer, org unit, site and role: the quasi-identifier combination that links most often.

In the reframed eval, employer + team + role caused 15 of the 17 linkable disclosures on the
243-case set, and team names (`영업2팀`, `품질보증팀`, `Payments Platform`) survived every agent
run. A company name alone is masked by the other detectors, but "the security team lead at the
Pangyo headquarters" still narrows the person to one or two people.

This module proposes deterministic candidates and a request-level link:

* ORG: English corporate names with a company suffix (`Halcyon Freight Systems`, `Quarry Lane
  Architects`), masked like any organization.
* unit: Korean `…팀|본부|실|파트|센터|사업부|그룹|연구소|지점|지사` after a name token
  (`영업2팀`, `품질보증팀`), English `Team X`, `X Platform|Squad|Division|Department`, `X team`.
* site: a known place before a site noun (`판교 본사`, `Tulsa plant`, `Riverside branch`).
* role: a job title next to a unit (`보안팀 팀장`) or a capitalized multi-word title
  (`Senior Project Architect`), and an age next to them.

Candidates are only *activated* when they can link: an organization was detected anywhere in the
request or run, or a unit or site co-occurs with another attribute in the same text. Activated
candidates become QUASI_IDENTIFIER generalizations that keep the function and drop the name
(`영업2팀` -> `영업 부서`, `Payments Platform team lead` -> `an engineering team lead`), while
the organization itself stays masked. Benign text ("우리 팀 회식", "the marketing team") never
matches or never links.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from airlock import generalize
from airlock.detect import regions
from airlock.detect.spans import Span

# ---- functions (department categories) ----------------------------------------------------------

# (keywords, Korean category, English category)
_FUNCTIONS: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (("영업", "세일즈", "판매", "sales", "account"), "영업", "sales"),
    (
        ("마케팅", "홍보", "광고", "브랜드", "marketing", "brand", "communications", "pr"),
        "마케팅",
        "marketing",
    ),
    (("인사", "채용", "노무", "조직문화", "hr", "people", "talent", "recruiting"), "인사", "HR"),
    (
        (
            "재무",
            "회계",
            "경리",
            "자금",
            "세무",
            "finance",
            "accounting",
            "treasury",
            "tax",
            "fp&a",
        ),
        "재무",
        "finance",
    ),
    (("법무", "준법", "컴플라이언스", "legal", "compliance"), "법무", "legal"),
    (("품질", "qa", "qc", "quality"), "품질", "quality"),
    (
        (
            "생산",
            "제조",
            "공정",
            "설비",
            "조립",
            "manufacturing",
            "production",
            "plant",
            "assembly",
        ),
        "생산",
        "manufacturing",
    ),
    (
        (
            "연구",
            "개발",
            "설계",
            "r&d",
            "research",
            "engineering",
            "development",
            "controls",
            "reactor",
        ),
        "연구개발",
        "engineering",
    ),
    (("정보보안", "보안", "security", "infosec"), "보안", "security"),
    (
        (
            "전산",
            "정보시스템",
            "인프라",
            "데이터",
            "플랫폼",
            "클라우드",
            "it",
            "infra",
            "infrastructure",
            "data",
            "platform",
            "payments",
            "cloud",
            "devops",
            "sre",
            "backend",
            "frontend",
            "mobile",
            "product",
        ),
        "IT",
        "engineering",
    ),
    (("고객", "상담", "cs", "support", "customer", "service"), "고객지원", "customer support"),
    (
        ("기획", "전략", "신사업", "strategy", "planning", "corporate development", "bizdev"),
        "기획",
        "strategy",
    ),
    (
        (
            "구매",
            "조달",
            "물류",
            "유통",
            "scm",
            "procurement",
            "logistics",
            "supply",
            "operations",
            "ops",
        ),
        "운영",
        "operations",
    ),
    (("디자인", "ux", "ui", "design"), "디자인", "design"),
    (("총무", "경영지원", "행정", "admin", "administration"), "경영지원", "administration"),
    (("안전", "환경", "ehs", "safety"), "안전", "safety"),
    (("감사", "윤리", "audit"), "감사", "audit"),
    (("교육", "연수", "training", "learning"), "교육", "training"),
    (("간호", "병동", "nursing", "icu", "ward"), "간호", "nursing"),
)


def _words(block: str) -> list[str]:
    return block.split()


def function_of(text: str) -> tuple[str, str] | None:
    low = text.casefold()
    for keys, ko, en in _FUNCTIONS:
        for k in keys:
            if k.isascii():
                if re.search(rf"(?<![a-z]){re.escape(k)}(?![a-z])", low):
                    return ko, en
            elif k in text:
                return ko, en
    return None


# ---- Korean units -------------------------------------------------------------------------------

_KO_TAIL = (
    r"(?=(?:에서는|에서도|에서|에게|에는|에|의|은|는|이|가|을|를|과|와|으로|로|도|만|까지|부터|"
    r"소속|쪽|장)?(?![가-힣A-Za-z0-9]))"
)
_KO_UNIT = re.compile(
    r"(?<![가-힣A-Za-z0-9&])(?P<stem>[가-힣A-Za-z&]{1,10}?\d{0,2})"
    r"(?P<suffix>사업부|본부|연구소|지점|지사|파트|센터|그룹|부문|팀|실)" + _KO_TAIL
)
# Stems that make a generic unit word, not a named unit.
_KO_UNIT_GENERIC = frozenset(
    _words(
        """
        우리 저희 같은 다른 상대 각 전 한 원 해당 모든 전체 소속 본 새 옛 신규 기존 담당
        관련 우승 응원 경쟁 라이벌 야구 축구 농구 배구 스포츠 프로 국가대표 대표 드림 올스타
        홈 원정 상대편 적 아군 청 백 홍 대책 수사 비상 선거 재난 합동 사령 작전 중앙 방역
        특별 우리의 이 그 저 어느 무슨 어떤 회의 화장 사무 교 병 진료 응급 대기 휴게 강의
        연구 상담 수술 입원 실험 분만 탈의 기계 보일러 지하 창고 거 침 욕 거실 주방 옥
        다용도 콜 쇼핑 문화 체육 복지 주민 보건 행정복지 서비스 데이터 고객 헬스 피트니스
        스터디 아이돌 걸 보이 재벌 대기업 계열 소 대 중 팀 파트 방송 기상 경기 프로젝트
        태스크포스 TF 싱크탱크 연합 동아리 모임 커뮤니티 사내 신입 막내 인턴 실무 1 2 3
        """
    )
)
# Suffixes that only count with a department word or a known place in the stem.
_KO_STRICT_SUFFIX = frozenset({"실", "센터", "그룹", "연구소", "지점", "지사", "부문"})

_KO_SITE = re.compile(
    r"(?<![가-힣A-Za-z0-9])(?P<place>[가-힣]{2,6})\s?"
    r"(?P<site>본사|본점|지사|지점|공장|사업장|캠퍼스|연구소|물류센터|사옥|사무소|오피스|영업소)"
    + _KO_TAIL
)
_KO_ROLE_LEVELS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("대표이사", "대표", "사장", "부사장", "전무", "상무", "이사", "본부장", "임원"), "임원"),
    (
        (
            "팀장",
            "파트장",
            "실장",
            "센터장",
            "그룹장",
            "지점장",
            "지사장",
            "부장",
            "차장",
            "리드",
            "매니저",
            "PM",
            "PL",
        ),
        "관리자",
    ),
    (("수석연구원", "책임연구원", "선임연구원", "연구원"), "연구원"),
    (("과장", "대리", "주임", "사원"), "직원"),
)
_KO_ROLE = re.compile(
    r"(?<![가-힣A-Za-z])(?P<role>"
    + "|".join(sorted((w for ws, _ in _KO_ROLE_LEVELS for w in ws), key=len, reverse=True))
    + r")(?:님)?"
    + _KO_TAIL
)


def _ko_role_level(role: str) -> str:
    for words, level in _KO_ROLE_LEVELS:
        if role in words:
            return level
    return "직원"


# ---- English units, sites, roles, orgs ----------------------------------------------------------

_CAP = r"[A-Z][A-Za-z0-9&'’\-]*"
_LEAD_STOP = frozenset(
    _words(
        """
        The A An Our My Their Your His Her Its On In At Of For And With From To Dear Hi
        Hello Thanks This That These Those Every Each New Old
        """
    )
)
_SP = r"[ \t]+"
_EN_UNIT = re.compile(
    rf"\bTeam[ \t]+(?P<tname>{_CAP}(?:[ \t]+{_CAP})?)"
    rf"|(?P<cap>(?:{_CAP}{_SP}){{0,2}}{_CAP}){_SP}"
    r"(?P<ukind>Platform|Squad|Division|Department|Dept\.?)"
    rf"(?:[ \t]+(?P<ctail>team))?\b"
    rf"|(?P<lcap>(?:{_CAP}[ \t]+){{0,2}}{_CAP})[ \t]+team\b"
    r"|(?:\b(?:the|a|an|our|my|her|his|their)[ \t]+)"
    r"(?P<low>[a-z][a-z&\-]+(?:[ \t]+[a-z][a-z&\-]+){0,2})"
    r"[ \t]+team\b"
)
_EN_PUBLIC_DEPTS = frozenset(
    _words(
        """
        Police Fire State Justice Treasury Health Education Defense Transportation Labor
        Commerce Energy Agriculture Interior Homeland Sheriff Parks Emergency Revenue Water
        Sanitation Public Google Cloud Microsoft Apple Amazon Oracle Salesforce Shopify
        Stripe Adobe
        """
    )
)
_EN_LOW_STOP = frozenset(
    _words(
        """
        whole entire same new old other own small big large great good best local national
        school sports football soccer baseball basketball hockey home away winning losing
        rescue swat support
        """
    )
)
_EN_SITE = re.compile(
    rf"(?P<place>(?:{_CAP}[ \t]+){{0,2}}{_CAP})[ \t]+"
    r"(?P<site>plant|office|branch|campus|warehouse|facility|site|headquarters|HQ|factory|"
    r"distribution center|store|location)\b"
)
_EN_SITE_STOP = frozenset(
    _words(
        """
        The Our My Main Head Home Post Box Front Back Branch Oval Patent Tax Doctor's
        Dentist's Apple Google Amazon Microsoft Walmart Target Costco
        """
    )
)
_EN_ROLE_HEADS = {
    "architect": "an architect", "engineer": "an engineer", "manager": "a manager",
    "director": "a director", "analyst": "an analyst", "designer": "a designer",
    "scientist": "a scientist", "developer": "a developer", "officer": "an officer",
    "coordinator": "a coordinator", "specialist": "a specialist", "consultant": "a consultant",
    "supervisor": "a supervisor", "administrator": "an administrator",
    "accountant": "an accountant", "nurse": "a nurse", "technician": "a technician",
    "representative": "a representative", "lead": "a team lead", "president": "an executive",
    "partner": "a partner", "associate": "an associate",
}  # fmt: skip
_EN_ROLE = re.compile(
    r"(?P<title>(?:(?:Senior|Sr\.|Junior|Jr\.|Lead|Principal|Staff|Chief|Head|Associate|Assistant|"
    r"Deputy|Vice|Executive|Regional|General)[ \t]+)*(?:[A-Z][a-z]+[ \t]+){0,2}"
    r"(?:Architect|Engineer|Manager|Director|Analyst|Designer|Scientist|Developer|Officer|"
    r"Coordinator|Specialist|Consultant|Supervisor|Administrator|Accountant|Nurse|Technician|"
    r"Representative|Lead|President|Partner))\b"
    r"|\b(?P<low>team lead|tech lead|engineering manager|product manager|shift supervisor|"
    r"charge nurse|store manager|branch manager|account manager|project manager)\b"
)
_EN_AGE = re.compile(
    r"\b(?:turned|turning|aged?)\s+\d{2}\b|\b\d{2}-year-old\b|\b\d{2}\s+years\s+old\b"
)
_KO_AGE = re.compile(
    r"(?:올해\s*)?(?:만\s*)?\d{2}\s*(?:세|살)(?![가-힣])|(?:올해\s*)?(?:스물|서른|마흔|쉰|예순)"
    r"(?:하나|한|둘|두|셋|세|넷|네|다섯|여섯|일곱|여덟|아홉)?(?:\s*살)?"
)

_EN_ORG_SUFFIX = (
    r"Inc\.?|LLC|L\.L\.C\.|Ltd\.?|Corp\.?|Corporation|Co\.|Company|Systems|Logistics|Analytics|"
    r"Architects|Associates|Holdings|Partners|Labs|Laboratories|Technologies|Solutions|Industries|"
    r"Freight|Pharmaceuticals|Pharma|Group|Bank|Credit Union|Capital|Ventures|Consulting|"
    r"Hospital|Clinic|Health|Energy|Foods|Motors|Manufacturing|Studios|Media|Software|Robotics|"
    r"Biotech|Insurance|Networks|Dynamics|Devices|Therapeutics|Outfitters|Brewing|Realty|Legal|LLP|"
    r"Semiconductors?|Electronics|Retail|Dental|Pharmacy|Aerospace|Automotive|Chemicals|Textiles|"
    r"Publishing|Airlines|Shipping|Construction|Engineering|Bakery|Brewery|University|College|"
    r"Academy|Institute"
)
_EN_ORG = re.compile(
    rf"(?<![A-Za-z])(?P<name>(?:{_CAP}[ \t]+){{1,3}}(?:{_EN_ORG_SUFFIX}))(?![A-Za-z])"
)
_EN_ORG_STOP_FIRST = frozenset(
    _words(
        """
        The A An Our My Their Your This That In At For With From To Dear Hi Hello Thanks
        Information Operating Computer Human Customer Public Local National General Mental
        Global Management Private Community Regional State Federal Venture Health Energy
        Support Security Software Google Microsoft Apple Amazon Meta Nvidia NVIDIA Oracle
        IBM Intel Samsung Goldman Morgan Wells Bank Citi Deloitte Accenture McKinsey Pfizer
        Moderna Tesla Ford Toyota Honda Boeing Johnson World Asian European American Mayo
        Cleveland Kaiser Stanford Harvard
        """
    )
)


@dataclass(frozen=True)
class Candidate:
    start: int
    end: int
    kind: str  # unit | site | role | age
    ko: str  # Korean generalization
    en: str  # English generalization
    rule: str

    def replacement(self, lang: str) -> str:
        return self.ko if lang == "ko" else self.en


def _strip_lead(text: str, start: int) -> tuple[str, int]:
    words = text.split(" ")
    while words and words[0] in _LEAD_STOP:
        start += len(words[0]) + 1
        words = words[1:]
    return " ".join(words), start


def ko_candidates(text: str) -> list[Candidate]:
    out: list[Candidate] = []
    for m in _KO_UNIT.finditer(text):
        stem, suffix = m.group("stem"), m.group("suffix")
        bare = re.sub(r"\d+$", "", stem)
        if bare in _KO_UNIT_GENERIC or len(bare) < 1 or (len(bare) < 2 and not stem[-1:].isdigit()):
            continue
        func = function_of(stem)
        top = regions.ko_container(bare) if suffix in ("지점", "지사", "연구소", "센터") else None
        if suffix in _KO_STRICT_SUFFIX and not func and not top:
            continue
        if top:
            ko = f"{top} 소재 {suffix}"
            en = f"a {'branch' if suffix in ('지점', '지사') else 'site'} in Korea"
        else:
            ko = f"{func[0]} 부서" if func else "사내 부서"
            en = f"a {func[1]} team" if func else "a team"
        out.append(Candidate(m.start(), m.end("suffix"), "unit", ko, en, "ko_org_unit"))
    for m in _KO_SITE.finditer(text):
        place, site = m.group("place"), m.group("site")
        top = regions.ko_container(place)
        if not top:
            continue
        out.append(
            Candidate(
                m.start(),
                m.end("site"),
                "site",
                f"{top} 소재 {site}",
                "a site in Korea",
                "ko_org_site",
            )  # fmt: skip
        )
    for m in _KO_ROLE.finditer(text):
        role = m.group("role")
        level = _ko_role_level(role)
        out.append(Candidate(m.start("role"), m.end("role"), "role", level, "an employee",
                             "ko_role"))  # fmt: skip
    for m in _KO_AGE.finditer(text):
        age = generalize.age_of(m.group())
        if age:
            out.append(Candidate(m.start(), m.end(), "age", generalize.decade_phrase(age, "ko"),
                                 generalize.decade_phrase(age, "en"), "ko_age"))  # fmt: skip
    return out


def en_candidates(text: str) -> list[Candidate]:
    out: list[Candidate] = []
    for m in _EN_UNIT.finditer(text):
        if m.group("tname"):
            out.append(Candidate(m.start(), m.end(), "unit", "사내 팀", "a project team",
                                 "en_team_name"))  # fmt: skip
            continue
        if m.group("cap"):
            words, start = _strip_lead(m.group("cap"), m.start("cap"))
            if not words or words.split()[0] in _EN_PUBLIC_DEPTS:
                continue
            kind = m.group("ukind")
            func = function_of(words)
            if kind in ("Platform", "Squad"):
                en = "an engineering team"
            else:
                en = f"a {func[1]} department" if func else "a department"
            ko = f"{func[0]} 부서" if func else "사내 부서"
            out.append(Candidate(start, m.end(), "unit", ko, en, "en_org_unit"))
            continue
        if m.group("lcap"):
            words, start = _strip_lead(m.group("lcap"), m.start("lcap"))
            if not words or words.split()[0] in _EN_PUBLIC_DEPTS:
                continue
            func = function_of(words)
            en = f"a {func[1]} team" if func else "a team"
            out.append(Candidate(start, m.end(), "unit", f"{func[0]} 부서" if func else "사내 부서",
                                 en, "en_org_unit"))  # fmt: skip
            continue
        low = m.group("low")
        tokens = low.split()
        if all(t in _EN_LOW_STOP for t in tokens):
            continue
        func = function_of(low)
        if not func and "-" not in low:
            continue
        en = f"a {func[1]} team" if func else "a team"
        ko = f"{func[0]} 부서" if func else "사내 부서"
        out.append(Candidate(m.start("low"), m.end(), "unit", ko, en, "en_org_unit"))
    for m in _EN_SITE.finditer(text):
        words, start = _strip_lead(m.group("place"), m.start("place"))
        if not words or words.split()[0] in _EN_SITE_STOP:
            continue
        if re.search(rf"(?:^|\s)(?:{_EN_ORG_SUFFIX})$", words):
            continue  # "Corvenna Systems warehouse": the organization is masked on its own
        site = m.group("site").lower()
        top = regions.en_container(words)
        en = f"a {site} in {top}" if top else f"a {site}"
        out.append(Candidate(start, m.end(), "site", "한 사업장", en, "en_org_site"))
    for m in _EN_ROLE.finditer(text):
        if m.group("title"):
            title, start = _strip_lead(m.group("title"), m.start("title"))
            if len(title.split()) < 2:
                continue  # "Manager" alone is not identifying
            head = title.split()[-1].lower()
        else:
            title, start = m.group("low"), m.start("low")
            head = title.split()[-1].lower()
        en = _EN_ROLE_HEADS.get(head, "an employee")
        out.append(Candidate(start, start + len(title), "role", "직원", en, "en_role"))
    for m in _EN_AGE.finditer(text):
        age = generalize.age_of(m.group())
        if age:
            out.append(Candidate(m.start(), m.end(), "age", generalize.decade_phrase(age, "ko"),
                                 generalize.decade_phrase(age, "en"), "en_age"))  # fmt: skip
    return out


def en_orgs(text: str) -> list[Span]:
    """English organization names with a corporate suffix ("Halcyon Freight Systems")."""
    spans = []
    for m in _EN_ORG.finditer(text):
        name, start = _strip_lead(m.group("name"), m.start("name"))
        tokens = name.split()
        if len(tokens) < 2 or tokens[0] in _EN_ORG_STOP_FIRST:
            continue
        if all(t.isupper() and len(t) <= 4 for t in tokens[:-1]):
            continue  # "IT Solutions", "HR Group": acronyms plus a suffix
        spans.append(
            Span(
                text=name,
                type="ORG",
                source="rule",
                start=start,
                end=start + len(name),
                rule="en_org_suffix",
            )  # fmt: skip
        )
    return spans


_KO_SMALL_PLACE = re.compile(
    r"(?<![가-힣])(?:(?P<top>서울|부산|대구|인천|대전|울산|세종|경기|강원|충북|충남|전북|전남|경북|경남|"
    r"제주)(?:특별시|광역시|특별자치시|특별자치도|도)?\s+)?"
    r"(?P<place>[가-힣]{2,6}(?:군|읍|면|리|마을))(?=에서|에|의|은|는|이|가|로|으로|\s|$|[,.])"
)
_KO_SMALL_PLACE_GENERIC = frozenset(
    [
        "시골마을",
        "우리마을",
        "이마을",
        "저마을",
        "그마을",
        "옆마을",
        "한마을",
        "작은마을",
        "산골마을",
        "어촌마을",
        "농촌마을",
        "외딴마을",
        "전원마을",
        "민속마을",
        "한옥마을",
        "시군",
        "해당군",
        "인근군",
        "이웃마을",
        "동네마을",
    ]
)
_EN_ONLY_IN_PLACE = re.compile(
    r"\b(?:the|our|my) only (?P<what>(?:[a-z\-]+[ \t]+){0,3}"
    r"(?:center|centre|hospital|clinic|school|firm|store|shop|restaurant|church|mosque|temple|pharmacy|bakery|bar|gym|practice|office|"
    r"company|plant|factory|farm|library|station))[ \t]+in[ \t]+"
    r"(?P<place>(?:[A-Z][\w'’\-]*[ \t]?){1,3})"
)


_EN_CITY_STATE = re.compile(
    r"\b(?P<prep>in|near|outside|from|to)[ \t]+"
    r"(?P<city>(?:[A-Z][\w'’\-]*[ \t]){0,2}[A-Z][\w'’\-]*),[ \t]*"
    r"(?P<state>" + "|".join(sorted(regions.EN_REGIONS | set(regions.US_STATE_CODES), key=len,
                                    reverse=True)) + r")\b"
)  # fmt: skip
_EN_FIRST_PERSON = re.compile(r"\b(?:I|I'm|I've|my|me|we|our|us)\b")


def place_candidates(text: str) -> list[Candidate]:
    """A small place a person lives or works in: `경북 새내군`, `the only X in Port Aldine`."""
    from airlock.detect.ko_rules import _KO_PERSON_CUE

    out: list[Candidate] = []
    for m in _KO_SMALL_PLACE.finditer(text):
        place = m.group("place")
        if place in _KO_SMALL_PLACE_GENERIC or place[:-1] in ("시", "군", "도"):
            continue
        s0, s1 = _sentence_of(text, m.start())
        if not _KO_PERSON_CUE.search(text[s0:s1]):
            continue
        phrase = text[m.start() : m.end()]
        ko = generalize.place_generalization(phrase, "ko")
        if ko is None:
            suffix = "마을" if place.endswith("마을") else place[-1]
            noun = {
                "군": "군 지역",
                "읍": "읍 지역",
                "면": "면 지역",
                "리": "마을",
                "마을": "마을",
            }[suffix]
            top = regions.ko_container(m.group("top") or "")
            ko = f"{top}의 한 {noun}" if top else f"한 {noun}"
        out.append(Candidate(m.start(), m.end(), "place", ko, "a small town", "ko_small_place"))
    for m in _EN_CITY_STATE.finditer(text):
        s0, s1 = _sentence_of(text, m.start())
        if not _EN_FIRST_PERSON.search(text[s0:s1]):
            continue
        state = regions.US_STATE_CODES.get(m.group("state"), m.group("state"))
        if m.group("city") in regions.EN_REGIONS:
            continue
        start = m.start("city")
        out.append(Candidate(start, m.end("state"), "place", "한 지역", f"a town in {state}",
                             "en_city_state"))  # fmt: skip
    for m in _EN_ONLY_IN_PLACE.finditer(text):
        place = m.group("place").strip()
        top = regions.en_container(place)
        what = m.group("what")
        en = f"a {what} in {top}" if top else f"a local {what}"
        out.append(Candidate(m.start(), m.end("place") - (len(m.group("place")) - len(place)),
                             "place", "한 지역", en, "en_only_in_place"))  # fmt: skip
    return out


def candidates(text: str) -> list[Candidate]:
    found = ko_candidates(text) + en_candidates(text) + place_candidates(text)
    # longest first, drop candidates inside a longer one of the same kind
    found.sort(key=lambda c: (-(c.end - c.start), c.start))
    chosen: list[Candidate] = []
    for c in found:
        if any(c.start >= o.start and c.end <= o.end for o in chosen):
            continue
        chosen.append(c)
    return sorted(chosen, key=lambda c: c.start)


def _sentence_of(text: str, pos: int) -> tuple[int, int]:
    start = max(text.rfind(ch, 0, pos) for ch in ".!?\n。") + 1
    ends = [i for i in (text.find(ch, pos) for ch in ".!?\n。") if i != -1]
    return start, (min(ends) if ends else len(text))


def link(
    texts: Sequence[str], spans_by_text: Sequence[Sequence[Span]], *, org_known: bool = False
) -> list[list[Span]]:
    """Activated quasi-identifier spans per text (QUASI_IDENTIFIER generalizations).

    `org_known`: an organization was already masked earlier in this conversation or run.
    """
    has_org = org_known or any(
        s.type == "ORG" and s.action != "keep" for spans in spans_by_text for s in spans
    )
    out: list[list[Span]] = []
    for text, spans in zip(texts, spans_by_text, strict=True):
        cands = candidates(text)
        lang = generalize.text_lang(text)
        anchors = [c for c in cands if c.kind in ("unit", "site")]
        org_positions = [
            (p.start(), p.end()) for s in spans if s.type == "ORG" and s.action != "keep"
            for p in re.finditer(re.escape(s.text), text)
        ]  # fmt: skip
        roles = [c for c in cands if c.kind == "role"]
        places = [c for c in cands if c.kind == "place"]
        ages = [c for c in cands if c.kind == "age"]

        def same_sentence(a: Candidate, b_start: int, text: str = text) -> bool:
            s0, s1 = _sentence_of(text, a.start)
            return s0 <= b_start < s1

        active: list[Candidate] = []
        for a in anchors:
            combined = (
                any(o is not a and o.kind != a.kind and same_sentence(a, o.start) for o in anchors)
                or any(0 <= r.start - a.end <= 12 for r in roles)
                or any(same_sentence(a, g.start) for g in ages)
            )
            if has_org or combined:
                active.append(a)
        chosen: list[Candidate] = list(active) + places
        for c in roles:
            near_unit = any(0 <= c.start - a.end <= 12 for a in active)
            titled = c.rule == "en_role" and c.en != "an employee"
            in_sentence = any(same_sentence(c, a.start) for a in active) or any(
                same_sentence(c, p) for p, _ in org_positions
            )
            if near_unit or (has_org and titled) or (titled and in_sentence):
                chosen.append(c)
        for g in ages:
            # Only next to a unit or site: an age next to a hospital name is the situation.
            if any(same_sentence(g, a.start) for a in active):
                chosen.append(g)
        merged = _merge_adjacent(text, chosen, lang)
        spans_out = []
        for c in merged:
            start, repl = _fit_article(text, c.start, c.replacement(lang))
            spans_out.append(
                Span(
                    text=text[start : c.end],
                    type="QUASI_IDENTIFIER",
                    action="generalize",
                    replacement=repl,
                    source="rule",
                    start=start,
                    end=c.end,
                    rule=f"link:{c.rule}",
                )  # fmt: skip
            )
        out.append(spans_out)
    return out


_ARTICLE_BEFORE = re.compile(r"\b(?:a|an)\s+$", re.I)
_DETERMINER_BEFORE = re.compile(
    r"(?:\b(?:the|our|my|their|his|her|its|your|this|that)|['’]s)\s+$", re.I
)


def _fit_article(text: str, start: int, replacement: str) -> tuple[int, str]:
    """(span start, replacement) that read well with the word before the span.

    "a Senior Project Architect" -> "an architect" (the article joins the span);
    "the Tulsa plant" -> "the plant in Oklahoma" (the replacement drops its article).
    """
    if not re.match(r"(?:a|an)\s", replacement):
        return start, replacement
    before = text[max(0, start - 8) : start]
    if m := _ARTICLE_BEFORE.search(before):
        return start - (len(before) - m.start()), replacement
    if _DETERMINER_BEFORE.search(before):
        return start, re.sub(r"^(?:a|an)\s+", "", replacement)
    return start, replacement


def _merge_adjacent(text: str, chosen: list[Candidate], lang: str) -> list[Candidate]:
    """`보안팀 팀장` / `Payments Platform team lead`: one phrase, one generalization."""
    chosen = sorted(chosen, key=lambda c: c.start)
    out: list[Candidate] = []
    for c in chosen:
        prev = out[-1] if out else None
        if (
            prev is not None
            and prev.kind in ("unit", "site")
            and c.kind == "role"
            and 0 <= c.start - prev.end <= 1
            and not text[prev.end : c.start].strip()
        ):
            ko = f"{prev.ko} {c.ko}"
            if c.en == "a team lead" and prev.en.endswith(" team"):
                en = f"{prev.en} lead"  # "an engineering team" + "lead"
            else:
                en = f"{c.en} in {prev.en}"
            out[-1] = Candidate(prev.start, c.end, "unit", ko, en, prev.rule)
            continue
        if prev is not None and c.start < prev.end:
            continue
        out.append(c)
    return out
