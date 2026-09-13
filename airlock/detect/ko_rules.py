"""Deterministic semantic rules, mainly for Korean, where the local model is weakest.

In the local-model spike, Nemotron-3-Nano-4B found Korean quasi-identifiers ("유일한 여성
부사장") 11% of the time, Korean health details 58% and small Korean company names 33%. These
rules add conservative, explainable proposals for those cases:

* QUASI_IDENTIFIER: a uniqueness cue (유일한, 유일하게, 혼자만, 단 한 명, only, sole) followed
  closely by a role, group or place word.
* HEALTH: diagnoses, conditions, medications and care terms, but only in a sentence that ties
  them to a person (저, 제 동료, 환자, 진단받았, 복용 중, I was diagnosed, ...). "당뇨에 좋은
  음식" is left alone.
* ORG: a Hangul/Latin name directly attached to a company or institution suffix (새론다움물류,
  한빛병원, ㈜누리소프트), excluding generic compounds (초등학교, 대학병원, 국회의원) and
  well-known public organizations.
* PERSON: a 2-4 syllable Hangul name starting with a common surname, right before an honorific
  or title (김서연님, 박지훈 고객, 문태오 대리), excluding common nouns and public figures.

They only *propose* spans, like the local model. False positives cost utility (over-masking),
so every rule has a negative list; review mode lets the user undo a proposal.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from airlock import placeholders
from airlock.detect.spans import Span

KO_QUASI_REPLACEMENT = "특정 역할의 구성원"
EN_QUASI_REPLACEMENT = "someone in a specific role"
KO_HEALTH_REPLACEMENT = "건강 문제"
EN_HEALTH_REPLACEMENT = "a health condition"

_HANGUL = re.compile(r"[가-힣]")


def _words(block: str) -> list[str]:
    return block.split()


def _stem_table(block: str) -> dict[str, frozenset[str]]:
    """Parse "suffix: stem stem ..." lines; indented lines continue the previous suffix."""
    table: dict[str, list[str]] = {}
    key = ""
    for line in block.splitlines():
        if not line.strip():
            continue
        if ":" in line:
            key, _, rest = line.partition(":")
            key = key.strip()
            table.setdefault(key, [])
            line = rest
        table[key].extend(line.split())
    return {k: frozenset(v) for k, v in table.items()}


# Particles/copulas that may follow a noun without a space.
_PARTICLES = (
    "으로부터|로부터|에서는|에게는|께서는|이라서|이라고|이지만|입니다|이에요|이었고|이었는데|"
    "으로서|로서|에서|에게|께서|한테|이랑|하고|이나|까지|부터|처럼|같은|이고|이며|인데|이다|"
    "이야|이라|였고|였는데|라서|라고|이어서|여서|으로|이|가|은|는|을|를|의|께|과|와|도|만|랑|나|로|에|인|야|다|님|들"
)
_PARTICLE_TAIL = re.compile(rf"(?:{_PARTICLES})$")


def _split_particle(token: str) -> str:
    return _PARTICLE_TAIL.sub("", token) if _HANGUL.search(token) else token


def _outside_placeholders(text: str, spans: Iterable[Span]) -> list[Span]:
    blocked = placeholders.intervals(text)
    out = []
    for s in spans:
        assert s.start is not None and s.end is not None
        if s.end > s.start and not any(s.start < b and a < s.end for a, b in blocked):
            out.append(s)
    return out


def _span(text: str, start: int, end: int, type_: str, rule: str, repl: str | None) -> Span:
    return Span(
        text=text[start:end],
        type=type_,
        action="generalize" if repl else "mask",
        replacement=repl,
        source="rule",
        start=start,
        end=end,
        rule=rule,
    )


# ---- sentences --------------------------------------------------------------------------------


def _sentences(text: str) -> list[tuple[int, int]]:
    out, start = [], 0
    for m in re.finditer(r"[.!?。\n]+", text):
        out.append((start, m.end()))
        start = m.end()
    if start < len(text):
        out.append((start, len(text)))
    return out


# ---- QUASI_IDENTIFIER ---------------------------------------------------------------------------

_KO_ROLE_WORDS = frozenset(
    _words(
        """
        부사장 사장 대표 대표이사 이사 임원 상무 전무 본부장 실장 팀장 파트장 부장 차장 과장 대리
        주임 사원 직원 인턴 신입 개발자 엔지니어 디자이너 기획자 마케터 연구원 연구자 과학자 박사
        석사 교수 강사 교사 선생님 원장 원감 교장 교감 의사 전문의 한의사 치과의사 수의사 간호사
        약사 간병인 요양보호사 물리치료사 변호사 판사 회계사 세무사 노무사 법무사 변리사 통역사
        번역가 기자 작가 피디 아나운서 목사 전도사 신부 수녀 스님 경찰 경찰관 형사 소방관 군인
        장교 부사관 병사 여군 공무원 사무관 주무관 조종사 기장 승무원 셰프 요리사 바리스타
        운전기사 택시기사 버스기사 선수 코치 감독 트레이너 매니저 점장 농부 어부 해녀 학생
        대학원생 유학생 박사과정 교환학생 여성 남성 여자 남자 외국인 한국인 흑인 백인 동양인
        아시아인 장애인 이민자 난민 교포 탈북민 탈북자 귀화인 혼혈 트랜스젠더 동성애자 게이
        레즈비언 입주민 주민 세입자 환자 생존자 목격자 증인 창업자 설립자 소유주 건물주 집주인
        쌍둥이 청각장애인 시각장애인 휠체어 사용자 워킹맘 한부모 입양아 노인 회원 멤버 조합원
        """
    )
)
_KO_ROLE_SUFFIXES = ("출신", "국적")
_KO_QUASI_CUE = re.compile(
    r"유일한|유일하게|유일무이한|혼자만|단\s*한\s*명(?:뿐인|의|인|뿐)?|하나뿐인"
)
_KO_CLAUSE_STOP = re.compile(r"[.,!?;:\n()\"“”'‘’]")
_KO_TOKEN = re.compile(r"[가-힣A-Za-z0-9][가-힣A-Za-z0-9\-]*")


_PHRASE_END = re.compile(
    r"[가-힣]{2,}(?:은|는|을|를|에서|에게|에|와|과|으로|이고|이다|인데|라서|이지만|하고)$"
)


def _ko_role(token: str) -> bool:
    if token in _KO_ROLE_WORDS:
        return True
    stem = _split_particle(token)
    # Strip a copula or particle twice ("부사장인데" -> "부사장인" -> "부사장").
    stem = _split_particle(stem) if stem not in _KO_ROLE_WORDS else stem
    if stem in _KO_ROLE_WORDS:
        return True
    return any(stem.endswith(sfx) and len(stem) > len(sfx) for sfx in _KO_ROLE_SUFFIXES) or (
        token.startswith(_KO_ROLE_SUFFIXES)
    )


def _role_end(token_match: re.Match[str]) -> int:
    token = token_match.group()
    if token in _KO_ROLE_WORDS:
        return token_match.end()
    stem = _split_particle(token)
    if stem not in _KO_ROLE_WORDS:
        stem2 = _split_particle(stem)
        if stem2 in _KO_ROLE_WORDS:
            stem = stem2
    return token_match.start() + len(stem)


def _ko_quasi(text: str) -> list[Span]:
    spans = []
    for cue in _KO_QUASI_CUE.finditer(text):
        tail = text[cue.end() : cue.end() + 40]
        stop = _KO_CLAUSE_STOP.search(tail)
        window = tail[: stop.start()] if stop else tail
        end = None
        for i, tok in enumerate(_KO_TOKEN.finditer(window)):
            if i >= 4:
                break
            if _ko_role(tok.group()):
                end = cue.end() + _role_end(tok)
            elif _PHRASE_END.fullmatch(tok.group()):
                break  # "유일한 방법은 ...": a particle closes the noun phrase without a role
        if end is not None:
            spans.append(
                _span(text, cue.start(), end, "QUASI_IDENTIFIER", "ko_quasi", KO_QUASI_REPLACEMENT)
            )
    return spans


_EN_ROLE = (
    r"nurse|doctor|physician|surgeon|dentist|pharmacist|therapist|engineer|developer|programmer|"
    r"designer|lawyer|attorney|partner|paralegal|accountant|teacher|professor|instructor|"
    r"principal|student|employee|worker|staffer|manager|director|executive|VP|CEO|CTO|CFO|"
    r"founder|owner|officer|pilot|firefighter|detective|soldier|veteran|chef|cook|translator|"
    r"interpreter|pastor|priest|rabbi|imam|woman|man|female|male|Black|Asian|Latino|Latina|"
    r"Hispanic|immigrant|refugee|foreigner|transgender|resident|tenant|patient|survivor|"
    r"witness|parent|mother|father|mom|dad|twin|intern|contractor|scientist|researcher|analyst|"
    r"clerk|cashier|driver|farmer|member"
)
_EN_QUASI = re.compile(
    rf"(?:(?<![A-Za-z])(?:[Tt]he|[Oo]ur|[Mm]y|[Hh]is|[Hh]er|[Tt]heir|[Ii]ts|an?)\s+|['’]s\s+)"
    rf"(?P<q>only|sole)\s+(?!(?:if|when|one|way|thing|things|option|time|reason|because|after|"
    rf"before|to|for|in|on|at|a|the|person|people|one's)\b)"
    rf"(?:[A-Za-z0-9'\-]+\s+){{0,4}}(?:{_EN_ROLE})s?(?![A-Za-z])"
    rf"(?:\s+(?:at|in|on|of|for)\s+(?:(?:a|an|the|our|my|this|that|his|her|their)\s+)?"
    rf"(?:[A-Za-z0-9'\-]+\s+){{0,3}}(?:firm|company|team|office|hospital|clinic|school|"
    rf"department|shift|unit|village|town|building|floor|startup|lab|store|branch|church|"
    rf"squad|class|county|base|station|ward|practice)s?(?![A-Za-z]))?",
)


def _en_quasi(text: str) -> list[Span]:
    return [
        _span(text, m.start("q"), m.end(), "QUASI_IDENTIFIER", "en_quasi", EN_QUASI_REPLACEMENT)
        for m in _EN_QUASI.finditer(text)
    ]


# ---- HEALTH -------------------------------------------------------------------------------------

_KO_HEALTH_TERMS = sorted(
    _words(
        r"""
        우울증 조울증 공황장애 불안장애 양극성장애 양극성\s장애 강박장애 강박증 조현병 섭식장애
        거식증 폭식증 불면증 수면장애 외상\s?후\s?스트레스\s?장애 산후우울증 대인기피증 공포증
        자폐 자폐\s?스펙트럼 발달장애 지적장애 틱장애 뇌전증 간질 치매 알츠하이머 파킨슨병 파킨슨
        뇌졸중 뇌경색 뇌출혈 심근경색 협심증 부정맥 심부전 고혈압 저혈압 당뇨병 당뇨 고지혈증
        제[12]형\s?당뇨 백혈병 림프종 골수종 흑색종 종양 천식 아토피 결핵 [BC]형\s?간염 간염
        간경화 신부전 투석 에이즈 매독 성병 헤르페스 임신 난임 불임 낙태 임신중절 갱년기 류마티스
        루푸스 크론병 궤양성\s?대장염 과민성\s?대장\s?증후군 알코올\s?중독 도박\s?중독 약물\s?중독
        자해 자살\s?시도 정신과 정신건강의학과 정신병원 심리상담 상담치료 항우울제 항불안제 수면제
        신경안정제 항정신병약 항암치료 항암제 항암 방사선\s?치료 화학요법 인슐린 메트포르민 프로작
        졸로프트 렉사프로 자낙스 아빌리파이 콘서타 리탈린 페니드 스트라테라 쎄로켈 설트랄린
        플루옥세틴 청각장애 시각장애 지체장애 뇌병변 희귀질환 희귀병 코로나\s?확진 양성\s?판정
        ADHD PTSD HIV AIDS HPV OCD
        """
    ),
    key=len,
    reverse=True,
)
_KO_CANCER = (
    r"(?:갑상선|유방|위|폐|대장|직장|간|췌장|전립선|자궁경부|자궁내막|자궁|난소|피부|혈액|방광|"
    r"신장|식도|담낭|담도|구강|후두|뇌|골|고환|소세포폐)암"
)
_KO_HEALTH = re.compile(
    rf"(?<![가-힣A-Za-z])(?:{_KO_CANCER}|{'|'.join(_KO_HEALTH_TERMS)}"
    rf"|암(?=\s|$|[이을은으에과와도,.!?]|환자|진단|치료|수술|판정|병동|센터|[1-4]기|말기|초기))"
    rf"(?![A-Za-z])"
)
# Medical care words only count with their object: "갑상선 수술을 받", "우울증 진단을 받".
_KO_CARE = re.compile(
    r"(?<![가-힣])(?P<object>[가-힣A-Za-z0-9]{2,8})\s?(?P<care>수술|진단|처방)\s?(?:을|를|이)?\s?"
    r"(?:받|했|하고|예정|나왔|나와)"
)
_KO_CARE_GENERIC = frozenset(
    _words(
        """
        자가 경영 시스템 건강 정밀 종합 조기 최종 초기 의사 기업 보안 어제 오늘 내일 지난주 이번주
        다음주 작년 올해 최근 다시 급하게 결국 드디어 이미 추가 응급 긴급 간단한 약을 약 성형 무료
        원격 진료
        """
    )
)
_KO_PERSON_CUE = re.compile(
    r"(?<![가-힣])(?:저는|저도|제가|저의|저희|제|내가|나는|난|내|우리|본인)(?=\s|$)"
    r"|(?<![가-힣])(?:엄마|어머니|아빠|아버지|남편|아내|와이프|아들|딸|오빠|언니|누나|동생|할머니|"
    r"할아버지|친구|동료|팀원|직원|고객|애인|부모님|장모님|시어머니)"
    r"(?=께서|가|이|는|은|의|를|을|도|랑|와|과|한테|에게|\s|$)"
    r"|[가-힣]\s?(?:님|씨)(?:은|는|이|가|께서|의|을|를|과|와|도|께)?(?![가-힣])|(?:대리|과장|팀장|부장|차장|사원|선생님|교수)(?:가|는|님|께서)"
)
_KO_HEALTH_VERB = re.compile(
    r"진단(?:을\s?)?받|진단이\s?나|판정(?:을\s?)?받|확진(?:을\s?)?받|처방(?:을\s?)?받|처방된|"
    r"수술(?:을\s?)?받|수술\s?예정|수술했|앓|걸렸|걸려서|걸린|복용|먹고\s?있|치료\s?중|치료(?:를\s?)?받|"
    r"입원했|입원\s?중|입원해|퇴원했|다니고\s?있|다니는\s?중|병가|휴직|투병|투약|재발했"
)

_EN_HEALTH = re.compile(
    r"(?<![A-Za-z])(?:(?:type [12] )?diabetes|depression|major depressive disorder|"
    r"(?:generalized )?anxiety disorder|panic (?:disorder|attacks)|bipolar(?: disorder)?|"
    r"schizophrenia|OCD|PTSD|ADHD|autism|epilepsy|seizures|dementia|Alzheimer's|Parkinson's|"
    r"heart attack|hypertension|(?:(?:breast|lung|colon|prostate|pancreatic|thyroid|skin|ovarian|"
    r"cervical|stage [0-4I]{1,3}) )?cancer|leukemia|lymphoma|chemotherapy|chemo|radiation therapy|"
    r"asthma|HIV|AIDS|hepatitis [ABC]|tuberculosis|pregnant|pregnancy|miscarriage|abortion|IVF|"
    r"infertility|insulin|antidepressants?|Prozac|Zoloft|Lexapro|Xanax|lithium|Adderall|Ritalin|"
    r"methadone|Suboxone|eating disorder|anorexia|bulimia|insomnia|multiple sclerosis|"
    r"Crohn's disease|lupus|self-harm|suicidal|overdose)(?![A-Za-z])",
    re.IGNORECASE,
)
_EN_PERSON_CUE = re.compile(
    r"(?<![A-Za-z])(?:I|I'm|I've|my|me|he|she|his|her|him|patient|employee|coworker|co-worker|"
    r"colleague|son|daughter|wife|husband|mom|mother|dad|father|brother|sister|friend|boss|"
    r"client|customer|tenant|student)(?![A-Za-z])"
)
_EN_HEALTH_VERB = re.compile(
    r"(?<![A-Za-z])(?:diagnos\w*|prescri\w*|taking|takes|suffer\w*|treated|treatment|battl\w*|"
    r"recover\w*|hospitali\w*|admitted|relaps\w*|living with|tested positive|on medication|"
    r"struggl\w*|went into rehab|in rehab)(?![A-Za-z])",
    re.IGNORECASE,
)


def _health(text: str) -> list[Span]:
    spans = []
    for s, e in _sentences(text):
        sentence = text[s:e]
        ko_ok = bool(_KO_PERSON_CUE.search(sentence) or _KO_HEALTH_VERB.search(sentence))
        en_ok = bool(_EN_PERSON_CUE.search(sentence) and _EN_HEALTH_VERB.search(sentence))
        if ko_ok:
            for m in _KO_HEALTH.finditer(sentence):
                spans.append(
                    _span(
                        text,
                        s + m.start(),
                        s + m.end(),
                        "HEALTH",
                        "ko_health",
                        KO_HEALTH_REPLACEMENT,
                    )
                )
            for m in _KO_CARE.finditer(sentence):
                if m.group("object") in _KO_CARE_GENERIC:
                    continue
                start, end = s + m.start("object"), s + m.end("care")
                spans.append(_span(text, start, end, "HEALTH", "ko_care", KO_HEALTH_REPLACEMENT))
        if en_ok:
            for m in _EN_HEALTH.finditer(sentence):
                repl = KO_HEALTH_REPLACEMENT if _HANGUL.search(sentence) else EN_HEALTH_REPLACEMENT
                spans.append(_span(text, s + m.start(), s + m.end(), "HEALTH", "en_health", repl))
    return spans


# ---- ORG ----------------------------------------------------------------------------------------

_ORG_SUFFIX = (
    r"주식회사|㈜|\(주\)|저축은행|은행|병원|의원|대학교|학교|재단|협회|공사|그룹|물류|리테일|전자|"
    r"제약|증권|보험|캐피탈|물산|상사"
)
_ORG_TAIL = (
    r"(?=(?:에서는|에게는|에서|에게|에는|에도|에|의|은|는|이|가|을|를|과|와|으로|로|측|쪽|도|만|"
    r"까지|부터|이랑|랑|하고|이나|나|께|께서)?(?![가-힣A-Za-z0-9]))"
)
_ORG_RE = re.compile(
    rf"(?<![가-힣A-Za-z0-9&])(?P<name>[가-힣A-Za-z0-9&]{{1,20}}?)\s?(?P<suffix>주식회사|㈜|\(주\))"
    rf"{_ORG_TAIL}"
    rf"|(?<![가-힣A-Za-z0-9&])(?P<prefix>주식회사|㈜|\(주\))\s?(?P<pname>[가-힣A-Za-z0-9&]{{2,20}}?)"
    rf"{_ORG_TAIL}"
    rf"|(?<![가-힣A-Za-z0-9&])(?P<stem>[가-힣A-Za-z0-9&]{{1,20}}?)(?P<osuffix>{_ORG_SUFFIX})"
    rf"{_ORG_TAIL}"
)

_ORG_GENERIC_STEMS: dict[str, frozenset[str]] = _stem_table(
    """
    은행: 중앙 시중 투자 인터넷 지방 외국 외국계 국책 상업 협동 혈액 정자 난자 푸드 식품 시간 세계
        국제 제대혈 모유 유전자 주거래 거래 대형 해외 미국 일본 유럽 중국 저축 상호 개발
    저축은행: 상호 대형 지방 서민 중소형
    병원: 대학 대학교 종합 동물 요양 정신 치과 한방 소아과 산부인과 개인 대형 지역 동네 아동
        어린이 여성 재활 전문 공공 시립 도립 국립 국군 보훈 상급종합 협력 거점 이비인후과 안과
        피부과 정형외과 내과 외과 일반 근처 인근 지정 응급 격리 야간 주말 24시 24시간 중소
        대학부속 부속 전담 감염병전담 척추 관절 한의 성형외과 소아청소년과 가정의학과
    의원: 국회 시 구 도 군 시의회 광역 지방 기초 비례대표 지역구 초선 재선 다선 전직 현직 여당
        야당 치과 피부과 내과 외과 안과 이비인후과 정형외과 소아과 소아청소년과 산부인과
        가정의학과 신경과 정신과 정신건강의학과 비뇨기과 성형외과 동네 개인 한 동물
    대학교: 명문 국립 사립 지방 해외 외국 사이버 방송통신 전문 여자 교육 공립 주립 과학기술 4년제
        2년제 신학
    학교: 초등 고등 중고등 국제 대안 특수 외국인 직업 전문 음악 미술 체육 과학 외국어 예술 방송
        운전 요리 간호 신학 기숙 명문 사관 경찰 여자 남자 공업 상업 농업 정보 마이스터 혁신 공립
        사립 국립 시립 초 중 고 대 여자고등 여자중 남자고등 남자중 인문계 실업계 특성화 영재 자사
        외고 과고 초중 유치원 어린이집 주말 야간 방과후 계절 여름 겨울
    재단: 공익 비영리 민간 문화 장학 복지 교육 사회복지 자선 의료 학술 연구 가족 개인 기업 종교
        공공 국제 학교법인
    협회: 변호사 의사 약사 치과의사 한의사 간호 무역 은행 금융투자 소비자 경영자 부동산 공인중개사
        세무사 회계사 건축사 체육 축구 야구 농구 배구 기자 방송 영화 출판 게임 소프트웨어 벤처기업
        중소기업 여성 장애인 노인 학부모 입주자 상인 번영 업계 산업
    공사: 도로 인테리어 리모델링 철거 건설 토목 전기 설비 보수 방수 도색 배관 확장 증축 신축 수리
        하수도 상수도 지하철 터널 교량 도배 창호 시설 조경 난방 해체 굴착 포장 복구 보강 내부 외부
        대규모 소규모 긴급 야간 주말 공동 관급 민간 아파트 주택 상가 건물
    그룹: 스터디 포커스 워킹 피어 걸 보이 아이돌 밴드 혼성 남성 여성 대기업 재벌 계열 연구 실험
        대조 비교 고객 사용자 타겟 소규모 대규모 채팅 단톡 카톡 온라인 오픈 연령 위험 고위험
        저위험 혈액형 하위 상위 동일 같은 다른 해당 소 대 중 지지 자조 치료 상담 독서 기도 셀 모임
        사내 팀 업무 프로젝트 테스트 관리 보안 권한 사용자 리소스
    물류: 국제 택배 해운 항공 창고 유통 콜드체인 풀필먼트 도심 스마트 역 글로벌 이커머스 해상 육상
        철도 냉동 제3자 통합 첨단 자동화 공동 지역 국내 해외 역방향 반품 배송
    리테일: 온라인 오프라인 글로벌 대형 패션 이커머스 럭셔리 스마트 오프 옴니채널
    전자: 가전 소형 생활 전기 광 양 중 원 반도체 소비자 산업 자동차 의료 전력 정보 디지털 첨단
        마이크로 나노 유기 무기
    증권: 유가 채권 담보 국채 사채 보통 우선 전환 해외 국내 대형 중소형 온라인 금융 투자
    보험: 생명 손해 자동차 실손 실비 건강 고용 산재 국민건강 여행자 화재 치아 운전자 종신 연금
        변액 상해 배상책임 책임 의료 사회 장기요양 펫 반려동물 주택화재 태아 어린이 저축성 보장성
        단체 개인 민간 공적 재 암 간병 치매 정기 유병자 간편 해외여행 보증 수출 재해 농작물 풍수해
        고용산재 국민
    상사: 직장 직속 전 이전 새 옛 나쁜 좋은 무능한 여자 남자 여성 남성 담당 직접 중간 최고 윗
    물산: 농 수 축
    캐피탈: 벤처 사모 할부 리스 대형
    제약: 시간 예산 공간 기술 물리 자원 법적 법률 규제 설계 성능 메모리 하드웨어 운영 환경 조건
        여러 많은 일부 추가 입력 출력 타입 형식 무결성 외래키 데이터 도메인 비즈니스 자금 인력
        일정 현실 구조 시스템 플랫폼 정책 보안 네트워크 사용 접근 권한 거리 이동 활동 표현 선택
        행동 다국적 글로벌 국내 해외 외국계 바이오 대형 중소 복제약 신약 전통 제품 용량 크기 비용
        구현 호환
    주식회사:
    """
)
_ORG_COMMON_STEMS = frozenset(
    _words(
        """
        우리 저희 이 그 저 해당 모든 각 여러 다른 같은 대형 소형 중소 동네 근처 지역 국내 해외
        외국 국립 공립 사립 시립 대학 종합 전문 개인 민간 공공 어느 무슨 어떤 새 옛 전 현 본 귀 타
        """
    )
)
_PUBLIC_ORG_PREFIX = re.compile(
    r"^(?:한국|대한|서울|경기|부산|인천|대구|대전|광주|울산|세종|제주|국립|국민)"
)
_FAMOUS_ORGS = frozenset(
    _words(
        """
        삼성전자 LG전자 SK하이닉스 대우전자 위니아전자 삼성그룹 SK그룹 LG그룹 현대그룹 롯데그룹
        한화그룹 CJ그룹 GS그룹 포스코그룹 신세계그룹 두산그룹 카카오그룹 네이버그룹 효성그룹
        코오롱그룹 한진그룹 금호아시아나그룹 현대차그룹 현대자동차그룹 셀트리온그룹 미래에셋그룹
        KB금융그룹 신한금융그룹 하나금융그룹 우리금융그룹 농협금융그룹 국민은행 KB국민은행
        신한은행 우리은행 하나은행 KEB하나은행 농협은행 NH농협은행 기업은행 IBK기업은행 카카오뱅크
        토스뱅크 케이뱅크 SC제일은행 한국은행 산업은행 KDB산업은행 수출입은행 한국수출입은행
        씨티은행 한국씨티은행 부산은행 대구은행 iM뱅크 경남은행 광주은행 전북은행 제주은행
        수협은행 우체국 서울대학교 연세대학교 고려대학교 성균관대학교 한양대학교 이화여자대학교
        서강대학교 중앙대학교 경희대학교 한국외국어대학교 부산대학교 경북대학교 전남대학교
        포항공과대학교 한국과학기술원 하버드대학교 스탠퍼드대학교 옥스퍼드대학교 케임브리지대학교
        도쿄대학교 한국방송통신대학교 서울대병원 서울대학교병원 세브란스병원 삼성서울병원
        서울아산병원 서울성모병원 강남세브란스병원 분당서울대병원 분당서울대학교병원
        고려대안암병원 경희대병원 한양대병원 이대목동병원 존스홉킨스병원 삼성증권 미래에셋증권
        한국투자증권 NH투자증권 KB증권 키움증권 신한투자증권 하나증권 대신증권 메리츠증권
        유안타증권 교보증권 한화투자증권 토스증권 카카오페이증권 현대차증권 IBK투자증권 SK증권
        유진투자증권 LS증권 한양증권 부국증권 신영증권 DB손해보험 KB손해보험 한화손해보험
        롯데손해보험 MG손해보험 흥국화재보험 AIG손해보험 대웅제약 동아제약 보령제약 일동제약
        셀트리온제약 삼진제약 신풍제약 제일제약 광동제약 경동제약 대원제약 한국화이자제약
        현대캐피탈 KB캐피탈 롯데캐피탈 우리금융캐피탈 하나캐피탈 신한캐피탈 SBI저축은행 OK저축은행
        웰컴저축은행 페퍼저축은행 한국투자저축은행 GS리테일 BGF리테일 롯데리테일 CJ대한통운
        한국전력공사 한국토지주택공사 LH공사 한국도로공사 한국가스공사 한국수자원공사
        인천국제공항공사 한국공항공사 서울교통공사 한국철도공사 대한적십자사 한국무역협회
        대한의사협회 대한변호사협회 한국경영자총협회
        """
    )
)


def _org_generic(stem: str, suffix: str) -> bool:
    if stem in _ORG_COMMON_STEMS or stem in _ORG_GENERIC_STEMS.get(suffix, ()):
        return True
    if suffix in ("공사", "협회", "재단") and _PUBLIC_ORG_PREFIX.match(stem):
        return True
    return len(stem) < 2 or stem.isdigit()


def _org(text: str) -> list[Span]:
    spans = []
    for m in _ORG_RE.finditer(text):
        if m.group("suffix"):
            stem, suffix = m.group("name"), m.group("suffix")
        elif m.group("prefix"):
            stem, suffix = m.group("pname"), m.group("prefix")
        else:
            stem, suffix = m.group("stem"), m.group("osuffix")
        whole = re.sub(r"\s+", "", m.group())
        if whole in _FAMOUS_ORGS or re.sub(r"㈜|\(주\)|주식회사", "", whole) in _FAMOUS_ORGS:
            continue
        if _org_generic(stem, suffix):
            continue
        spans.append(_span(text, m.start(), m.end(), "ORG", "ko_org_suffix", None))
    return spans


# ---- PERSON -------------------------------------------------------------------------------------

_SURNAMES = (
    "김이박최정강조윤장임한오서신권황안송류유전홍고문양손배백허남심노하곽성차주우구민나진지엄채원천방"
    "공현함변염여추도석선설마길연위표명기반왕금옥육인맹제모탁국"
)
_COMPOUND_SURNAMES = "황보|남궁|제갈|선우|독고|사공|서문"
_TITLES_ANY = (
    r"대표님|대표|팀장님|팀장|부장님|부장|과장님|과장|차장님|차장|대리님|대리|사원|실장님|실장|주임님|주임|"
    r"상무님|상무|전무님|전무|이사님|본부장님|본부장|선생님|교수님|교수|원장님|원장|변호사님|변호사|"
    r"의사|고객님|고객|환자분|환자|기자님|기자|작가님|작가|간호사님|간호사|약사님|님|씨"
)
_PERSON_RE = re.compile(
    rf"(?<![가-힣])(?P<name>(?:{_COMPOUND_SURNAMES})[가-힣]{{1,2}}|[{_SURNAMES}][가-힣]{{1,3}}?)"
    rf"(?P<sep>\s?)(?P<title>{_TITLES_ANY})"
    rf"(?=(?:께서는|께서|에게|한테|이랑|하고|이나|이고|이며|인데|입니다|이세요|께|이|가|은|는|을|를|의|과|와|"
    rf"도|만|랑|들|로|에|과의|와의)?(?![가-힣]))"
)
# Titles that follow a name only when attached, or with a space after a 3-syllable name.
_NAME_BAD_LAST = frozenset("증과층급실팀처청측들분쪽께적형별의사장님군읍면")
_TITLE_WORDS = frozenset(
    _words(
        """
        대표 팀장 부장 과장 차장 대리 사원 실장 주임 상무 전무 이사 본부장 선생 교수 원장 변호사
        의사 고객 환자 기자 작가 간호사 약사 사장 회장 부사장 반장 소장 국장 기사
        """
    )
)
_NAME_STOPWORDS = frozenset(
    _words(
        """
        고객 선생 사장 부장 과장 차장 팀장 원장 교수 기사 박사 간호 의사 환자 손님 형님 선배 후배
        이사 대표 전무 상무 회장 실장 주임 강사 조교 조장 반장 소장 국장 부모 어머 아버 할머
        할아버 장모 장인 남편 아내 여보 신부 신랑 우리 저희 여러 모두 전원 이분 그분 저분 누구
        아무 모든 하나 서방 임금 공주 왕자 도련 사모 스승 주인 주민 시민 국민 회원 임원 직원 사원
        신입 인턴 막내 전임 후임 선임 담임 교감 교장 총장 학장 이장 통장 시장 장관 차관 총리 의원
        경비 이웃 동료 친구 조카 사촌 삼촌 이모 고모 형수 제수 성님 영감 대감 마님 도사 마음 솜
        이번 저번 지난 다음 최근 이전 신임 신규 기존 전체 주요 우수 장기 단골 일반 방문 신청 구매
        해당 담당 전담 주치의 지도 명예 석좌 정교수 부교수 조교수 국선 고문 사내 외부 내부 현지
        한국 미국 중국 일본 해외 국내 외국 우울증 고혈압 정신과 유치원 원어민 성형외과 한의원 동네
        옆집 윗집 아랫집 앞집 입주민 세입자 집주인 건물주 임대인 임차인 매도인 매수인 신고인
        피해자 가해자 용의자 피고인 원고 피고 정신 소아 노인 여성 남성 성인 청소년 신생아 중환자
        응급 입원 외래 초진 재진 여자 남자 수석 책임 부사장 정규직 계약직 파견 고객사 협력사
        거래처 공급사 하청 원청 유명 전문 인기 강남 서울 부산 인천 광주 울산 제주 수원 성남 용인
        고양 안양 안산 천안 전주 진주 창원 원주 구미 경주 김해 양산 남양주 하남 오산 이천 여주
        양평 홍천 강릉 동해 정선 제천 공주 서산 아산 정읍 남원 김제 여수 나주 안동 영주 상주 경산
        사천 서귀포 주식 기업 법인 개인 가족 모임 한분 두분 세분 여러분 이상 이하 미만 정도 대상
        우선 최우선 대기 예약 방문객 참석 지원 신청자 당첨 수상 유료 무료 정기 임시 기간제 파트
        전직 현직 차기 초대 역대 공동 부대 대체 가상 샘플 테스트 홍보 모델 전속 소속 담당자 관리
        운영 기획 개발 영업 인사 총무 재무 회계 법무 구매팀 생산 품질 연구 기술 마케팅
        """
    )
)
_PUBLIC_FIGURES = frozenset(
    _words(
        """
        이순신 세종대왕 장영실 허준 정약용 이황 이이 김구 안중근 유관순 윤봉길 김유신 광개토대왕
        신사임당 백종원 손흥민 이강인 김민재 류현진 박찬호 박지성 김연아 이재용 정의선 구광모
        최태원 신동빈 방시혁 김범수 이해진 봉준호 박찬욱 유재석 강호동 이재명 윤석열 문재인 박근혜
        이명박 노무현 김대중 김영삼 한강 조수미 정주영 이건희 반기문 조성진 임윤찬 황의조 김하성
        이정후 오타니 차범근 홍명보 서장훈
        """
    )
)


def _person(text: str) -> list[Span]:
    spans = []
    for m in _PERSON_RE.finditer(text):
        name, sep, title = m.group("name"), m.group("sep"), m.group("title")
        compound = name[:2] in _COMPOUND_SURNAMES.split("|")
        syllables = len(name)
        if name in _NAME_STOPWORDS or name in _PUBLIC_FIGURES or name[-1] in _NAME_BAD_LAST:
            continue
        if name[1:] in _TITLE_WORDS or name[2:] in _TITLE_WORDS:
            continue  # "김대리님", "박팀장님": surname + title, not a full name
        if syllables == 2 and (sep or title not in ("님", "씨")):
            continue  # "이번 과장", "최근 고객": two-syllable names need a direct 님/씨
        if syllables == 4 and not compound:
            continue
        if sep and syllables < 3:
            continue
        spans.append(
            _span(text, m.start("name"), m.end("name"), "PERSON", "ko_honorific_name", None)
        )
    return spans


# ---- entry point --------------------------------------------------------------------------------


def detect_rules(text: str) -> list[Span]:
    """Deterministic semantic proposals with offsets. Never fires inside placeholders."""
    if not text.strip():
        return []
    spans = _ko_quasi(text) + _en_quasi(text) + _health(text) + _org(text) + _person(text)
    return _outside_placeholders(text, spans)
