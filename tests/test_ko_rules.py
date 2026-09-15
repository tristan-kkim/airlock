"""Deterministic Korean/English semantic rules: positives and benign negatives."""

import json

import pytest

from airlock.detect.gliner import ko_name
from airlock.detect.ko_rules import detect_rules, noun_shaped, plausible_name
from airlock.detect.shape import check_llm_span
from airlock.detect.spans import Span


def found(text: str) -> set[tuple[str, str]]:
    return {(s.type, s.text) for s in detect_rules(text)}


@pytest.mark.parametrize(
    ("text", "type_", "value"),
    [
        # quasi-identifiers
        (
            "판교 스타트업에서 유일한 여성 부사장인데 요즘 힘들어.",
            "QUASI_IDENTIFIER",
            "유일한 여성 부사장",
        ),
        (
            "마을에서 유일하게 한국어-포르투갈어 통역사로 일하는 58세 남성이야",
            "QUASI_IDENTIFIER",
            "유일하게 한국어-포르투갈어 통역사",
        ),
        (
            "우리 팀에서 혼자만 외국인 개발자라서 눈에 띄어",
            "QUASI_IDENTIFIER",
            "혼자만 외국인 개발자",
        ),
        ("본사에 단 한 명의 여성 임원이 있는데", "QUASI_IDENTIFIER", "단 한 명의 여성 임원"),
        (
            "I'm the only male nurse on the night shift at our clinic.",
            "QUASI_IDENTIFIER",
            "only male nurse on the night shift",
        ),
        ("She is the firm's sole Black partner.", "QUASI_IDENTIFIER", "sole Black partner"),
        # health
        ("제 동료 문태오 대리가 갑상선암 수술을 받아서 병가 중이에요", "HEALTH", "갑상선암 수술"),
        ("저는 우울증 진단을 받았고 프로작 복용 중입니다", "HEALTH", "프로작"),
        ("아내가 임신 12주차라서 야근이 어려워요", "HEALTH", "임신"),
        ("팀원이 공황장애로 정신과 다니고 있어요", "HEALTH", "정신과"),
        ("엄마가 HIV 양성 판정을 받았어", "HEALTH", "HIV"),
        ("My son was diagnosed with epilepsy last year.", "HEALTH", "epilepsy"),
        # organizations
        ("고객사 새론다움물류에 보낼 주간 보고 써줘", "ORG", "새론다움물류"),
        ("㈜누리소프트와 계약 조건을 정리해줘", "ORG", "㈜누리소프트"),
        ("한빛병원에서 받은 진료비 영수증", "ORG", "한빛병원"),
        ("가온저축은행 대출 연장 문의", "ORG", "가온저축은행"),
        ("미리내리테일 PM으로 일하고 있어", "ORG", "미리내리테일"),
        # names before honorifics and titles
        ("김서연님께 회의록을 보내주세요", "PERSON", "김서연"),
        ("주민등록번호가 있는 박지훈 고객의 청구 건", "PERSON", "박지훈"),
        ("문태오 대리가 내일 휴가야", "PERSON", "문태오"),
        ("남궁민수 팀장님과 통화했어요", "PERSON", "남궁민수"),
    ],
)
def test_rules_propose(text, type_, value) -> None:
    assert (type_, value) in found(text), found(text)


@pytest.mark.parametrize(
    "text",
    [
        "이게 유일한 방법은 아니지만 일단 해보자.",
        "유일하게 남은 선택지는 환불이야.",
        "혼자만의 시간이 필요해.",
        "The only way to fix this is to restart the server.",
        "It works only if the cache is warm; the sole purpose is speed.",
        "당뇨에 좋은 음식 알려줘.",
        "우울증 증상과 치료 방법을 설명해줘.",
        "Explain how insulin works in type 1 diabetes.",
        "삼성전자와 SK하이닉스의 반도체 전략을 비교해줘.",
        "국민은행 금리와 신한은행 금리를 비교해줘.",
        "초등학교 방학 숙제 아이디어 알려줘.",
        "국회의원 선거 제도를 설명해줘.",
        "시간제약이 있어서 인테리어 공사를 미뤘어.",
        "스터디그룹 운영 팁 알려줘.",
        "이순신 장군과 세종대왕의 업적을 정리해줘.",
        "백종원 대표의 창업 이야기를 요약해줘.",
        "고객님께 보낼 안내문을 써줘. 담당 과장님 확인 필요.",
        "이번 과장님 회의 안건 정리해줘.",
        "김대리님, 오늘 회의는 3시입니다.",
        "비밀번호 관리 모범 사례를 알려줘.",
    ],
)
def test_benign_text_stays_clean(text) -> None:
    assert found(text) == set()


def test_rules_never_fire_inside_placeholders() -> None:
    text = "<PERSON_1>님께 <ORG_1>물류 건으로 [[PERSON_2]] 씨와 < HEALTH_1 > 얘기"
    assert detect_rules(text) == []


def test_rule_spans_carry_offsets_and_generalizations() -> None:
    text = "판교에서 유일한 여성 부사장인데 우울증 진단을 받았어요."
    spans = {s.type: s for s in detect_rules(text)}
    quasi, health = spans["QUASI_IDENTIFIER"], spans["HEALTH"]
    assert text[quasi.start : quasi.end] == quasi.text
    assert quasi.action == "generalize" and quasi.replacement and quasi.source == "rule"
    assert health.action == "generalize" and health.replacement == "건강 문제"


# ---- name shape: common nouns are not people ----------------------------------------------------
#
# The demo recording `agent-resignation-ko` sent "<PERSON_8> 수급 자격 <PERSON_7>법": the model had
# proposed legal terms as people and nothing checked the shape of a Hangul PERSON span.

LEGAL_TERMS = [
    "실업급여", "퇴직금", "근로기준법", "수급 자격", "수급자격", "희망퇴직", "고용보험",
    "고용보험법", "위로금", "연차수당", "통상임금", "노무사", "자격증", "관리비", "권고사직",
    "정규직", "합의서", "임금", "급여", "서명",
]  # fmt: skip
NAMES = [
    "박성훈", "김민수", "이영희", "남궁민수", "황보이든", "선우다온", "정다은", "김진실", "박순금",
    "오세린", "문태오", "강채원", "박하은", "권소율", "김태형", "예진", "다은", "박 성훈",
    "김철수 이영희",
]  # fmt: skip


@pytest.mark.parametrize("term", LEGAL_TERMS)
def test_legal_and_common_terms_are_not_names(term) -> None:
    assert not plausible_name(term)
    span, outcome = check_llm_span(Span(text=term, type="PERSON", source="llm"), f"질문: {term}")
    assert span is None and outcome == "dropped"
    if " " not in term:
        assert ko_name(term) is None  # the GLiNER ensemble applies the same shape


@pytest.mark.parametrize("name", NAMES)
def test_names_keep_their_shape(name) -> None:
    assert plausible_name(name)
    span, outcome = check_llm_span(Span(text=name, type="PERSON", source="llm"), f"수신: {name}")
    assert span is not None and outcome == "ok"


def test_noun_shape_is_structural() -> None:
    assert noun_shaped("고용보험")  # four syllables without a compound surname
    assert not noun_shaped("남궁민수")
    assert noun_shaped("자격증") and noun_shaped("노무사")  # a syllable that ends nouns, not names
    assert not noun_shaped("김진실") and not noun_shaped("박순금")  # 실 and 금 end real names
    assert noun_shaped("위로금")  # listed: passes every structural check


def test_korean_search_query_with_legal_terms_is_not_blocked(client, harness) -> None:
    """The model proposes 실업급여 and 고용보험 as people; the query must still go out."""
    harness.entities = {"실업급여": ("PERSON", "mask", ""), "고용보험": ("PERSON", "mask", "")}
    harness.rewrite = lambda q, c: q
    query = "실업급여 수급 자격 고용보험법"
    r = client.post("/v1/search", json={"query": query, "max_results": 2})
    assert r.status_code == 200, r.text
    assert r.json()["outbound_query"] == query
    assert harness.tavily_requests[-1]["query"] == query


def test_korean_hr_document_keeps_its_terms_and_masks_the_name(client, harness) -> None:
    harness.entities = {
        "박성훈": ("PERSON", "mask", ""),
        "퇴직금": ("PERSON", "mask", ""),
        "희망퇴직": ("PERSON", "mask", ""),
        "고용보험": ("PERSON", "mask", ""),
    }
    text = (
        "박성훈 팀장은 희망퇴직 대상자다. 법정 퇴직금 외 위로금을 받고 고용보험 실업급여를 "
        "신청한다."
    )
    r = client.post("/v1/chat/completions", json={"messages": [{"role": "user", "content": text}]})
    assert r.status_code == 200, r.text
    sent = harness.upstream_requests[-1]["messages"][-1]["content"]
    assert sent.startswith("<PERSON_1> 팀장은 희망퇴직 대상자다.")
    assert "퇴직금 외 위로금을 받고 고용보험 실업급여를" in sent
    assert "PERSON_2" not in json.dumps(harness.upstream_requests[-1], ensure_ascii=False)
