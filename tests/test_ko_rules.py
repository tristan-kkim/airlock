"""Deterministic Korean/English semantic rules: positives and benign negatives."""

import pytest

from airlock.detect.ko_rules import detect_rules


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
