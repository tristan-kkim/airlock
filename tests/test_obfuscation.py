"""Korean adversarial encodings: normalized views, detection on them, and the gate.

Every value is synthetic. The forms come from the adversarial category of the eval: names with
their syllables apart or in separated jamo, phone numbers in Korean or Hanja numerals, digits in
full width or split over lines, and homoglyph letters.
"""

import json

import pytest

from airlock import gate
from airlock.detect.ko_rules import detect_rules
from airlock.detect.obfuscation import detect_obfuscated
from airlock.hashing import Hasher
from airlock.textnorm import basic_view, compact_view, detection_view, fuzzy_find

HASH = Hasher(b"obfuscation-test-key")


def found(text: str) -> list[tuple[str, str]]:
    return [(s.text, s.type) for s in detect_obfuscated(text)]


# ---- views ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "view"),
    [
        ("ㄱㅣㅁㅁㅣㄴㅈㅣ", "김민지"),
        ("ㅂㅏㄱㅅㅓㅇㅕㄴ", "박서연"),
        ("ㅋㅋㅋ 좋아", "ᄏᄏᄏ 좋아"),  # no vowel: nothing to compose
        ("Jаne Pаrk", "jane park"),  # Cyrillic а
    ],
)
def test_basic_view_composes_jamo_and_folds_homoglyphs(raw, view) -> None:
    assert basic_view(raw).text == view


def test_compact_view_composes_jamo_across_separators() -> None:
    assert compact_view("ㄱ ㅣ ㅁ ㅁ ㅣ ㄴ ㅈ ㅣ").text == "김민지"


@pytest.mark.parametrize(
    ("raw", "view"),
    [
        ("이름 정.민.준, 메일", "이름 정민준, 메일"),  # the comma ends the run
        ("김 민 지한테 연락해", "김민지한테 연락해"),
        ("이름: 박·서·연입니다", "이름: 박서연입니다"),
        ("번호는 공일공 공구일일 공구이오이고 내일", "번호는 010 0911 0925이고 내일"),
        ("〇一〇 二三四五 六七八九로", "010 2345 6789로"),
        ("９ ６ １ ２ １ ５ - ２ ８ ４ ９ ３ ４ ７", "961215-2849347"),
        ("그 일이 사이 좋게 끝났어", "그 일이 사이 좋게 끝났어"),  # short runs inside words
        ("이 책 좀 봐줘", "이책좀 봐줘"),  # joined in the view only; no rule fires on it
    ],
)
def test_detection_view(raw, view) -> None:
    v = detection_view(raw)
    assert v.text == view
    assert len(v.starts) == len(v.text) == len(v.ends)


def test_fuzzy_find_matches_a_name_in_jamo() -> None:
    text = "이름은 ㄱㅣㅁㅁㅣㄴㅈㅣ 입니다"
    [(s, e)] = fuzzy_find(text, "김민지")
    assert text[s:e] == "ㄱㅣㅁㅁㅣㄴㅈㅣ"


# ---- detection -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "value", "type_"),
    [
        ("명함 정리해줘: 이름 정.민.준, 직함 선임연구원.", "정.민.준", "PERSON"),
        ("명함 정리해줘: 이름 도-하-린, 직함 대리.", "도-하-린", "PERSON"),
        ("김 민 지 씨한테 서류 보내줘", "김 민 지", "PERSON"),
        ("ㄱㅣㅁㅁㅣㄴㅈㅣ 씨에게 연락해줘", "ㄱㅣㅁㅁㅣㄴㅈㅣ", "PERSON"),
        ("이름은 장 유 나. 서류에 넣어줘", "장 유 나", "PERSON"),
        (
            '음성 메모: "번호는 공일공 공구일일 공구이오이고 내일 전화 주세요."',
            "공일공 공구일일 공구이오",
            "CONTACT",
        ),
        ("연락처 영일영-사삼이일-팔팔칠육 으로 부탁", "영일영-사삼이일-팔팔칠육", "CONTACT"),
        ("〇一〇 二三四五 六七八九로 연락", "〇一〇 二三四五 六七八九", "CONTACT"),
        ("메일 jane.park＠example．com 로 보내", "jane.park＠example．com", "CONTACT"),
        (
            "법인카드 번호가 줄이 나뉘었어:\n５１２７２１４７\n１３７８８２１０\n사용자 확인",
            "５１２７２１４７\n１３７８８２１０",
            "FINANCIAL",
        ),
        ("카드번호 메모\n4774 4068\n8584 4904\n정산해줘", "4774 4068\n8584 4904", "FINANCIAL"),
    ],
)
def test_hidden_values_are_detected(text, value, type_) -> None:
    assert (value, type_) in found(text)


@pytest.mark.parametrize(
    "text",
    [
        "이 책 좀 봐줘. 그 일이 사이 좋게 끝났어.",
        "1부터 10까지 제곱 리스트 만들어줘: 1 4 9 16 25 36",
        "세종대왕이 한글을 창제한 배경을 설명해줘.",
        "주문 수량\n12\n8\n합계 알려줘",  # short lines, no card cue
        "김치찌개 4인분 레시피를 6인분으로 늘려줘.",
        "Plain ASCII text with 010-2345-6789 is left to the ordinary rules.",
    ],
)
def test_ordinary_text_adds_nothing(text) -> None:
    assert found(text) == []


def test_labeled_korean_names_are_rules() -> None:
    spans = {(s.text, s.rule) for s in detect_rules("예금주 강채원, 사용자: 정예준. 박하은입니다.")}
    assert ("강채원", "ko_labeled_name") in spans
    assert ("정예준", "ko_labeled_name") in spans
    assert ("박하은", "ko_labeled_name") in spans
    assert not [
        s for s in detect_rules("사용자 이름 확인하고 담당자 배정해줘") if s.type == "PERSON"
    ]


# ---- gate ----------------------------------------------------------------------------------------


def msg(text: str) -> dict:
    return {"messages": [{"role": "user", "content": text}]}


@pytest.mark.parametrize(
    ("term", "variant"),
    [
        ("김민지", "담당은 ㄱㅣㅁㅁㅣㄴㅈㅣ 입니다"),
        ("김민지", "담당은 ㄱ ㅣ ㅁ ㅁ ㅣ ㄴ ㅈ ㅣ"),
        ("Nightjar Labs", "Nіghtjаr Lаbs"),  # Cyrillic і and а
        ("010-2345-6789", "영일영 이삼사오 육칠팔구"),
        ("5127214713788210", "５１２７２１４７\n１３７８８２１０"),
    ],
)
def test_gate_blocks_new_variants_of_known_values(term, variant) -> None:
    decision = gate.check(
        msg(variant), [gate.Protected(term, "PERSON", "vault_original")], hasher=HASH
    )
    assert decision.decision == "block", variant


def test_gate_checks_high_confidence_patterns_on_the_normalized_text() -> None:
    # A resident registration number written in Korean numerals: nobody declared it.
    decision = gate.check(msg("주민번호 구육일이일오-이팔사구삼사칠 맞아?"), [], hasher=HASH)
    assert decision.decision == "block"
    assert decision.reasons[0].startswith("secret_pattern:kr_rrn:")
    assert gate.check(msg("사이 좋게 오늘 일이 잘 끝났어"), [], hasher=HASH).allowed


# ---- end to end ----------------------------------------------------------------------------------


def test_undeclared_obfuscated_values_are_masked_before_the_local_model(client, harness) -> None:
    text = (
        '명함 정리해줘: 이름 정.민.준, 직함 선임연구원. 음성 메모: "번호는 공일공 공구일일 '
        '공구이오이고 내일 전화 주세요."'
    )
    r = client.post("/v1/chat/completions", json={"messages": [{"role": "user", "content": text}]})
    assert r.status_code == 200, r.text
    sent = json.dumps(harness.upstream_requests[-1], ensure_ascii=False)
    assert "정.민.준" not in sent and "공일공 공구일일" not in sent
    assert "선임연구원" in sent  # a job title is not a value
    detector_input = json.dumps(harness.local_requests[0], ensure_ascii=False)
    assert "정.민.준" not in detector_input  # deterministic: hidden from the local model too
