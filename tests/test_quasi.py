"""Quasi-identifier combinations (`airlock.detect.quasi`) and the Korean over-masking fixes.

The prompts are synthetic and written for these tests; none is an eval case.
"""

import pytest

from airlock.config import ProtectionLevel
from airlock.detect import gliner, quasi
from airlock.detect.gliner import personal_context
from airlock.detect.spans import Span
from tests.test_gliner import FakeGliner, chat, outbound

BALANCED = ProtectionLevel.BALANCED


@pytest.fixture
def ensemble(make_client, monkeypatch):
    """(client with the GLiNER ensemble on, its fake model)."""
    fake = FakeGliner()
    monkeypatch.setattr(gliner, "availability_problem", lambda settings: None)
    monkeypatch.setattr(gliner.GlinerModel, "_load", lambda self: fake)
    return make_client(gliner=True), fake


def coarse(text: str, level: ProtectionLevel = BALANCED, spans=()) -> dict[str, str]:
    return {s.text: s.replacement for s in quasi.coarsen(text, list(spans), level)}


def categories(text: str) -> dict[str, str]:
    return {text[a.start : a.end]: a.category for a in quasi.attributes(text)}


# ---- attributes ----------------------------------------------------------------------------------


def test_korean_attribute_categories() -> None:
    text = (
        "충남 바람골면 보건지소의 유일한 소아과 전문의(남, 38세)이고 2015년 임용 수석이었어. "
        "봉사 모임에서 받은 은메달 얘기도 있어."
    )
    found = categories(text)
    assert found["바람골면 보건지소"] == "org"  # the named institution wins over its place
    assert found["소아과 전문의"] == "role"
    assert found["38세"] == "age"
    assert found["2015년 임용"] == "cohort"
    assert found["수석"] == "rare"
    assert found["유일한"] == "rare"


def test_english_attribute_categories() -> None:
    text = (
        "I'm 41, a twin, and the only night-shift radiologist at Fernhollow Medical Center in "
        "Brackett Springs, Montana; I joined in 2016."
    )
    found = categories(text)
    assert found["I'm 41"] == "age"
    assert found["night-shift radiologist"] == "role"
    assert found["Fernhollow Medical Center"] == "org"
    assert found["Brackett Springs, Montana"] == "place"
    assert found["joined in 2016"] == "cohort"
    assert found["a twin"] == "rare"


def test_roles_of_other_people_are_not_the_subjects() -> None:
    text = "우리 학교 교장 갑질을 제보하고 싶어. 담임목사 헌금 문제도 있어."
    assert "role" not in categories(text).values()
    assert "role" not in categories("Report my sergeant's retaliation.").values()


# ---- scoring and coarsening ----------------------------------------------------------------------


def test_combination_is_coarsened_most_identifying_first() -> None:
    text = (
        "달빛섬 보건지소의 유일한 소아과 전문의(여, 44세)인데 소장 갑질을 투서하려고 해. "
        "문장 다듬어줘."
    )
    out = coarse(text)
    assert out["달빛섬 보건지소"] == "한 보건지소"
    assert out["44세"] == "40대"
    assert out["소아과 전문의"] == "의사"
    assert "유일한" not in out  # a uniqueness claim is kept: it is usually the situation


def test_cohort_and_rank_become_bands() -> None:
    text = "세종시 한 부처 5급 사무관이고 2021년 행정고시 수석이었어. 익명 제보 초안 부탁해."
    out = coarse(text)
    assert out["2021년 행정고시"] == "2020년대 행정고시"
    assert "수석" in out or "5급 사무관" in out
    assert quasi.score([a for a in quasi.attributes(text) if text[a.start : a.end] not in out]) < 3


def test_english_combination_reads_naturally() -> None:
    text = (
        "My mom, 58, is the only Tagalog-speaking pediatric oncologist in Larkspur Falls, "
        "Nevada. How do I help her prepare for a deposition?"
    )
    out = coarse(text)
    assert out["58"] == "in her 50s"
    assert out["pediatric oncologist"] == "physician"  # no article after "Tagalog-speaking"
    assert out["Larkspur Falls, Nevada"] == "a town in Nevada"


def test_article_before_the_span_joins_it() -> None:
    text = "I'm a left-handed helicopter mechanic."
    start = text.index("left-handed")
    assert quasi._fit_article(text, start, "a technician") == (text.index("a left"), "a technician")
    text = "the only Tagalog-speaking oncologist"
    assert quasi._fit_article(text, text.index("oncologist"), "a physician")[1] == "physician"
    text = "works in Brackett Springs, Montana"
    assert quasi._fit_article(text, text.index("Brackett"), "a town in Montana")[1] == (
        "a town in Montana"
    )


def test_below_k_nothing_changes() -> None:
    assert coarse("저는 초등학교 교사이고 45세야. 수업 자료 만들어줘.") == {}
    assert coarse("I'm a nurse in Tulsa, Oklahoma. Any tips for night shifts?") == {}


def test_strict_uses_k_2_and_minimal_is_off() -> None:
    text = "저는 제주 모래울마을에 사는데 어촌계 가입 서류 알려줘."
    assert coarse(text) == {}  # one fine place scores 2: below k at balanced
    assert coarse(text, ProtectionLevel.STRICT) == {"제주 모래울마을": "제주의 한 마을"}
    assert coarse(text, ProtectionLevel.MINIMAL) == {}


def test_covered_attributes_do_not_count() -> None:
    text = "우리 아빠가 부산 사하구 해오름교회의 전도사고 61세야. 위로 편지 써줘."
    assert coarse(text)
    church = text.index("해오름교회")
    masked = [
        Span("해오름교회", "ORG", start=church, end=church + 5, source="rule"),
        Span("61세", "QUASI_IDENTIFIER", action="generalize", replacement="60대", source="llm"),
    ]
    assert coarse(text, spans=masked) == {}


def test_the_asked_about_attribute_is_kept() -> None:
    text = (
        "My wife is the only female airline captain at her base and she's 47. "
        "Can the airline ground her?"
    )
    out = coarse(text)
    assert "female airline captain" not in out  # "airline" is what the question is about
    assert out == {"47": "in her 40s"}


def test_text_about_nobody_is_left_alone() -> None:
    text = "경주 불국사 석굴암 1박 2일 여행 코스 추천해줘. 2019년 입학 기준 학번은 19학번이야."
    assert coarse(text) == {}


def test_job_titles_are_not_organizations() -> None:
    assert quasi.is_job_title("선임연구원")
    assert quasi.is_job_title("직함 선임연구원")
    assert quasi.is_job_title("CTO")
    assert not quasi.is_job_title("해오름소프트")


# ---- pipeline ------------------------------------------------------------------------------------


def test_pipeline_coarsens_the_combination(client, harness) -> None:
    text = (
        "달빛섬 보건지소의 유일한 소아과 전문의(여, 44세)인데 소장 갑질을 투서하려고 해. 다듬어줘."
    )
    r = client.post("/v1/chat/completions", json={"messages": [{"role": "user", "content": text}]})
    assert r.status_code == 200, r.text
    sent = harness.upstream_requests[-1]["messages"][-1]["content"]
    assert "달빛섬" not in sent and "소아과 전문의" not in sent and "44세" not in sent
    assert "한 보건지소" in sent and "의사" in sent and "40대" in sent
    assert "갑질" in sent and "투서" in sent
    stats = client.get(f"/audit/{r.headers['x-airlock-request-id']}").json()["meta"]["detector"]
    assert stats["quasi_coarsened"] == 3


def test_public_figure_and_job_title_spans_are_dropped(client, harness) -> None:
    harness.entities = {
        "장영실이": ("PERSON", "mask", ""),
        "선임연구원": ("ORG", "mask", ""),
    }
    r = client.post(
        "/v1/chat/completions",
        json={
            "messages": [
                {
                    "role": "user",
                    "content": "장영실이 만든 자격루 원리 설명해줘. 직함은 선임연구원.",
                }
            ]
        },
    )
    assert r.status_code == 200, r.text
    sent = harness.upstream_requests[-1]["messages"][-1]["content"]
    assert "장영실이" in sent and "선임연구원" in sent


# ---- Korean benign searches ----------------------------------------------------------------------


def test_personal_context() -> None:
    assert not personal_context(["KTX 서울 부산 소요시간"], [[]])
    assert not personal_context(["2026 minimum wage US"], [[]])
    assert personal_context(["우리 회사 구조조정 소문"], [[]])
    assert personal_context(["can my employer fire me"], [[]])
    assert personal_context(["소요시간"], [[Span("정민준", "PERSON", source="llm")]])


@pytest.mark.parametrize(
    ("query", "entity"),
    [("KTX 서울 부산 소요시간", "KTX"), ("경주 불국사 석굴암 1박 2일 여행 코스", "불국사")],
)
def test_benign_korean_search_keeps_its_topic(ensemble, harness, query, entity):
    client, fake_gliner = ensemble
    fake_gliner.entities = {entity: ("company_name", 0.9)}
    harness.rewrite = lambda q, c: q  # a rewrite that keeps the public name
    r = client.post("/v1/search", json={"query": query, "max_results": 2})
    assert r.status_code == 200, r.text
    assert harness.tavily_requests[-1]["query"] == query
    audit = client.get(f"/audit/{r.json()['request_id']}").json()
    assert audit["detections"] == [] and audit["gate"]["decision"] == "allow"


def test_company_in_a_personal_search_is_still_masked(ensemble, harness):
    client, fake_gliner = ensemble
    fake_gliner.entities = {"해오름물산": ("company_name", 0.9)}
    harness.rewrite = lambda q, c: "해오름물산 구조조정"
    r = client.post(
        "/v1/search", json={"query": "우리 회사 해오름물산 구조조정 대상 기준", "max_results": 2}
    )
    assert r.status_code == 422
    assert r.json()["error"]["reasons"][0].startswith("vault_original:ORG:")


def test_chat_with_gliner_company_and_person_cue_still_adjudicates(ensemble, harness):
    client, fake_gliner = ensemble
    fake_gliner.entities = {"누리온": ("company_name", 0.9)}
    r = chat(client, "제가 다니는 누리온 연봉 협상 메일 써줘")
    assert r.status_code == 200
    assert "누리온" not in outbound(harness)
    assert any("span adjudicator" in q["messages"][0]["content"] for q in harness.local_requests)
