"""Detector round two: one detection entry point, cross-slot masking, employer/unit/role links,
surrogate substitution and rehydration, entailed generalizations, new patterns. All offline."""

from __future__ import annotations

import asyncio
import json
import re
from datetime import date

import pytest

from airlock import generalize, surrogate
from airlock.config import ProtectionLevel, Settings, Substitution, load_settings
from airlock.detect import org_rules, regions
from airlock.detect.llm import LLMResult
from airlock.detect.patterns import detect_patterns
from airlock.detect.shape import check_llm_span, trim
from airlock.detect.spans import Span
from airlock.pipeline import Sanitizer, decode_json_text
from airlock.rehydrate import StreamRehydrator, rehydrate_arguments, rehydrate_text
from airlock.vault import Vault
from tests.conftest import completion
from tests.test_agent import (  # noqa: F401 - fixtures
    agent,
    call,
    final_of,
    make_agent_client,
    run_events,
    script,
    tool_reply,
)
from tests.test_gliner import fake_gliner  # noqa: F401 - fixture


def chat(client, content, headers=None):
    messages = content if isinstance(content, list) else [{"role": "user", "content": content}]
    return client.post("/v1/chat/completions", json={"messages": messages}, headers=headers or {})


def sent_text(harness) -> str:
    return harness.upstream_requests[-1]["messages"][-1]["content"]


class NoSpans:
    """A local detector that proposes nothing: only deterministic spans and rules remain."""

    model = None

    async def detect(self, text, original=None):
        return LLMResult()


def offline(substitution=Substitution.PLACEHOLDER, **kw) -> tuple[Sanitizer, Vault]:
    vault = Vault(":memory:")
    settings = Settings(substitution=substitution, **kw)
    return Sanitizer(settings, NoSpans(), vault), vault


def run(coro):
    return asyncio.run(coro)


# ---- 1. one detection entry point ---------------------------------------------------------------


def test_agent_search_guard_gets_gliner_spans(make_agent_client, agent, fake_gliner) -> None:  # noqa: F811
    """The search guard used to call the per-text detector and skipped the GLiNER ensemble."""
    agent.h.entities = {}
    fake_gliner.entities = {"Okafor": ("last_name", 0.95)}
    agent.rewrites = [lambda d: "Okafor severance rights", lambda d: "severance rights"]
    agent.h.upstream_reply = script(
        tool_reply(call("web_search", {"query": "Okafor severance rights"})),
        tool_reply(call("finish", {"answer": "done"})),
    )
    client = make_agent_client(gliner=True)
    events = run_events(client, docs=[("a.md", "Severance notes.")])
    assert final_of(events)["status"] == "finished"
    search = next(e for e in events if e.get("destination") == "tavily")
    # GLiNER's span (adjudicated yes) made the gate reject the first rewrite that kept it.
    assert search["attempts"][0]["gate_reasons"], search
    assert search["outbound_query"] == "severance rights"
    assert all("Okafor" not in r["query"] for r in agent.h.tavily_requests)


def test_agent_turn_uses_the_ensemble(make_agent_client, agent, fake_gliner) -> None:  # noqa: F811
    agent.h.entities = {}
    fake_gliner.entities = {"Zed Quillfeather": ("first_name", 0.95)}
    agent.h.upstream_reply = script(
        tool_reply(call("read_local_doc", {"doc_id": "doc-1"})),
        tool_reply(call("finish", {"answer": "ok"})),
    )
    client = make_agent_client(gliner=True)
    events = run_events(client, docs=[("a.md", "Dear Zed Quillfeather, your role ends.")])
    assert final_of(events)["status"] == "finished"
    wire = b"".join(agent.h.upstream_raw).decode()
    assert "Quillfeather" not in wire


# ---- 2. cross-slot masking ----------------------------------------------------------------------


def test_value_detected_in_one_slot_is_masked_in_every_slot(client, harness) -> None:
    harness.entities = {}
    harness.local_content = lambda user: json.dumps(
        {"spans": [{"text": "Mira Solberg", "type": "PERSON", "action": "mask", "replacement": ""}]}
        if "Dear Mira Solberg" in user
        else {"spans": []}
    )
    r = chat(
        client,
        [
            {"role": "user", "content": "Dear Mira Solberg, the contract is attached."},
            {"role": "assistant", "content": "Noted."},
            {"role": "user", "content": "Mira Solberg wants a summary."},
        ],
    )
    assert r.status_code == 200, r.text
    wire = json.dumps(harness.upstream_requests[-1], ensure_ascii=False)
    assert "Solberg" not in wire
    assert "<PERSON_1> wants a summary." in wire
    stats = client.get(f"/audit/{r.headers['x-airlock-request-id']}").json()["meta"]["detector"]
    assert stats["propagated"] >= 1


def test_search_context_value_is_masked_in_the_query() -> None:
    sanitizer, vault = offline()
    session = vault.session("s")
    query, context = "새론다움물류 구조조정 소식", "나 새론다움물류 다녀."
    results = run(sanitizer.sanitize_texts([query, context], session))
    assert "새론다움물류" not in results[0].text and "새론다움물류" not in results[1].text


# ---- 3. employer + unit + role ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "gone", "kept"),
    [
        (
            "동해누리정밀(주) 품질보증팀 박성훈 팀장에게 통보합니다.",
            ["동해누리정밀", "품질보증팀", "팀장"],
            ["품질 부서", "관리자"],
        ),
        (
            "청람로지스 판교 본사 보안팀 팀장이야.",
            ["판교 본사", "보안팀 팀장"],
            ["경기도 소재 본사"],
        ),
        (
            "I lead the Payments Platform team at Halcyon Freight Systems.",
            ["Payments Platform", "Halcyon Freight Systems"],
            ["the engineering team"],
        ),
        (
            "I'm a Senior Project Architect at Quarry Lane Architects.",
            ["Senior Project Architect", "Quarry Lane Architects"],
            ["I'm an architect at"],
        ),
        (
            "I'm the former CFO of a 30-person brewery in Cobalt Springs, Colorado.",
            ["Cobalt Springs"],
            ["a town in Colorado"],
        ),
        (
            "경북 새내군에서 사과 농사짓는 부부고 남편이 전직 변호사야.",
            ["새내군"],
            ["경상북도의 한 군 지역"],
        ),
        (
            "ER nurse at the only trauma center in Port Aldine, and I run marathons.",
            ["Port Aldine"],
            ["a local trauma center"],
        ),
        (
            "I work at Nettlefield Pharmacy Group's Tulsa plant and turned 52 in March.",
            ["Tulsa", "turned 52"],
            ["plant in Oklahoma", "in their 50s"],
        ),
    ],
)
def test_org_unit_role_link(text, gone, kept) -> None:
    sanitizer, vault = offline()
    [result] = run(sanitizer.sanitize_texts([text], vault.session("c")))
    for g in gone:
        assert g not in result.text, result.text
    for k in kept:
        assert k in result.text, result.text


@pytest.mark.parametrize(
    "text",
    [
        "우리 팀 회식 장소 추천해줘.",
        "마케팅팀 신입 교육 자료 목차 짜줘.",
        "Our marketing team wants a launch checklist.",
        "화장실 청소 체크리스트 만들어줘.",
        "고객센터 상담원 응대 스크립트 써줘.",
        "Explain how the Police Department handles noise complaints.",
        "Give me a template for a team lead's weekly update.",
        "The sales team at a SaaS company usually has SDRs and AEs. Explain the roles.",
        "연구실 안전 수칙 알려줘.",
        "I'm 34 and a nurse. What stretches help back pain?",
        "What is the weather like in Austin, Texas in May?",
        "양평군 맛집 추천해줘.",
        "Our only option in Denver is the downtown clinic.",
    ],
)
def test_benign_org_unit_text_is_untouched(text) -> None:
    sanitizer, vault = offline()
    [result] = run(sanitizer.sanitize_texts([text], vault.session("c")))
    assert result.text == text
    assert not [d for d in result.detections if d.action != "keep"]


def test_role_alone_needs_an_organization_or_unit() -> None:
    cands = org_rules.candidates("Senior Project Architect")
    assert [c.kind for c in cands] == ["role"]
    [[]] = org_rules.link(["I'm a Senior Project Architect."], [[]])
    [linked] = org_rules.link(["I'm a Senior Project Architect."], [[]], org_known=True)
    assert (
        linked
        and linked[0].replacement == "an architect"
        and linked[0].text == "a Senior Project Architect"
    )


def test_english_org_rule_negatives() -> None:
    assert [s.text for s in org_rules.en_orgs("My employer Halcyon Freight Systems")] == [
        "Halcyon Freight Systems"
    ]
    for text in ("The Operating Systems course", "Google Cloud Platform", "IT Solutions team"):
        assert org_rules.en_orgs(text) == [], text


# ---- 4. surrogates ------------------------------------------------------------------------------


KEY = b"k" * 32


def gen(value: str, type_: str, taken=lambda v: False, **kw) -> str | None:
    return surrogate.generate(value, type_, key=KEY, scope="conv", taken=taken, **kw)


@pytest.mark.parametrize(
    ("original", "type_", "shape"),
    [
        ("정다은", "PERSON", r"[가-힣]{3}"),
        ("남궁하람", "PERSON", r"(?:남궁|선우|독고|황보|제갈)[가-힣]{2}"),
        ("Jordan Albright", "PERSON", r"[A-Z][a-z]+ [A-Z][a-z]+"),
        ("새론다움물류", "ORG", r"[가-힣]+물류"),
        ("동해누리정밀(주)", "ORG", r"[가-힣]+정밀\(주\)"),
        ("Halcyon Freight Systems", "ORG", r"[A-Z][a-z]+(?: [A-Z][a-z]+)* Freight Systems"),
        ("010-2345-6789", "CONTACT", r"010-0000-[1-9]\d{3}"),
        ("jane.park@corp.co.kr", "CONTACT", r"[a-z0-9.]+@example\.com"),
        ("(415) 222-0133", "CONTACT", r"\(415\) 555-01\d\d"),
        ("900101-1234567", "ID_NUMBER", r"\d{2}00\d{2}-[1-4]\d{6}"),
        ("123-45-6789", "ID_NUMBER", r"000-\d{2}-\d{4}"),
        ("HFS-40418", "ID_NUMBER", r"HFS-\d{5}"),
        ("2026가합12345", "ID_NUMBER", r"2026가합\d{5}"),
        ("4532015112830366", "FINANCIAL", r"\d{16}"),
        ("경기도 성남시 분당구 은행나무샘길 88, 111동 2304호", "LOCATION",
         r"경기도 성남시 분당구 [가-힣]+(?:로|길) \d+, \d+동 \d+호"),
        ("433 Larkspur Lane, Richmond, VA", "LOCATION", r"\d+ [A-Z][a-z]+ Lane, Richmond, VA"),
    ],
)  # fmt: skip
def test_surrogate_shapes(original, type_, shape) -> None:
    value = gen(original, type_)
    assert value is not None and re.fullmatch(shape, value), value
    assert value != original


def test_surrogates_are_invalid_values() -> None:
    card = gen("4532015112830366", "FINANCIAL")
    digits = [int(c) for c in card]
    total = sum(
        d if i % 2 == 0 else (d * 2 - 9 if d > 4 else d * 2) for i, d in enumerate(digits[::-1])
    )
    assert total % 10 != 0  # fails Luhn
    assert detect_patterns(gen("900101-1234567", "ID_NUMBER")) == []  # not an RRN any more


def test_secrets_never_get_surrogates(client, harness) -> None:
    assert gen("sk-proj-Zx8Qw3Er5Ty7Ui9Op1As2Df4", "SECRET") is None
    assert gen("hunter2!", "SECRET") is None
    harness.entities = {"Jane Park": ("PERSON", "mask", "")}
    c = client.app.state.services.sanitizer
    c.settings = c.settings.with_overrides(substitution=Substitution.SURROGATE)
    r = chat(client, "Jane Park's API key is sk-proj-Zx8Qw3Er5Ty7Ui9Op1As2Df4, fix the config.")
    assert r.status_code == 200, r.text
    sent = sent_text(harness)
    assert "<SECRET_1>" in sent and "Jane Park" not in sent and "<PERSON_" not in sent


def test_unknown_shapes_fall_back_to_placeholders() -> None:
    assert gen("은하수다리", "PERSON") is None  # a declared project name typed PERSON
    assert gen("Project Halcyon", "PERSON") is None
    assert gen("mystery", "ORG") is None
    assert gen("Tulsa", "LOCATION") is None


def test_surrogate_collision_check() -> None:
    first = gen("정다은", "PERSON")
    second = gen("정다은", "PERSON", taken=lambda v: v == first)
    assert second and second != first
    assert surrogate.collides("김하늘", ["김하늘에게 전달"], [], [])
    assert surrogate.collides("010-0000-1234", [], ["0000-1234"], [])
    assert surrogate.collides("x@example.com", [], [], ["X@example.com"])


def test_surrogate_mode_end_to_end_is_consistent_and_rehydrates(client, harness) -> None:
    harness.entities = {"정다은": ("PERSON", "mask", ""), "새론다움물류": ("ORG", "mask", "")}
    services = client.app.state.services
    services.sanitizer.settings = services.sanitizer.settings.with_overrides(
        substitution=Substitution.SURROGATE
    )
    captured = {}

    def reply(payload):
        text = payload["messages"][-1]["content"]
        captured["sent"] = text
        name = re.search(r"담당자 ([가-힣]{3})", text).group(1)
        org = re.search(r"([가-힣]+물류)", text).group(1)
        captured.update(name=name, org=org)
        return completion(f"{name}님께: {org}과의 계약을 확인했습니다. {name}이 서명하면 됩니다.")

    harness.upstream_reply = reply
    headers = {"x-airlock-conversation-id": "surrogate-conv"}
    r = chat(
        client,
        "담당자 정다은님께 새론다움물류 계약서 확인 메일 써줘. 연락처 010-2345-6789",
        headers,
    )
    assert r.status_code == 200, r.text
    sent = captured["sent"]
    assert "정다은" not in sent and "새론다움물류" not in sent and "010-2345-6789" not in sent
    assert re.search(r"010-0000-\d{4}", sent) and "<" not in sent
    answer = r.json()["choices"][0]["message"]["content"]
    # particle after the restored value follows the original: 류 has no final consonant
    assert "새론다움물류와의 계약" in answer
    assert "정다은님께" in answer and "정다은이 서명" in answer

    # same conversation: same surrogate
    r2 = chat(
        client,
        "담당자 정다은님께 새론다움물류 계약서 확인 메일 써줘. 연락처 010-2345-6789",
        headers,
    )
    assert r2.status_code == 200
    assert captured["name"] in harness.upstream_requests[-1]["messages"][-1]["content"]
    audit = client.get(f"/audit/{r.headers['x-airlock-request-id']}").json()
    assert {d["action"] for d in audit["detections"]} == {"surrogate"}
    assert audit["meta"]["detector"]["surrogates"] == 3


@pytest.mark.parametrize(
    ("original", "surrogate_value", "answer", "expected"),
    [
        ("새론다움물류", "한빛정밀", "한빛정밀과의 계약", "새론다움물류와의 계약"),
        ("박지우", "김서준", "김서준이 말했다", "박지우가 말했다"),
        ("김민준", "이하나", "이하나가 말했다", "김민준이 말했다"),
        ("김민준", "이하나", "이하나는 이하나를", "김민준은 김민준을"),
        ("서울은행", "한결은행", "한결은행으로 이체", "서울은행으로 이체"),
        ("가온물류", "새솔정밀", "새솔정밀으로 보내", "가온물류로 보내"),
        ("Jordan Albright", "Casey Morrow", "Casey Morrow's file and Morrow's badge",
         "Jordan Albright's file and Albright's badge"),
        ("010-2345-6789", "010-0000-4821", "call 01000004821 now", "call 010-2345-6789 now"),
    ],
)  # fmt: skip
def test_rehydration_with_particles_and_possessives(original, surrogate_value, answer, expected):
    vault = Vault(":memory:")
    session = vault.session("c")
    session.surrogate(original, "PERSON" if " " in original else "ORG", surrogate_value)
    assert rehydrate_text(answer, session) == expected


def test_surrogate_rehydration_in_tool_arguments_and_streams() -> None:
    vault = Vault(":memory:")
    session = vault.session("c")
    session.surrogate("정다은", "PERSON", "김하늘")
    args = json.dumps({"to": "김하늘", "body": "김하늘은 확인"}, ensure_ascii=False)
    assert json.loads(rehydrate_arguments(args, session)) == {
        "to": "정다은",
        "body": "정다은은 확인",
    }

    stream = StreamRehydrator(session)
    out = (
        "".join(stream.feed(piece) for piece in ["안녕 김하", "늘", "은 잘 지내"]) + stream.flush()
    )
    assert out == "안녕 정다은은 잘 지내"
    stream = StreamRehydrator(session)
    out = "".join(stream.feed(p) for p in ["김하늘", "이 왔다"]) + stream.flush()
    assert out == "정다은이 왔다"


def test_placeholder_note_only_when_placeholders_remain(client, harness) -> None:
    harness.entities = {"Jane Park": ("PERSON", "mask", "")}
    services = client.app.state.services
    services.sanitizer.settings = services.sanitizer.settings.with_overrides(
        substitution=Substitution.SURROGATE
    )
    r = chat(client, "Write to Jane Park about the lease.")
    assert r.status_code == 200
    assert all(m["role"] != "system" for m in harness.upstream_requests[-1]["messages"])


def test_substitution_setting(monkeypatch) -> None:
    monkeypatch.setenv("AIRLOCK_SUBSTITUTION", "surrogate")
    assert load_settings(env_file=None).substitution is Substitution.SURROGATE
    monkeypatch.setenv("AIRLOCK_SUBSTITUTION", "decoy")
    with pytest.raises(ValueError):
        load_settings(env_file=None)


# ---- 5. entailed generalization -----------------------------------------------------------------


def g(text: str, replacement: str, type_: str = "QUASI_IDENTIFIER", context: str | None = None):
    span = Span(text=text, type=type_, action="generalize", replacement=replacement)
    return generalize.fix_generalization(span, context or text)


@pytest.mark.parametrize(
    ("original", "replacement", "context", "want"),
    [
        ("마흔다섯", "30대", "올해 마흔다섯이야", "40대"),
        ("45세", "in their 30s", "나이는 45세", "40대"),
        ("38", "30대", "38세 여성", None),  # already correct: unchanged
        ("turned 52", "in their 40s", "I turned 52 in March", "in their 50s"),
        ("1999-05-21", "in their 30s", "Date of birth: 1999-05-21", "born in the 1990s"),
    ],
)
def test_age_generalizations_contain_the_value(original, replacement, context, want) -> None:
    span, outcome = g(original, replacement, context=context)
    if want is None:
        assert outcome is None
    else:
        assert span.replacement == want and outcome == "fixed"
    age = generalize.age_of(original) or (
        generalize.age_from_birth(generalize.date_in(original))
        if generalize.date_in(original)
        else None
    )
    ranges = generalize.stated_ranges(span.replacement or "")
    if age is not None and ranges and "born" not in (span.replacement or ""):
        assert any(lo <= age <= hi for lo, hi in ranges)


def test_age_from_birth_date_is_computed_relative_to_today() -> None:
    assert generalize.age_from_birth(date(1999, 5, 21), date(2026, 9, 14)) == 27
    assert generalize.age_from_birth(date(1999, 12, 1), date(2026, 9, 14)) == 26
    assert generalize.decade_phrase(27, "en") == "in their 20s"


@pytest.mark.parametrize(
    ("original", "replacement", "want"),
    [
        ("성남시", "서울의 한 구", "경기도의 한 도시"),
        ("분당구", "a district in Seoul", "경기도의 한 자치구"),
        ("Tulsa", "a city in Texas", "a city in Oklahoma"),
        ("새내군", "North Korea", "한 군 지역"),
    ],
)
def test_places_generalize_to_a_containing_region(original, replacement, want) -> None:
    context = f"{original}에 살아" if re.search("[가-힣]", original) else f"I live in {original}"
    span, outcome = g(original, replacement, "LOCATION", context)
    assert outcome == "fixed" and span.replacement == want
    top = regions.ko_container(original) or regions.en_container(original)
    if top:
        assert regions.contains(top, original)


def test_region_containment_table() -> None:
    assert regions.contains("경기도", "성남시 분당구")
    assert not regions.contains("서울", "성남시")
    assert regions.contains("Oklahoma", "Tulsa")
    assert not regions.contains("Texas", "Tulsa")
    assert generalize.places_consistent("경북 새내군에서", "경상북도의 한 군") is True
    assert generalize.places_consistent("경북 새내군에서", "a district in North Korea") is False


def test_no_language_switching() -> None:
    span, outcome = g("공황장애", "an anxiety disorder", "HEALTH", "저 공황장애 진단받았어요")
    assert outcome == "fixed" and span.replacement == "불안장애"
    span, outcome = g("유일한 여성 부사장", "the only female VP", context="유일한 여성 부사장이야")
    assert outcome == "rejected"


def test_health_generalization_uses_local_entailment(client, harness) -> None:
    client.app.state.services.sanitizer.settings = client.app.state.services.sanitizer.settings
    harness.entities = {
        "lumbar disc herniation": ("HEALTH", "generalize", "back pain"),
        "Fabry disease": ("HEALTH", "generalize", "a rare genetic disorder"),
    }
    harness.entail = lambda o, r: "no" if r == "back pain" else "yes"
    r = chat(client, "My MRI shows lumbar disc herniation and I also have Fabry disease. Explain.")
    assert r.status_code == 200, r.text
    sent = sent_text(harness)
    assert "a spinal disc condition" in sent and "back pain" not in sent
    assert "a rare genetic disorder" in sent
    stats = client.get(f"/audit/{r.headers['x-airlock-request-id']}").json()["meta"]["detector"]
    assert stats["entailment_calls"] == 1


def test_balanced_keeps_situation_values_but_strict_does_not(client, harness, make_client) -> None:
    harness.entities = {
        "3,450,000원": ("FINANCIAL", "mask", ""),
        "HbA1c 7.2%": ("HEALTH", "generalize", "혈당 수치"),
        "당뇨병": ("HEALTH", "generalize", "만성 질환"),
        "홍소율": ("PERSON", "mask", ""),
    }
    text = "홍소율 기본급 3,450,000원이고 당뇨병이 있어 HbA1c 7.2%야. 공제율 정상이야?"
    r = chat(client, text)
    assert r.status_code == 200
    sent = sent_text(harness)
    assert "3,450,000원" in sent and "HbA1c 7.2%" in sent and "당뇨병" in sent
    assert "홍소율" not in sent
    strict = make_client(protection_level=ProtectionLevel.STRICT)
    chat(strict, text)
    sent = sent_text(harness)
    assert "3,450,000원" not in sent and "당뇨병" not in sent


def test_birth_dates_are_not_kept_as_situation() -> None:
    assert generalize.is_birth_date("생년월일 1990-03-02", 5, 15, "1990-03-02")
    assert not generalize.is_birth_date("결제일 2026-03-02", 4, 14, "2026-03-02")
    assert generalize.situation_value("2026-03-02") and generalize.situation_value("6,200만원")
    assert generalize.situation_value("500mg") and not generalize.situation_value("Jane Park")


@pytest.mark.parametrize(
    ("span_text", "type_", "want"),
    [
        ("정다은님", "PERSON", "정다은"),
        ("정다은", "PERSON", "정다은"),  # 은 is part of the name
        ("신소율 팀장님", "PERSON", "신소율"),
        ("Dr. Renata Oyelaran", "PERSON", "Renata Oyelaran"),
        ("invoice 9UUT-9586", "ID_NUMBER", "9UUT-9586"),
        ("새론다움물류과", "ORG", "새론다움물류"),
    ],
)
def test_spans_lose_honorifics_titles_and_labels(span_text, type_, want) -> None:
    assert trim(Span(span_text, type_), span_text).text == want


def test_honorific_is_not_doubled_on_rehydration(client, harness) -> None:
    harness.entities = {"정다은님": ("PERSON", "mask", "")}
    harness.upstream_reply = lambda p: completion("<PERSON_1>님, 안녕하세요.")
    r = chat(client, "정다은님께 안부 메일 써줘")
    assert r.status_code == 200
    assert sent_text(harness).startswith("<PERSON_1>님께")
    assert r.json()["choices"][0]["message"]["content"] == "정다은님, 안녕하세요."


# ---- 6. patterns, shapes, JSON decoding ---------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "value", "rule"),
    [
        ("alertWebhook: 'https://hooks.chat.example/services/T0AIbHs53lVv9wxbLnlb3B7Wjl'",
         "/services/T0AIbHs53lVv9wxbLnlb3B7Wjl", "webhook_url"),
        ("https://discord.com/api/webhooks/1234567890/abcDEFghiJKL123",
         "/api/webhooks/1234567890/abcDEFghiJKL123", "webhook_url"),
        ("f.pdf?X-Amz-Signature=abc123def456ghi789&x=1", "abc123def456ghi789", "signed_url_param"),
        ("문서 Q5F6-0648 빼고", "Q5F6-0648", "ticket_id"),
        ("ticket JIRA-4821 is open", "JIRA-4821", "ticket_id"),
        ("사건번호 2026가합12345 관련", "2026가합12345", "kr_case_number"),
        ("경기도 성남시 분당구 은행나무샘길 88, 111동 2304호, 현관",
         "경기도 성남시 분당구 은행나무샘길 88, 111동 2304호", "kr_address"),
        ("현관 비밀번호 38966240.", "38966240", "code_after_cue"),
        ("OTP 030846 입력", "030846", "code_after_cue"),
        ("Ship-to: 315 Larkspur Lane, Tucson, AZ.", "315 Larkspur Lane", "street_address"),
        ("병원 앱 비밀번호 yD4mB4vMBn는 메모용", "yD4mB4vMBn", "code_after_cue"),
    ],
)  # fmt: skip
def test_new_patterns(text, value, rule) -> None:
    assert (value, rule) in {(s.text, s.rule) for s in detect_patterns(text)}


@pytest.mark.parametrize(
    "text",
    [
        "ISO-9001 인증과 SHA-256, CVE-2024-1234 설명해줘",
        "COVID-19 vaccine schedule",
        "비밀번호를 2024년에 바꿨어",
        "인증번호 6자리를 입력하세요",
        "see https://example.com/services/consulting-2024",
        "The password is incorrect.",
        "UTF-8 and AES-256 encryption",
    ],
)
def test_new_pattern_negatives(text) -> None:
    rules = {"webhook_url", "signed_url_param", "ticket_id", "kr_case_number", "code_after_cue"}
    assert not [s for s in detect_patterns(text) if s.rule in rules], text


@pytest.mark.parametrize(
    ("span_text", "type_", "outcome", "new_type"),
    [
        ("010-2345-6789", "ORG", "retyped", "CONTACT"),  # a phone read as an affiliation
        ("283-910-22841", "CONTACT", "retyped", "FINANCIAL"),  # an account read as a contact
        ("ci-runner", "ORG", "dropped", None),
        ("체외수정 시술", "SECRET", "dropped", None),
        ("minsu_92", "CONTACT", "ok", "CONTACT"),
        ("솔바람7788", "SECRET", "ok", "SECRET"),
    ],
)
def test_llm_spans_must_have_the_shape_of_their_type(span_text, type_, outcome, new_type) -> None:
    span, got = check_llm_span(Span(span_text, type_), f"text with {span_text} inside")
    assert got == outcome
    assert (span.type if span else None) == new_type


def test_unicode_escaped_tool_arguments_are_decoded_before_detection(client, harness) -> None:
    harness.entities = {"강채원": ("PERSON", "mask", "")}
    args = json.dumps({"recipient_name": "강채원", "note": "계약 확인"})  # ensure_ascii escapes
    assert "\\uac15" in args
    assert json.loads(decode_json_text(args)) == json.loads(args)
    assert "강채원" in decode_json_text(args)
    messages = [
        {"role": "user", "content": "메일 보내줘"},
        {"role": "assistant", "content": None,
         "tool_calls": [{"id": "c1", "type": "function",
                         "function": {"name": "send_mail", "arguments": args}}]},
        {"role": "tool", "tool_call_id": "c1", "content": '{"status": "sent"}'},
    ]  # fmt: skip
    r = chat(client, messages)
    assert r.status_code == 200, r.text
    wire = harness.upstream_raw[-1].decode()
    sent_args = harness.upstream_requests[-1]["messages"][-2]["tool_calls"][0]["function"][
        "arguments"
    ]
    assert json.loads(sent_args)["recipient_name"] == "<PERSON_1>"
    assert "\\uac15" not in wire and "강채원" not in wire


def test_json_keys_of_tool_arguments_are_never_rewritten(client, harness) -> None:
    """GLiNER once read `doc_id` as an HTTP cookie; a placeholder key breaks the call and the gate
    then blocks the turn because the tool schema still holds the key."""
    harness.entities = {"doc_id": ("SECRET", "mask", ""), "Mira Solberg": ("PERSON", "mask", "")}
    args = json.dumps({"doc_id": "doc-1", "note": "for Mira Solberg"})
    messages = [
        {"role": "user", "content": "read it"},
        {"role": "assistant", "content": None,
         "tool_calls": [{"id": "c1", "type": "function",
                         "function": {"name": "read_local_doc", "arguments": args}}]},
        {"role": "tool", "tool_call_id": "c1", "content": "text"},
    ]  # fmt: skip
    r = chat(client, messages)
    assert r.status_code == 200, r.text
    sent = harness.upstream_requests[-1]["messages"][-2]["tool_calls"][0]["function"]["arguments"]
    assert json.loads(sent) == {"doc_id": "doc-1", "note": "for <PERSON_1>"}


def test_gliner_secret_shape_rejects_identifiers() -> None:
    from airlock.detect.gliner import LABELS_BY_NAME, shape_ok

    assert not shape_ok("doc_id", LABELS_BY_NAME["http_cookie"])
    assert not shape_ok("api-key", LABELS_BY_NAME["password"])
    assert shape_ok("hunter2!", LABELS_BY_NAME["password"])


def test_titles_do_not_cross_lines_and_surrogates_avoid_request_originals() -> None:
    text = "Employer: Northgate Community Credit Union\nManager: Tom Albrecht\nRole: Teller"
    assert not [c for c in org_rules.candidates(text) if "\n" in text[c.start : c.end]]
    assert surrogate.collides("Larkmoor Community Credit Union", [], ["Credit Union"], [])


def test_surrogate_details_that_answers_repeat_stay_true() -> None:
    card = gen("5106 1241 9510 7109", "FINANCIAL")
    assert card.endswith("7109") and card != "5106 1241 9510 7109"
    assert not set(gen("Imani Vasquez-Hale", "PERSON").split()[0:1]) & {"Felix", "Nadia", "Ingrid"}
    vault = Vault(":memory:")
    session = vault.session("c")
    session.surrogate("Linden Vale Clinic", "ORG", "Duskwood Foxglove Clinic")
    assert (
        rehydrate_text("You tested at Duskwood Foxglove.", session) == "You tested at Linden Vale."
    )
