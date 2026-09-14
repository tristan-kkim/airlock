"""S9: answer distortion. Each test pins one mechanism found in the S6 test-split answers
(`eval/results/s9-distortion/DIAGNOSIS.md`) or in the dev-split payloads. All offline."""

from __future__ import annotations

import json

from airlock import generalize, placeholders
from airlock.detect.patterns import detect_patterns
from airlock.detect.shape import trim
from airlock.detect.spans import Span
from airlock.detect.term_type import infer_term_type
from airlock.pipeline import PLACEHOLDER_NOTE, placeholder_note
from airlock.rehydrate import StreamRehydrator
from airlock.vault import Vault
from tests.conftest import completion
from tests.test_gliner import fake_gliner  # noqa: F401 - fixture


def chat(client, content):
    return client.post(
        "/v1/chat/completions", json={"messages": [{"role": "user", "content": content}]}
    )


def sent(harness) -> list[dict]:
    return harness.upstream_requests[-1]["messages"]


# ---- placeholder type of declared terms ----------------------------------------------------------


def test_untyped_terms_get_org_project_person_or_term() -> None:
    batch = ["남궁하람", "새론다움물류", "누리결파트너스", "프로젝트 물수제비"]
    batch += ["Sableridge Media", "Sableridge", "Harrowgate Biosystems", "Project Nightjar"]
    batch += ["Marisol Szymborski"]
    types = {t: infer_term_type(t, batch) for t in batch}
    assert types == {
        "남궁하람": "PERSON",
        "새론다움물류": "ORG",
        "누리결파트너스": "ORG",
        "프로젝트 물수제비": "PROJECT",
        "Sableridge Media": "ORG",
        "Sableridge": "ORG",  # the leading word of a declared organization
        "Harrowgate Biosystems": "ORG",
        "Project Nightjar": "PROJECT",
        "Marisol Szymborski": "PERSON",
    }
    assert infer_term_type("Wolvercote") == "TERM"  # nothing says what it is


def test_vault_infers_types_only_when_the_client_gives_none() -> None:
    vault = Vault(":memory:")
    vault.add_terms(["해솔마루바이오", "남궁하람"])
    vault.add_terms(["Kestrel"], "ORG")
    vault.add_terms(["Wolvercote Energy"])
    vault.add_terms(["Wolvercote"])  # an earlier declared organization counts
    assert {t.text: t.type for t in vault.terms()} == {
        "해솔마루바이오": "ORG",
        "남궁하람": "PERSON",
        "Kestrel": "ORG",
        "Wolvercote Energy": "ORG",
        "Wolvercote": "ORG",
    }


def test_two_organizations_do_not_go_out_as_two_people(client, harness) -> None:
    client.post("/vault/terms", json={"terms": ["남궁하람", "새론다움물류", "해솔마루바이오"]})
    r = chat(client, "새론다움물류에서 해솔마루바이오와 함께한 출시 글 써줘. 작성자는 남궁하람.")
    assert r.status_code == 200, r.text
    text = sent(harness)[-1]["content"]
    assert "<ORG_1>에서 <ORG_2>와" in text and "<PERSON_1>" in text


def test_model_span_wider_than_a_declared_term_is_dropped(client, harness) -> None:
    """A model span around a declared term: "데이터 이관은 선우다온 담당" went out as
    "데이터 <PERSON_4> 담당"."""
    client.post("/vault/terms", json={"terms": ["선우다온", "황보이든", "사공나래"]})
    harness.entities = {
        "이관은 선우다온": ("PERSON", "mask", ""),
        "황보이든. 사공나래": ("CONTACT", "mask", ""),
    }
    r = chat(client, "데이터 이관은 선우다온 담당. 담당자는 황보이든. 사공나래 명의로 메일 써줘.")
    assert r.status_code == 200, r.text
    text = sent(harness)[-1]["content"]
    assert "데이터 이관은 <PERSON_1> 담당" in text
    assert "담당자는 <PERSON_2>. <PERSON_3> 명의로" in text


# ---- the upstream note ---------------------------------------------------------------------------


def test_note_says_tokens_are_real_values_and_lists_their_kinds(client, harness) -> None:
    harness.entities = {
        "Jordan Rasmussen": ("PERSON", "mask", ""),
        "jordan.r19@example.org": ("CONTACT", "mask", ""),
    }
    r = chat(client, "Write to Jordan Rasmussen (jordan.r19@example.org) about the lease.")
    assert r.status_code == 200, r.text
    note = sent(harness)[0]["content"]
    assert note.startswith(PLACEHOLDER_NOTE)
    assert "never tell the user that a value is a placeholder" in note
    assert "Do not compute anything from a token" in note
    assert note.endswith(
        "In this conversation: <CONTACT_n> is a phone number, e-mail address or handle; "
        "<PERSON_n> is a person's name."
    )
    assert "Jordan" not in note and "example.org" not in note


def test_note_without_placeholders_has_no_legend() -> None:
    assert "In this conversation" not in placeholder_note(["no tokens here"])
    assert "<ORG_n> is an organization's name" in placeholder_note(["<ORG_1> and [[ORG_2]]"])


# ---- rehydration ---------------------------------------------------------------------------------


def test_last_four_digits_restore_only_the_last_four() -> None:
    known = {"FINANCIAL_1": "5811 9184 6707 5448", "ID_NUMBER_1": "S9J918BD6G"}.get
    out = placeholders.rehydrate(
        "Card (last 4 digits only): **<FINANCIAL_1>**. Account ending in <FINANCIAL_1>. "
        "카드 끝자리 <FINANCIAL_1>입니다. Card number: <FINANCIAL_1>. Student ID <ID_NUMBER_1>.",
        known,
    )
    assert out == (
        "Card (last 4 digits only): **5448**. Account ending in 5448. 카드 끝자리 5448입니다. "
        "Card number: 5811 9184 6707 5448. Student ID S9J918BD6G."
    )


def test_last_four_digits_across_stream_chunks() -> None:
    class Session:
        def original_for(self, key):
            return {"FINANCIAL_1": "5811 9184 6707 5448"}.get(key)

        def surrogate_pairs(self):
            return []

    stream = StreamRehydrator(Session())  # type: ignore[arg-type]
    out = stream.feed("Re: account ending in ") + stream.feed("<FINANCIAL_1> and ") + stream.flush()
    assert out == "Re: account ending in 5448 and "


def test_korean_particle_follows_the_restored_value() -> None:
    known = {"PERSON_1": "남궁하람", "ORG_1": "새론다움물류", "PERSON_2": "Jordan"}.get
    out = placeholders.rehydrate("<PERSON_1>가 <ORG_1>과 협업했고 <PERSON_2>가 도왔다.", known)
    assert out == "남궁하람이 새론다움물류와 협업했고 Jordan가 도왔다."


# ---- values the answer needs ---------------------------------------------------------------


def test_schedules_lab_values_and_labeled_amounts_are_situation() -> None:
    assert generalize.situation_value("7시, 11시, 15시, 19시", "FINANCIAL")
    assert generalize.situation_value("8:30 a.m.") and generalize.situation_value("오전 9시 반")
    assert generalize.situation_value("fasting glucose 162 mg/dL", "HEALTH")
    assert generalize.situation_value("eGFR 88", "QUASI_IDENTIFIER")
    assert generalize.situation_value("월 소득 290만원", "FINANCIAL")
    assert generalize.situation_value("90 days overdue, $46,500", "FINANCIAL")
    assert generalize.situation_value("90일째 안 주고 있어(4,650만원)", "FINANCIAL")
    assert generalize.situation_value("sold 120 shares bought 14 months ago at $312", "FINANCIAL")
    assert not generalize.situation_value("$84,300 from Greyloft Studios", "FINANCIAL")
    assert not generalize.situation_value("acct 4471-2290, $46,500", "FINANCIAL")
    assert not generalize.situation_value("account 11413888539", "FINANCIAL")
    assert not generalize.situation_value("193-364014-02-231", "FINANCIAL")


def test_dose_times_and_lab_values_stay_in_the_request(client, harness) -> None:
    harness.entities = {
        "신수아": ("PERSON", "mask", ""),
        "7시, 11시, 15시, 19시": ("FINANCIAL", "mask", ""),
        "fasting glucose 162 mg/dL": ("HEALTH", "mask", ""),
        "eGFR 88": ("QUASI_IDENTIFIER", "mask", ""),
    }
    chat(client, "어머니 신수아, 레보도파 하루 4회(7시, 11시, 15시, 19시).")
    assert "(7시, 11시, 15시, 19시)" in sent(harness)[-1]["content"]
    chat(client, "Labs: HbA1c 7.9%, fasting glucose 162 mg/dL, LDL 171 mg/dL, eGFR 88.")
    assert "fasting glucose 162 mg/dL" in sent(harness)[-1]["content"]
    assert "eGFR 88" in sent(harness)[-1]["content"]


def test_a_number_the_request_computes_with_is_not_an_account(client, harness) -> None:
    harness.entities = {"479001600": ("FINANCIAL", "mask", "")}
    chat(client, "Is 479001600 equal to 12 factorial? Show the steps.")
    assert "Is 479001600 equal to 12 factorial?" in sent(harness)[-1]["content"]
    assert not generalize.arithmetic_number("card 5811918467075448, compute the fee", None, None,
                                            "5811918467075448")  # fmt: skip


def test_a_diagnosis_is_not_an_identifying_phrase(client, harness) -> None:
    """A diagnosis span: "stage II HER2-positive breast cancer" went out as
    <QUASI_IDENTIFIER_1>, and "요추 추간판탈출증" as an invented term ("등기증후군")."""
    harness.entities = {
        "Henrik Pembrooke": ("PERSON", "mask", ""),
        "stage II HER2-positive breast cancer": ("QUASI_IDENTIFIER", "mask", ""),
        "요추 추간판탈출증": ("QUASI_IDENTIFIER", "generalize", "등기증후군"),
    }
    chat(client, "My mother Henrik Pembrooke has stage II HER2-positive breast cancer. Explain.")
    assert "stage II HER2-positive breast cancer" in sent(harness)[-1]["content"]
    chat(client, "실손보험 청구 사유 써줘. 진단명 요추 추간판탈출증, 도수치료 10회.")
    text = sent(harness)[-1]["content"]
    assert "요추 추간판탈출증" in text and "등기증후군" not in text
    # Short health terms are not reworded by the local model either ("요추" went out as "등심").
    harness.entities = {
        "요추": ("HEALTH", "generalize", "등심"),
        "체외수정 시술": ("HEALTH", "generalize", "수술 시술"),
    }
    chat(client, "진단명 요추 디스크, 다음 달 체외수정 시술 예정이야.")
    assert "요추 디스크, 다음 달 체외수정 시술" in sent(harness)[-1]["content"]
    assert not generalize.health_term("the only deaf kid in our class")
    # A uniqueness phrase that mentions a condition is still a quasi-identifier.
    assert not generalize.diagnosis_term("the only fourth-grader with cochlear implants")
    assert not generalize.diagnosis_term("정보처리기사 자격증")


def test_a_job_title_is_not_an_id_number_even_when_gliner_agrees(
    make_client,
    harness,
    fake_gliner,  # noqa: F811 - fixture
) -> None:
    client = make_client(gliner=True)
    harness.entities = {"직함 선임연구원": ("ID_NUMBER", "mask", "")}
    fake_gliner.entities = {"직함 선임연구원": ("unique_id", 0.9)}
    r = chat(client, "명함 정보 정리해줘: 이름 정민준, 직함 선임연구원.")
    assert r.status_code == 200, r.text
    assert "직함 선임연구원" in sent(harness)[-1]["content"]
    # A code with two digits under a money label is still masked, as an ID number.
    harness.entities = {"Q4MGD7UBTYHL": ("FINANCIAL", "mask", "")}
    fake_gliner.entities = {"Q4MGD7UBTYHL": ("account_number", 0.9)}
    chat(client, "실손보험 청구해줘. 증권번호 Q4MGD7UBTYHL, 도수치료 10회 받았어.")
    assert "증권번호 <ID_NUMBER_1>" in sent(harness)[-1]["content"]


# ---- code --------------------------------------------------------------------------------------


def test_variable_names_and_service_accounts_are_not_masked(client, harness) -> None:
    harness.entities = {
        "orders_rw": ("PERSON", "mask", ""),
        "PAYMENTS_API_KEY": ("SECRET", "mask", ""),
        "DB_USER: b3JkZXJzX3J3": ("SECRET", "mask", ""),
    }
    text = (
        "```\nPAYMENTS_API_KEY=pmk_live_ZjGy2bFG6V34lzu3jshUdCCy\n  DB_USER: b3JkZXJzX3J3\n```\n"
        "logs: KeyError: 'PAYMENTS_API_KEY', password authentication failed for user \"orders_rw\""
    )
    r = chat(client, text)
    assert r.status_code == 200, r.text
    out = sent(harness)[-1]["content"]
    assert "PAYMENTS_API_KEY=<SECRET_1>" in out and "KeyError: 'PAYMENTS_API_KEY'" in out
    assert "DB_USER: <SECRET_2>" in out and 'for user "orders_rw"' in out
    assert "pmk_live" not in out


def test_camel_case_object_keys_are_not_masked(client, harness) -> None:
    harness.entities = {"redisUrl": ("SECRET", "mask", ""), "hunterTwo": ("SECRET", "mask", "")}
    chat(client, "config: { redisUrl: 'redis://db:6379/0' } and my password is hunterTwo")
    out = sent(harness)[-1]["content"]
    assert "redisUrl: 'redis://db:6379/0'" in out and "hunterTwo" not in out


def test_entropy_span_leaves_the_variable_name() -> None:
    spans = detect_patterns("JWT_SECRET=9FRRqrTbWCKhrXPBuB7BP1ai6EcX5IGD")
    assert {s.text for s in spans} == {"9FRRqrTbWCKhrXPBuB7BP1ai6EcX5IGD"}
    assert trim(Span(text="DB_USER: b3JkZXJzX3J3", type="SECRET", source="llm"), "").text == (
        "b3JkZXJzX3J3"
    )
    url = "redisUrl: 'redis://:rQpokK1JPxkuvAr4VUWa@10.0.4.21:6379/0'"
    assert trim(Span(text=url, type="ID_NUMBER", source="llm"), "").text.startswith("redis://")
    dsn = "postgresql://svc:pw@10.0.0.1/db"
    assert trim(Span(text=dsn, type="SECRET", source="llm"), "").text == dsn


def test_generalization_after_a_determiner_drops_its_article(client, harness) -> None:
    harness.entities = {
        "tenure-track quantum optics professor at Aldermoor University": (
            "QUASI_IDENTIFIER", "generalize", "a senior physics professor"
        ),
    }  # fmt: skip
    chat(client, "I'm the tenure-track quantum optics professor at Aldermoor University.")
    assert "I'm the senior physics professor." in sent(harness)[-1]["content"]


def test_rehydrated_answer_uses_the_new_rules_end_to_end(client, harness) -> None:
    harness.entities = {"5811 9184 6707 5448": ("FINANCIAL", "mask", "")}
    harness.upstream_reply = lambda p: completion("Card ending in <FINANCIAL_1>.")
    r = chat(client, "Dispute letter. Card 5811 9184 6707 5448, charged $612.40.")
    assert r.status_code == 200, r.text
    assert "$612.40" in json.dumps(sent(harness))
    assert r.json()["choices"][0]["message"]["content"] == "Card ending in 5448."


# ---- deterministic backstops for values the local model missed on dev ----------------------------


def test_seed_phrase_is_a_secret_without_the_local_model() -> None:
    text = "Wallet won't restore from this seed phrase: \"orbit cactus harbor hazel hazel tundra "
    text += 'meadow dynamo ember anchor dynamo velvet". Did I get the order wrong?'
    [span] = [s for s in detect_patterns(text) if s.rule == "seed_phrase"]
    assert span.text.startswith("orbit cactus") and span.text.endswith("dynamo velvet")
    assert not [s for s in detect_patterns("Why is a seed phrase safer than a password?")]


def test_labeled_birth_date_is_masked_without_the_local_model(client, harness) -> None:
    r = chat(client, "My mother (DOB 1953-01-15) was diagnosed with breast cancer. Explain.")
    assert r.status_code == 200, r.text
    messages = sent(harness)
    assert "(DOB <DATE_OF_BIRTH_1>)" in messages[-1]["content"]
    assert "<DATE_OF_BIRTH_n> is a date of birth" in messages[0]["content"]
    assert [s.text for s in generalize.birth_dates("생년월일: 1990년 3월 2일이야")] == [
        "1990년 3월 2일"
    ]
    assert generalize.birth_dates("결제일 2026-03-02, born on March 3, 1987")[0].text == (
        "March 3, 1987"
    )
