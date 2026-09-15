"""Detector hardening: pattern-first masking, span verification, fail-closed malfunctions,
placeholder syntax and lenient rehydration, review mode, audit counters."""

import json

import httpx
import pytest

from airlock.config import ReviewMode
from airlock.detect.llm import detector_max_tokens, looks_repetitive
from airlock.detect.verify import generalization_ok, grounded
from airlock.pipeline import PLACEHOLDER_NOTE
from airlock.rehydrate import StreamRehydrator, rehydrate_text
from airlock.vault import Vault
from tests.conftest import completion

NAME = "Jane Park"
PHONE = "010-2345-6789"
EMAIL = "jane.park@example.com"
KEY = "sk-proj-Zx8Qw3Er5Ty7Ui9Op1As2Df4"
RRN = "900101-1234567"


def chat(client, content, headers=None, **extra):
    return client.post(
        "/v1/chat/completions",
        json={"messages": [{"role": "user", "content": content}], **extra},
        headers=headers or {},
    )


def detector_inputs(harness) -> list[str]:
    return [
        r["messages"][1]["content"]
        for r in harness.local_requests
        if "privacy gate of Airlock" in r["messages"][0]["content"]
    ]


# ---- 1. pattern-first ordering ------------------------------------------------------------------


def test_local_model_never_receives_raw_pattern_secrets(client, harness) -> None:
    harness.entities = {NAME: ("PERSON", "mask", "")}
    text = f"I am {NAME}, call {PHONE} or mail {EMAIL}. Key {KEY}, RRN {RRN}. Also {PHONE} again."
    r = chat(client, text)
    assert r.status_code == 200, r.text

    [seen] = detector_inputs(harness)
    for secret in (PHONE, EMAIL, KEY, RRN):
        assert secret not in seen
    assert seen.startswith("<draft>\n") and seen.endswith("\n</draft>")
    assert "<CONTACT_1>" in seen and "<CONTACT_2>" in seen and "<SECRET_1>" in seen
    assert seen.count("<CONTACT_1>") == 2  # same value, same local token
    assert NAME in seen  # semantic spans are left for the model

    sent = harness.upstream_requests[0]["messages"][-1]["content"]
    assert NAME not in sent and PHONE not in sent and "<PERSON_1>" in sent


def test_detector_request_uses_spike_sampling_and_sized_output_cap(client, harness) -> None:
    chat(client, "short note")
    chat(client, "a much longer note " * 40, headers={"x-airlock-conversation-id": "other"})
    short, long = [r for r in harness.local_requests]
    assert short["temperature"] == 0.6 and short["top_p"] == 0.95
    assert short["chat_template_kwargs"] == {"enable_thinking": False}
    assert short["response_format"]["json_schema"]["schema"]["properties"]["spans"]["maxItems"]
    assert short["max_tokens"] < long["max_tokens"] <= 1536
    assert detector_max_tokens(10) == 180 and detector_max_tokens(10_000) == 1536


def test_local_model_is_skipped_when_only_masked_values_remain(client, harness) -> None:
    r = chat(client, f"{PHONE} {EMAIL}")
    assert r.status_code == 200
    assert detector_inputs(harness) == []


# ---- 2. span verification -----------------------------------------------------------------------


def test_hallucinated_spans_are_discarded_and_counted(client, harness) -> None:
    harness.entities = {NAME: ("PERSON", "mask", "")}
    harness.extra_spans = [
        {"text": "123-45-6789", "type": "ID_NUMBER", "action": "mask", "replacement": ""},
        {"text": "Dr. Imaginary", "type": "PERSON", "action": "mask", "replacement": ""},
        {"text": "<CONTACT_1>", "type": "CONTACT", "action": "mask", "replacement": ""},
        {"text": "x", "type": "PERSON", "action": "mask", "replacement": ""},
    ]
    r = chat(client, f"{NAME} has type 2 diabetes, phone {PHONE}.")
    assert r.status_code == 200, r.text
    sent = harness.upstream_requests[0]["messages"][-1]["content"]
    assert sent == "<PERSON_1> has type 2 diabetes, phone <CONTACT_1>."

    meta = client.get(f"/audit/{r.headers['x-airlock-request-id']}").json()["meta"]["detector"]
    assert meta["llm_proposed"] == 5
    assert meta["llm_kept"] == 1
    assert meta["llm_discarded_ungrounded"] == 2
    assert meta["llm_discarded_invalid"] == 2
    assert meta["pattern_spans"] == 1 and meta["masked_before_llm"] == 1


def test_grounding_uses_vault_normalization() -> None:
    assert grounded("JANE  park", "hello Jane Park!")
    assert grounded("ｊａｎｅ", "jane")
    assert not grounded("123-45-6789", "제2형 당뇨")


@pytest.mark.parametrize(
    ("original", "replacement", "ok"),
    [
        ("34 years old", "in their 30s", True),
        ("stage 2 breast cancer", "a serious medical condition", True),
        ("갑상선암", "질병", True),
        ("유일한 여성 부사장", "임원", True),
        # leaks
        ("Gangnam", "near Gangnam station", False),
        ("58세 남성", "58세 전후 남성", False),  # digit run survives
        (
            "유일하게 한국어-포르투갈어 통역사로 일하는 58세 남성",
            "한국어-포르투갈어 통역사",
            False,
        ),  # spike failure: a crop that keeps the identifier
        ("유일하게 스와힐리어 번역가로 일하는", "스와힐리어 전문가", False),  # rare word survives
        ("the only Black partner at Hollis & Reed", "a partner at Hollis", False),  # proper noun
        ("여성 부사장", "female manager", False),  # language switch
        ("Dw!8842kq", "}]}]```.```json{", False),  # junk
        ("우울증", "", False),
    ],
)
def test_generalization_validation(original, replacement, ok) -> None:
    assert generalization_ok(original, replacement) is ok


def test_leaky_generalization_falls_back_to_mask_and_is_counted(client, harness) -> None:
    quasi = "유일하게 한국어-포르투갈어 통역사로 일하는 58세 남성"
    harness.entities = {quasi: ("QUASI_IDENTIFIER", "generalize", "한국어-포르투갈어 통역사")}
    r = chat(client, f"마을에서 {quasi}인데 이력서 써줘")
    assert r.status_code == 200, r.text
    sent = harness.upstream_requests[0]["messages"][-1]["content"]
    assert "포르투갈어" not in sent and "58세" not in sent
    assert "<QUASI_IDENTIFIER_1>" in sent
    audit = client.get(f"/audit/{r.headers['x-airlock-request-id']}").json()
    assert audit["meta"]["detector"]["generalize_rejected"] >= 1


# ---- 3. fail closed on detector malfunction -----------------------------------------------------


@pytest.mark.parametrize(
    ("setup", "kind"),
    [
        (
            lambda h: setattr(h, "local_content", lambda u: '{"spans": [{"text": "Ja'),
            "invalid_json",
        ),
        (lambda h: setattr(h, "local_content", lambda u: 'Sure! {"spans": []}'), "prose"),
        (lambda h: setattr(h, "local_content", lambda u: "No sensitive data found."), "prose"),
        (lambda h: setattr(h, "local_finish", "length"), "length"),
        (lambda h: setattr(h, "local_timeout", True), "timeout"),
        (
            lambda h: setattr(
                h,
                "local_content",
                lambda u: (
                    '{"spans":['
                    + ",".join(['{"text":"최고","type":"QUASI_IDENTIFIER"}'] * 12)
                    + "]}"
                ),
            ),
            "repetition",
        ),
        (
            lambda h: setattr(
                h,
                "local_content",
                lambda u: json.dumps(
                    {
                        "spans": [
                            {"text": t, "type": "PERSON", "action": "mask", "replacement": ""}
                            for t in ["Jane", "Park", "Jane", "Park"] * 3
                        ]
                    }
                ),
            ),
            "repetition",
        ),
        (lambda h: setattr(h, "local_content", lambda u: '{"items": []}'), "schema"),
    ],
)
def test_detector_malfunction_blocks(client, harness, setup, kind) -> None:
    setup(harness)
    r = chat(client, f"hello {NAME}, please draft a note")
    assert r.status_code == 422, r.text
    err = r.json()["error"]
    assert err["type"] == "airlock_blocked"
    assert err["reasons"] == [f"local_detector_malformed:{kind}"]
    assert harness.upstream_requests == []
    audit = client.get(f"/audit/{err['request_id']}").json()
    assert audit["gate"]["decision"] == "block" and audit["outbound"] == []


def test_one_malformed_answer_is_retried_once(client, harness) -> None:
    answers = iter(['{"spans":[' + '{"text":"x","type":"Q"},' * 8, '{"spans": []}'])
    harness.local_content = lambda u: next(answers)
    r = chat(client, "hello there")
    assert r.status_code == 200, r.text
    assert len(harness.local_requests) == 2
    # The retry is a different sample: a fresh seed and a little more temperature.
    first, second = harness.local_requests
    assert "seed" not in first and first["temperature"] == 0.6
    assert isinstance(second["seed"], int) and second["temperature"] == 0.8


def test_chat_never_resamples_or_degrades_after_two_malformed_answers(client, harness) -> None:
    """The agent loop's retry-then-degrade path is not the chat path: chat fails closed."""
    loop = '{"spans":[' + '{"text":"x","type":"Q"},' * 8
    answers = iter([loop, loop, loop, loop, '{"spans": []}'])
    harness.local_content = lambda u: next(answers)
    r = chat(client, "hello there")
    assert r.status_code == 422
    assert r.json()["error"]["reasons"] == ["local_detector_malformed:repetition"]
    assert len(harness.local_requests) == 2
    assert harness.upstream_requests == []


def test_repetition_detector_ignores_normal_output() -> None:
    normal = json.dumps(
        {
            "spans": [
                {"text": n, "type": "PERSON", "action": "mask", "replacement": ""}
                for n in ("김서연", "박지훈", "이도윤", "문태오")
            ]
        },
        ensure_ascii=False,
    )
    assert not looks_repetitive(normal)
    assert looks_repetitive('{"text":"최고","type":"Q"},' * 6)


# ---- 4. placeholders and lenient rehydration ----------------------------------------------------


@pytest.mark.parametrize(
    "variant",
    [
        "<PERSON_1>",
        "< PERSON_1 >",
        "&lt;PERSON_1&gt;",
        "[[PERSON_1]]",
        "[PERSON_1]",
        "⟨PERSON_1⟩",
        "<person_1>",
        "＜PERSON_1＞",
        "［［PERSON_1］］",
        "⟦PERSON_1⟧",
        "{{PERSON_1}}",
        "PERSON_1",
    ],
)
def test_lenient_rehydration_variants(variant) -> None:
    s = Vault(":memory:").session("c")
    s.mask("김서연", "PERSON")
    assert rehydrate_text(f"안녕하세요 {variant}님.", s) == "안녕하세요 김서연님."


def test_rehydration_leaves_unknown_and_code_like_tokens() -> None:
    s = Vault(":memory:").session("c")
    s.mask("Jane", "PERSON")
    text = "List<T_1> and <PERSON_9> and [x] and <b>bold</b> and PERSON_10"
    assert rehydrate_text(text, s) == text


def test_stream_rehydrator_holds_split_angle_and_entity_forms() -> None:
    s = Vault(":memory:").session("c")
    s.mask("Jane", "PERSON")
    r = StreamRehydrator(s)
    pieces = ["Hi <PER", "SON_1>, ", "&l", "t;PERSON_1&g", "t; and a < b", " done"]
    out = "".join(r.feed(p) for p in pieces) + r.flush()
    assert out == "Hi Jane, Jane and a < b done"


def test_vault_migrates_legacy_rendered_values(tmp_path) -> None:
    path = str(tmp_path / "vault.sqlite3")
    v = Vault(path)
    v._conn.execute(
        "INSERT INTO mappings VALUES ('c', 'jane', 'Jane', 'PERSON', 'mask', '[[PERSON_1]]', 0)"
    )
    v._conn.commit()
    v.close()
    s = Vault(path).session("c")
    assert s.original_for("PERSON_1") == "Jane"
    assert s.mask("Jane", "PERSON").outbound == "<PERSON_1>"
    assert s.mask("Bob", "PERSON").outbound == "<PERSON_2>"


def test_upstream_gets_placeholder_instruction_and_legacy_history_is_canonicalized(
    client, harness
) -> None:
    harness.entities = {NAME: ("PERSON", "mask", "")}
    harness.upstream_reply = lambda p: completion("Hello &lt;PERSON_1&gt; / [[PERSON_1]]")
    turn1 = [{"role": "user", "content": f"I am {NAME}."}]
    r1 = client.post("/v1/chat/completions", json={"messages": turn1})
    assert r1.json()["choices"][0]["message"]["content"] == f"Hello {NAME} / {NAME}"
    sent = harness.upstream_requests[0]["messages"]
    assert sent[0]["role"] == "system" and sent[0]["content"].startswith(PLACEHOLDER_NOTE)
    assert "<PERSON_1>" in PLACEHOLDER_NOTE and "copy them exactly" in PLACEHOLDER_NOTE
    assert "<PERSON_n> is a person's name" in sent[0]["content"]

    turn2 = [*turn1, {"role": "assistant", "content": "Hi [[PERSON_1]]"}]
    turn2.append({"role": "user", "content": "again"})
    client.post("/v1/chat/completions", json={"messages": turn2})
    assert harness.upstream_requests[1]["messages"][-2]["content"] == "Hi <PERSON_1>"


# ---- 5. review mode -----------------------------------------------------------------------------


def test_review_round_trip_with_reject_and_add(client, harness) -> None:
    harness.entities = {NAME: ("PERSON", "mask", ""), "Hanbit Clinic": ("ORG", "mask", "")}
    harness.upstream_reply = lambda p: completion("Dear <PERSON_1>, noted <PROJECT_1>.")
    text = f"I am {NAME} from Hanbit Clinic, phone {PHONE}, project Nightjar."
    r = chat(client, text, headers={"x-airlock-review": "required"}, stream=False)
    assert r.status_code == 409, r.text
    err = r.json()["error"]
    assert err["type"] == "airlock_review_required" and err["reasons"] == ["requested"]
    assert harness.upstream_requests == []

    proposed = {p["text"]: p for p in err["proposed"]}
    assert set(proposed) == {NAME, "Hanbit Clinic", PHONE}
    person = proposed[NAME]
    assert set(person) >= {
        "span_id", "type", "action", "preview_before", "preview_after", "source", "confidence",
    }  # fmt: skip
    assert NAME in person["preview_before"] and "<PERSON_1>" in person["preview_after"]
    assert person["source"] == "llm" and 0 < person["confidence"] <= 1
    assert proposed[PHONE]["source"] == "regex"

    # Nothing was written to the vault while waiting.
    audit = client.get(f"/audit/{err['request_id']}").json()
    assert audit["gate"]["decision"] == "review" and audit["outbound"] == []
    assert NAME not in json.dumps(audit)

    decision = {
        "approve": [person["span_id"], proposed[PHONE]["span_id"]],
        "reject": [proposed["Hanbit Clinic"]["span_id"]],
        "add": [{"text": "Nightjar", "type": "PROJECT"}],
    }
    r2 = client.post(f"/review/{err['review_id']}", json=decision)
    assert r2.status_code == 200, r2.text
    sent = harness.upstream_requests[0]["messages"][-1]["content"]
    assert sent == "I am <PERSON_1> from Hanbit Clinic, phone <CONTACT_1>, project <PROJECT_1>."
    assert r2.json()["choices"][0]["message"]["content"] == f"Dear {NAME}, noted Nightjar."

    audit2 = client.get(f"/audit/{r2.headers['x-airlock-request-id']}").json()
    assert audit2["meta"]["review"] == {
        "review_id": err["review_id"],
        "proposed": 3,
        "approved": 2,
        "rejected": 1,
        "added": 1,
    }
    assert {d["source"] for d in audit2["detections"]} == {"llm", "regex", "user"}
    # Single use.
    assert client.post(f"/review/{err['review_id']}", json={}).status_code == 404


def test_review_rejects_unknown_span_ids_and_keeps_review(client, harness) -> None:
    r = chat(client, f"call {PHONE}", headers={"x-airlock-review": "required"})
    review_id = r.json()["error"]["review_id"]
    bad = client.post(f"/review/{review_id}", json={"reject": ["s99"]})
    assert bad.status_code == 400
    assert client.post(f"/review/{review_id}", json={}).status_code == 200


def test_rejecting_a_locked_secret_still_blocks_at_the_gate(client, harness) -> None:
    r = chat(client, f"key {KEY}", headers={"x-airlock-review": "required"})
    [p] = r.json()["error"]["proposed"]
    assert p["locked"] is True
    r2 = client.post(f"/review/{r.json()['error']['review_id']}", json={"reject": [p["span_id"]]})
    assert r2.status_code == 422
    assert r2.json()["error"]["reasons"][0].startswith("secret_pattern:openai_style_key")
    assert harness.upstream_requests == []


def test_uncertain_mode_triggers_only_on_uncertainty(make_client, harness) -> None:
    client = make_client(review_mode=ReviewMode.UNCERTAIN)
    # Regex-only findings: confident, sent directly.
    assert chat(client, f"call {PHONE}").status_code == 200

    # A span only the local model found.
    harness.entities = {NAME: ("PERSON", "mask", "")}
    r = chat(client, f"write to {NAME}", headers={"x-airlock-conversation-id": "u2"})
    assert r.status_code == 409 and r.json()["error"]["reasons"] == ["llm_only_spans"]

    # A discarded (hallucinated) span.
    harness.entities = {}
    harness.extra_spans = [
        {"text": "Nobody", "type": "PERSON", "action": "mask", "replacement": ""}
    ]
    r = chat(client, "plain question", headers={"x-airlock-conversation-id": "u3"})
    assert r.status_code == 409 and r.json()["error"]["reasons"] == ["discarded_spans"]

    # A Korean semantic cue from the deterministic rules.
    harness.extra_spans = []
    r = chat(client, "저는 우울증 진단을 받았어요", headers={"x-airlock-conversation-id": "u4"})
    assert r.status_code == 409 and r.json()["error"]["reasons"] == ["semantic_cues"]

    # The header forces review even when nothing is uncertain.
    r = chat(client, "hello", headers={"x-airlock-review": "required"})
    assert r.status_code == 409 and r.json()["error"]["proposed"] == []


def test_always_mode_and_vault_reset_clears_pending_reviews(make_client, harness) -> None:
    client = make_client(review_mode=ReviewMode.ALWAYS)
    r = chat(client, "hello")
    assert r.status_code == 409 and r.json()["error"]["reasons"] == ["always"]
    client.post("/vault/reset", json={})
    assert client.post(f"/review/{r.json()['error']['review_id']}", json={}).status_code == 404


# ---- 6. audit counters and Korean end to end ----------------------------------------------------


def test_korean_rules_merge_with_llm_and_audit_counts(client, harness) -> None:
    harness.entities = {"문태오": ("PERSON", "mask", "")}
    text = (
        "고객사 새론다움물류 담당 문태오 대리가 갑상선암 수술을 받아서, "
        "팀에서 유일한 여성 부사장인 제가 대신 연락드립니다. 연락처 010-4821-7753"
    )
    r = chat(client, text)
    assert r.status_code == 200, r.text
    sent = harness.upstream_requests[0]["messages"][-1]["content"]
    for leaked in ("새론다움물류", "문태오", "유일한 여성 부사장", "010-4821-7753"):
        assert leaked not in sent
    # A common diagnosis is kept at balanced, except next to a small-group cue ("유일한"): then
    # it becomes its category-level term.
    assert "갑상선암" not in sent and "암 수술" in sent and "특정 역할의 구성원" in sent

    audit = client.get(f"/audit/{r.headers['x-airlock-request-id']}").json()
    meta = audit["meta"]["detector"]
    assert meta["pattern_spans"] == 1 and meta["masked_before_llm"] == 1
    assert meta["rule_spans"] >= 4 and meta["semantic_cues"] >= 2
    assert meta["llm_calls"] == 1 and meta["llm_kept"] == 1
    sources = {d["source"] for d in audit["detections"]}
    assert {"rule", "regex"} <= sources


def test_timeouts_in_search_block_as_malformed(client, harness) -> None:
    harness.local_timeout = True
    r = client.post("/v1/search", json={"query": "anything", "max_results": 1})
    assert r.status_code == 422
    assert r.json()["error"]["reasons"] == ["local_detector_malformed:timeout"]


def test_http_error_from_local_server_is_unavailable(client, harness) -> None:
    def broken(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "boom"})

    harness._local = broken  # type: ignore[method-assign]
    r = chat(client, "hello")
    assert r.json()["error"]["reasons"] == ["local_detector_unavailable:LocalModelUnavailable"]
