"""GLiNER ensemble: agreement, type consistency, local adjudication, disabled mode, fail-closed
startup. The GLiNER model object is a fake; nothing is downloaded or loaded."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import pytest

from airlock import cli
from airlock.config import load_settings
from airlock.detect import gliner
from airlock.detect.gliner import (
    LABELS_BY_NAME,
    GlinerUnavailable,
    build_ensemble,
    mislabel,
    shape_ok,
)
from airlock.server import create_app
from tests.conftest import make_settings

AUDIT_HEADERS = {"x-airlock-conversation-id": "gliner-test"}


@dataclass
class FakeGliner:
    """Stands in for `gliner.GLiNER`: returns fixed (label, score) for every needle it sees."""

    entities: dict[str, tuple[str, float]] = field(default_factory=dict)
    calls: list[tuple[list[str], list[str], float]] = field(default_factory=list)

    def inference(self, texts, labels, flat_ner=True, threshold=0.5, batch_size=8):
        self.calls.append((list(texts), list(labels), threshold))
        out = []
        for text in texts:
            found = []
            for needle, (label, score) in self.entities.items():
                if label not in labels or score < threshold:
                    continue
                start = text.find(needle)
                while start != -1:
                    found.append(
                        {"start": start, "end": start + len(needle), "label": label, "score": score}
                    )
                    start = text.find(needle, start + 1)
            out.append(found)
        return out


@pytest.fixture
def fake_gliner(monkeypatch) -> FakeGliner:
    fake = FakeGliner()
    monkeypatch.setattr(gliner, "availability_problem", lambda settings: None)
    monkeypatch.setattr(gliner.GlinerModel, "_load", lambda self: fake)
    return fake


@pytest.fixture
def gliner_client(make_client, fake_gliner):
    return make_client(gliner=True)


def chat(client, content: str | list[dict[str, Any]]):
    messages = content if isinstance(content, list) else [{"role": "user", "content": content}]
    return client.post("/v1/chat/completions", json={"messages": messages}, headers=AUDIT_HEADERS)


def outbound(harness) -> str:
    return json.dumps(harness.upstream_requests[-1]["messages"], ensure_ascii=False)


def audit(client, response) -> dict[str, Any]:
    return client.get(f"/audit/{response.headers['x-airlock-request-id']}").json()


def adjudication_requests(harness) -> list[dict[str, Any]]:
    return [
        r
        for r in harness.local_requests
        if "span adjudicator of Airlock" in r["messages"][0]["content"]
    ]


# ---- agreement ----------------------------------------------------------------------------------


def test_agreed_spans_are_accepted_without_adjudication(gliner_client, harness, fake_gliner):
    # Nano finds only the surname; GLiNER finds first and last name, which join into one span.
    harness.entities = {"Park": ("PERSON", "mask", "")}
    fake_gliner.entities = {"Jane": ("first_name", 0.99), "Park": ("last_name", 0.99)}
    r = chat(gliner_client, "Please write to Jane Park about the lease renewal.")
    assert r.status_code == 200, r.text

    sent = outbound(harness)
    assert "Jane" not in sent and "Park" not in sent
    assert adjudication_requests(harness) == []
    stats = audit(gliner_client, r)["meta"]["detector"]
    assert stats["gliner_spans"] == 1 and stats["gliner_agreed"] == 1
    assert stats["gliner_candidates"] == 0 and stats["adjudication_calls"] == 0


def test_agreement_inside_a_generalization_keeps_the_generalization(
    gliner_client, harness, fake_gliner
):
    harness.entities = {
        "the only female VP at Orbitline": ("QUASI_IDENTIFIER", "generalize", "a senior leader")
    }
    fake_gliner.entities = {"Orbitline": ("company_name", 0.95)}
    r = chat(gliner_client, "I am the only female VP at Orbitline and want to report harassment.")
    assert r.status_code == 200, r.text
    assert "a senior leader" in outbound(harness)
    assert adjudication_requests(harness) == []


# ---- type consistency ---------------------------------------------------------------------------


def test_type_consistency_rejects_mislabels_before_adjudication(
    gliner_client, harness, fake_gliner
):
    # qid-ko-01 as GLiNER-PII saw it: the age written in words came back as PASSWORD.
    text = "청람로지스 판교 본사 보안팀에서 유일한 여성 팀장이고 올해 마흔다섯이야. 신고서 도와줘."
    fake_gliner.entities = {
        "마흔다섯이야": ("password", 0.51),  # age as PASSWORD
        "보안팀에서": ("first_name", 0.8),  # not a name shape
        "localhost": ("api_key", 0.9),  # no entropy, no password shape
        "올해": ("customer_id", 0.9),  # no digits
    }
    r = chat(gliner_client, text + " 서버는 localhost 야.")
    assert r.status_code == 200, r.text

    sent = outbound(harness)
    assert "마흔다섯" in sent and "보안팀" in sent and "localhost" in sent
    assert adjudication_requests(harness) == []
    stats = audit(gliner_client, r)["meta"]["detector"]
    assert stats["gliner_rejected_mislabel"] == 1
    assert stats["gliner_rejected_shape"] == 3
    assert stats["gliner_candidates"] == 0


@pytest.mark.parametrize(
    ("text", "label", "ok"),
    [
        ("장유나", "first_name", True),
        ("장유나님", "first_name", True),
        ("보안팀", "first_name", False),
        ("세종대왕", "first_name", False),
        ("Jane Park", "first_name", True),
        ("manager", "first_name", False),
        ("Dw!8842kq", "password", True),
        ("password", "password", False),
        ("마흔다섯", "password", False),
        ("010-0123-4567", "phone_number", True),
        ("공일공 공일이삼 사오육칠", "phone_number", True),
        ("next week", "phone_number", False),
        ("AC-8NMD61YGVM", "account_number", True),
        ("EMP-0042", "employee_id", True),
        ("Monday", "customer_id", False),
        ("845", "cvv", True),
        ("jane@example.com", "email", True),
        ("Please email", "email", False),
    ],
)
def test_shape_checks(text, label, ok):
    spec = LABELS_BY_NAME[label]
    assert (shape_ok(text, spec) and not mislabel(text, spec)) is ok


@pytest.mark.parametrize(
    ("text", "label", "bad"),
    [
        ("마흔다섯", "password", True),
        ("45세", "customer_id", True),
        ("turned 52", "unique_id", True),
        ("2024-01-15", "phone_number", True),
        ("2024-01-15", "date_of_birth", False),
        ("$4,200", "account_number", True),
        ("6,200만원", "account_number", True),
        ("845", "cvv", False),
        ("Dw!8842kq", "password", False),
    ],
)
def test_age_date_and_money_mislabels(text, label, bad):
    assert mislabel(text, LABELS_BY_NAME[label]) is bad


def test_korean_particles_are_trimmed_and_names_remapped(gliner_client, harness, fake_gliner):
    fake_gliner.entities = {
        "조유나입니다": ("first_name", 0.99),
        "F8YAXXGS이고": ("password", 0.8),
        "독고새론": ("password", 0.8),  # a name under PASSWORD: remapped to PERSON
    }
    r = chat(gliner_client, "저는 조유나입니다. 비번 F8YAXXGS이고 담당자 독고새론 연락처 부탁.")
    assert r.status_code == 200, r.text
    sent = outbound(harness)
    assert "조유나" not in sent and "F8YAXXGS" not in sent and "독고새론" not in sent
    assert "입니다" in sent and "이고" in sent  # particles stay in the prompt
    stats = audit(gliner_client, r)["meta"]["detector"]
    assert stats["gliner_remapped"] == 1
    types = {d["type"] for d in audit(gliner_client, r)["detections"] if d["source"] == "gliner"}
    assert "PERSON" in types and "SECRET" in types


# ---- adjudication -------------------------------------------------------------------------------


def test_adjudication_accepts_yes_and_rejects_no(gliner_client, harness, fake_gliner):
    fake_gliner.entities = {
        "Quillmere Analytics": ("company_name", 0.97),
        "Alan Turing": ("first_name", 0.99),
    }
    harness.adjudicate = lambda span: "no" if span == "Alan Turing" else "yes"
    r = chat(
        gliner_client,
        "My manager at Quillmere Analytics keeps quoting Alan Turing in reviews. Draft a reply.",
    )
    assert r.status_code == 200, r.text

    sent = outbound(harness)
    assert "Quillmere" not in sent and "Alan Turing" in sent
    [req] = adjudication_requests(harness)
    assert req["temperature"] == 0.0
    assert req["chat_template_kwargs"] == {"enable_thinking": False}
    schema = req["response_format"]["json_schema"]["schema"]
    assert schema["required"] == ["c1", "c2"] and schema["additionalProperties"] is False
    assert schema["properties"]["c1"]["enum"] == ["yes", "no"]

    record = audit(gliner_client, r)
    stats = record["meta"]["detector"]
    assert stats["gliner_candidates"] == 2 and stats["adjudication_calls"] == 1
    assert stats["adjudicated_yes"] == 1 and stats["adjudicated_no"] == 1
    assert {d["source"] for d in record["detections"]} == {"gliner"}


def test_one_adjudication_call_per_request_and_no_raw_pattern_values(
    gliner_client, harness, fake_gliner
):
    fake_gliner.entities = {"Brightwell Dental": ("company_name", 0.9), "Ohana": ("city", 0.9)}
    messages = [
        {"role": "system", "content": "You help with e-mails."},
        {"role": "user", "content": "Book a cleaning at Brightwell Dental, call 010-2345-6789."},
        {"role": "assistant", "content": "Sure."},
        {"role": "user", "content": "Also mention I moved to Ohana last month."},
    ]
    r = chat(gliner_client, messages)
    assert r.status_code == 200, r.text
    [req] = adjudication_requests(harness)
    user = req["messages"][1]["content"]
    assert "010-2345-6789" not in user and "<CONTACT>" in user  # pattern values stay hidden
    assert "⟦Brightwell Dental⟧" in user and "⟦Ohana⟧" in user
    assert len(fake_gliner.calls) == len(gliner.label_groups())  # all texts in one batch


def test_adjudication_is_skipped_without_gliner_only_candidates(
    gliner_client, harness, fake_gliner
):
    r = chat(gliner_client, "Explain the difference between TCP and UDP.")
    assert r.status_code == 200
    assert adjudication_requests(harness) == []
    stats = audit(gliner_client, r)["meta"]["detector"]
    assert stats["gliner_texts"] == 1 and stats["adjudication_ms"] == 0


def test_malformed_adjudication_fails_closed(gliner_client, harness, fake_gliner):
    fake_gliner.entities = {"Quillmere Analytics": ("company_name", 0.97)}
    harness.adjudication_content = lambda user: '{"c1": "maybe"}'
    r = chat(gliner_client, "My employer Quillmere Analytics denied my leave.")
    assert r.status_code == 422
    assert r.json()["error"]["reasons"] == ["local_detector_malformed:schema"]
    assert harness.upstream_requests == []


def test_thresholds_filter_low_scores(make_client, harness, fake_gliner):
    fake_gliner.entities = {"Quillmere Analytics": ("company_name", 0.35)}
    client = make_client(gliner=True, gliner_threshold=0.4)
    r = chat(client, "My employer Quillmere Analytics denied my leave.")
    assert "Quillmere Analytics" in outbound(harness)
    assert audit(client, r)["meta"]["detector"]["gliner_spans"] == 0

    client = make_client(gliner=True, gliner_threshold=0.4, gliner_thresholds="company_name=0.3")
    chat(client, "My employer Quillmere Analytics denied my leave.")
    assert "Quillmere Analytics" not in outbound(harness)


def test_search_path_uses_the_ensemble(gliner_client, harness, fake_gliner):
    fake_gliner.entities = {"Quillmere Analytics": ("company_name", 0.97)}
    harness.rewrite = lambda q, c: "layoff rumors tech company"
    r = gliner_client.post(
        "/v1/search", json={"query": "Quillmere Analytics layoffs", "context": "I work there."}
    )
    assert r.status_code == 200, r.text
    assert len(adjudication_requests(harness)) == 1
    assert any(d["source"] == "gliner" for d in audit(gliner_client, r)["detections"])


# ---- disabled mode and startup ------------------------------------------------------------------


def test_disabled_mode_matches_current_behavior(make_client, harness, monkeypatch):
    def never(self):
        raise AssertionError("GLiNER must not load when AIRLOCK_GLINER is off")

    monkeypatch.setattr(gliner.GlinerModel, "_load", never)
    harness.entities = {"Jane Park": ("PERSON", "mask", "")}
    client = make_client()
    assert client.app.state.services.sanitizer.ensemble is None
    r = chat(client, "Please write to Jane Park at 010-2345-6789 about the lease.")
    assert r.status_code == 200
    sent = harness.upstream_requests[-1]["messages"][-1]["content"]
    assert sent == "Please write to <PERSON_1> at <CONTACT_1> about the lease."
    stats = audit(client, r)["meta"]["detector"]
    assert not any(k.startswith(("gliner", "adjudicat")) for k in stats)
    assert set(stats) == {
        "texts", "pattern_spans", "vault_spans", "masked_before_llm", "rule_spans", "llm_calls",
        "llm_proposed", "llm_kept", "llm_discarded_ungrounded", "llm_discarded_invalid",
        "generalize_rejected", "semantic_cues",
    }  # fmt: skip
    assert adjudication_requests(harness) == []


def test_settings_from_environment(monkeypatch):
    monkeypatch.setenv("AIRLOCK_GLINER", "on")
    monkeypatch.setenv("AIRLOCK_GLINER_THRESHOLD", "0.55")
    monkeypatch.setenv("AIRLOCK_GLINER_MODEL", "/models/gliner-PII")
    monkeypatch.setenv("AIRLOCK_GLINER_ADJUDICATE", "off")
    s = load_settings(env_file=None)
    assert s.gliner and s.gliner_threshold == 0.55 and s.gliner_model == "/models/gliner-PII"
    assert s.gliner_adjudicate is False
    monkeypatch.delenv("AIRLOCK_GLINER")
    assert load_settings(env_file=None).gliner is False


def test_missing_weights_fail_closed_at_startup_and_in_doctor(tmp_path, monkeypatch, capsys):
    settings = make_settings(gliner=True, gliner_model=str(tmp_path))
    problem = gliner.availability_problem(settings)
    assert problem and "gliner_config.json" in problem

    with pytest.raises(GlinerUnavailable):
        build_ensemble(settings, local=None)  # type: ignore[arg-type]
    with pytest.raises(GlinerUnavailable):
        create_app(settings)

    [row] = list(gliner.doctor_checks(settings))
    assert row[0] == "fail" and row[1] == "gliner"

    monkeypatch.setattr(cli, "load_settings", lambda: settings)
    assert cli.main(["serve", "--port", "1"]) == 1
    assert "GLiNER cannot run" in capsys.readouterr().err


def test_missing_package_fails_closed(tmp_path, monkeypatch):
    real = gliner.importlib.util.find_spec
    monkeypatch.setattr(
        gliner.importlib.util,
        "find_spec",
        lambda name, *a: None if name == "gliner" else real(name, *a),
    )
    settings = make_settings(gliner=True, gliner_model=str(tmp_path))
    assert "not installed" in (gliner.availability_problem(settings) or "")
    [row] = list(gliner.doctor_checks(settings))
    assert row[0] == "fail"


def test_doctor_reports_off_when_disabled():
    [row] = list(gliner.doctor_checks(make_settings()))
    assert row[0] == "ok" and "off" in row[2]
