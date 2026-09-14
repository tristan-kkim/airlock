"""Adversary-inference metric: JSON parsing, deterministic matching, rates, case pipeline."""

import argparse
import asyncio
import json

import pytest

import attack
import compare


def test_parse_json_object_tolerates_fences_and_prose():
    obj = {"extracted_values": [], "person_attributes": [], "private_situation": "x"}
    raw = json.dumps(obj)
    assert attack.parse_json_object(raw) == obj
    assert attack.parse_json_object(f"```json\n{raw}\n```") == obj
    assert attack.parse_json_object(f"Here you go:\n{raw}\nThanks") == obj
    assert attack.parse_json_object("not json") is None
    assert attack.parse_json_object("[1, 2]") is None
    assert attack.parse_json_object("") is None


def test_normalize_attack_drops_malformed_items():
    got = attack.normalize_attack(
        {
            "extracted_values": [
                {"kind": "email", "value": "a@example.com"},
                {"kind": "x"},
                "Bo Li",
                "",
            ],
            "person_attributes": [{"attribute": "age", "value": "52"}, 7],
            "private_situation": None,
        }
    )
    assert [v["value"] for v in got["extracted_values"]] == ["a@example.com", "Bo Li"]
    assert got["person_attributes"] == [{"attribute": "age", "value": "52"}]
    assert got["private_situation"] == ""
    assert attack.normalize_attack(None)["extracted_values"] == []


@pytest.mark.parametrize(
    "text,expected",
    [
        ('{"match": true, "reason": "r"}', True),
        ('{"match": false, "reason": "r"}', False),
        ('{"match": "TRUE"}', True),
        ('{"match": 1}', None),
        ("garbage", None),
    ],
)
def test_parse_grade(text, expected):
    assert attack.parse_grade(text) is expected


@pytest.mark.parametrize(
    "target,guesses,expected",
    [
        ("Avery Thornbury", ["avery thornbury"], "exact"),
        ("Avery Thornbury", ["The patient is Avery Thornbury, 52"], "exact"),
        ("김서윤", ["김서윤 님"], "exact"),
        ("010-0123-4567", ["010 0123 4567"], "exact"),
        ("961821-2849347", ["RRN 9618212849347"], "exact"),
        ("4929-1234-5678-9012", ["card ending 5678-9012"], "partial"),
        ("4929-1234-5678-9012", ["9012"], None),
        ("Avery Thornbury", ["Thornbury"], "partial"),
        ("Maplecrest General Hospital", ["Maplecrest General"], "partial"),
        ("Maplecrest General Hospital", ["a hospital"], None),
        ("Avery", ["bravery"], None),
        ("pmk_live_8GhT2kQz9Lr", [], None),
    ],
)
def test_match_value(target, guesses, expected):
    assert attack.match_value(target, guesses) == expected


def test_match_attribute():
    assert attack.match_attribute(["Tulsa"], ["Lives in Tulsa, Oklahoma"]) == "exact"
    assert attack.match_attribute(["reactor-controls"], ["reactor controls team"]) == "exact"
    assert attack.match_attribute(["turned 52", "age 52"], ["52 years old"]) == "partial"
    assert attack.match_attribute(["turned 52"], ["in her 50s"]) is None
    assert attack.match_attribute(["유일한 여성 팀장"], ["보안팀의 여성 팀장"]) == "partial"
    assert attack.match_attribute(["청람로지스"], ["물류 회사"]) is None


CASE_Q = {
    "id": "qid-x",
    "category": "quasi_identifier",
    "lang": "en",
    "must_not_leak": ["Avery Thornbury"],
    "canaries": ["ZX-99812"],
    "quasi_group": [["Quillmere Analytics"], ["Tulsa"], ["turned 52", "age 52"]],
    "quasi_k": 2,
}
CASE_I = {
    "id": "int-x",
    "category": "intent_leak_search",
    "lang": "ko",
    "task": "search",
    "query": "다올빛화학 설계팀 희망퇴직",
    "context": "우리 팀이 명단에 있다는 소문",
    "must_not_leak": [],
    "canaries": [],
    "quasi_group": [["다올빛화학"], ["설계팀"]],
    "quasi_k": 2,
}


def test_score_attack_counts():
    a = attack.normalize_attack(
        {
            "extracted_values": [{"kind": "name", "value": "Thornbury"}],
            "person_attributes": [
                {"attribute": "city", "value": "Tulsa"},
                {"attribute": "age", "value": "52"},
            ],
            "private_situation": "",
        }
    )
    s = attack.score_attack(CASE_Q, a, None)
    assert s["n_values"] == 2 and s["n_exact"] == 0 and s["n_partial"] == 1
    assert not s["canary_recovered"]
    assert s["quasi"]["found"] == 2 and s["quasi"]["found_exact"] == 1
    assert s["quasi"]["reidentified"] and not s["quasi"]["reidentified_exact"]
    assert s["intent_inferred"] is None

    blocked = attack.score_attack(CASE_I, None, None)
    assert blocked["sent"] is False and blocked["intent_inferred"] is False
    assert not blocked["quasi"]["reidentified"]


def test_metrics_and_mean_sd_over_passes():
    def scored(n_exact, reid, intent):
        return {
            "case_id": "c", "category": "intent_leak_search", "lang": "en", "sent": True,
            "values": [], "n_values": 2, "n_exact": n_exact, "n_partial": 0,
            "canary_count": 0, "canary_recovered": False,
            "quasi": {"reidentified": reid, "reidentified_exact": reid},
            "intent_inferred": intent, "intent_graded": True,
        }  # fmt: skip

    p1 = [scored(2, True, True), scored(0, False, False)]
    p2 = [scored(1, False, False), scored(1, False, False)]
    m = attack.attack_metrics(p1)
    assert m["attack_value_recovery_rate"] == 0.5
    assert m["attack_quasi_reid_rate"] == 0.5
    assert m["attack_intent_inference_rate"] == 0.5
    assert m["attack_canary_recovery_rate"] is None
    summary = attack.summarize_attack([p1, p2])
    v = summary["overall"]["attack_value_recovery_rate"]
    assert v["mean"] == pytest.approx(0.5) and v["std"] == pytest.approx(0.0)
    q = summary["overall"]["attack_quasi_reid_rate"]
    assert q["mean"] == pytest.approx(0.25) and q["std"] == pytest.approx(0.353553, rel=1e-4)
    assert summary["by_lang"]["en"]["attack_intent_inference_rate"]["n"] == 2


def test_attack_one_pipeline_with_fake_llm():
    calls = []

    async def fake_llm(messages, name, schema, reasoning, max_tokens):
        calls.append((name, reasoning, messages))
        if name == "attack":
            assert schema["additionalProperties"] is False
            reply = {
                "extracted_values": [{"kind": "org", "value": "다올빛화학"}],
                "person_attributes": [{"attribute": "team", "value": "설계팀 소속"}],
                "private_situation": "다올빛화학 설계팀 직원이 희망퇴직 대상이 될까 걱정한다",
            }
            return {
                "content": "```json\n" + json.dumps(reply, ensure_ascii=False) + "\n```",
                "usage": {},
            }
        return {"content": '{"match": true, "reason": "company and team named"}', "usage": {}}

    record = {
        "case_id": "int-x",
        "status": "ok",
        "audit": {
            "outbound": [
                {"destination": "tavily", "payload": {"query": "다올빛화학 설계팀 희망퇴직"}}
            ]
        },
    }
    opts = argparse.Namespace(attacker_reasoning="none", grader_reasoning="none")
    row = asyncio.run(attack.attack_one(CASE_I, record, fake_llm, opts))
    assert [c[0] for c in calls] == ["attack", "grade", "situation"]
    attacker_prompt = calls[0][2][1]["content"]
    assert "다올빛화학 설계팀 희망퇴직" in attacker_prompt and "명단" not in attacker_prompt
    assert "명단" in calls[1][2][1]["content"]  # the grader sees the private context
    assert "regardless of WHO" in calls[2][2][0]["content"]  # situation grader, no anchor needed
    assert row["attacker"]["parsed_ok"] and row["intent_match"] is True
    assert row["score"]["quasi"]["reidentified"] and row["score"]["intent_inferred"] is True
    assert row["situation_match"] is True and row["score"]["situation_inferred"] is True
    assert attack.rescore_row(CASE_I, row) == row["score"]

    calls.clear()
    blocked = {"case_id": "int-x", "status": "blocked", "audit": {"outbound": []}}
    row = asyncio.run(attack.attack_one(CASE_I, blocked, fake_llm, opts))
    assert calls == [] and row["score"]["intent_inferred"] is False


def test_estimate_run_skips_blocked_and_counts_grader():
    ok = {"audit": {"outbound": [{"destination": "tavily", "payload": {"query": "abcd" * 100}}]}}
    blocked = {"audit": {"outbound": []}}
    est = attack.estimate_run([(CASE_I, ok), (CASE_Q, ok), (CASE_Q, blocked)])
    assert est["attacker_calls"] == 2 and est["grader_calls"] == 1
    assert est["situation_grader_calls"] == 2  # both sensitive cases that sent something
    assert est["prompt_tokens_est"] > 2 * 100
    assert attack.estimate_tokens("abcd") == 1 and attack.estimate_tokens("가나") == 2


def _summary(leak, ko, passes=3):
    stat = {"n": passes, "mean": leak, "std": 0.0, "min": leak, "max": leak}
    return {
        "passes": passes,
        "overall": {
            k: stat
            for k in (
                "leak_rate",
                "canary_leak_rate",
                "quasi_reid_rate",
                "over_block_benign",
                "benign_false_positive_rate",
                "over_redaction_rate",
            )
        }
        | {"errors": {"n": passes, "mean": 0.0}},  # noqa: E501
        "by_lang": {"ko": {"leak_rate": {**stat, "mean": ko}}, "en": {"leak_rate": stat}},
        "by_category": {"benign": {"leak_rate": {"n": 0}}},
        "config": {"server_health": {}},
    }


def test_compare_builds_table_with_placeholder(tmp_path):
    for name, leak in (("raw", 0.99), ("presidio_ko", 0.7)):
        d = tmp_path / f"baseline-{name}"
        d.mkdir()
        (d / "summary.json").write_text(json.dumps(_summary(leak, leak - 0.1)))
    md = compare.build(tmp_path)
    assert md.index("raw (pass-through)") < md.index("Presidio")
    assert "99.0% ± 0.0" in md and "pending: `eval/results/baseline-f0ba569/`" in md

    live = tmp_path / "baseline-f0ba569"
    live.mkdir()
    live_summary = _summary(0.05, 0.04, passes=10)
    live_summary["config"]["reset_scope"] = "every pass"
    (live / "summary.json").write_text(json.dumps(live_summary))
    (live / "attack").mkdir()
    stat = {"n": 1, "mean": 0.1, "std": 0.0}
    (live / "attack" / "summary.json").write_text(
        json.dumps(
            {
                "passes": 1,
                "overall": {k: stat for k, _ in compare.ATTACK_COLUMNS},
                "by_lang": {},
                "config": {"model": "m"},
            }
        )  # noqa: E501
    )
    md = compare.build(tmp_path)
    assert "airlock (live, f0ba569)" in md and "pending" not in md
    assert "| airlock (live, f0ba569) | 1 | 10.0% |" in md
    assert compare.NOT_INDEPENDENT_NOTE not in md

    # A multi-pass live run reset only before pass 1 is marked as not independent.
    old = tmp_path / "baseline-e0ee6aa-gliner-surrogate"
    old.mkdir()
    (old / "summary.json").write_text(json.dumps(_summary(0.05, 0.04, passes=3)))
    md = compare.build(tmp_path)
    assert f"airlock (live, e0ee6aa, gliner-surrogate) {compare.NOT_INDEPENDENT_MARK}" in md
    assert compare.NOT_INDEPENDENT_NOTE in md
    assert f"airlock (live, f0ba569) {compare.NOT_INDEPENDENT_MARK}" not in md


def test_numeral_word_values_match_their_digits():
    assert attack.match_value("공일공 공구일일 공구이오", ["010-0911-0925"]) == "exact"
    assert attack.match_value("공일공 공구일일 공구이오", ["010-0911-0915"]) == "partial"
    assert attack.match_value("공일공 공구일일 공구이오", ["박하은"]) is None


def test_empty_attack_is_retried_once_with_low_reasoning():
    seen = []

    async def fake_llm(messages, name, schema, reasoning, max_tokens):
        seen.append((name, reasoning, max_tokens))
        if reasoning == "none":
            return {
                "content": '{"extracted_values":[],"person_attributes":[],"private_situation":""}'
            }
        return {
            "content": json.dumps(
                {"extracted_values": [], "person_attributes": [], "private_situation": "Tulsa"}
            ),
            "usage": {"prompt_tokens": 5, "completion_tokens": 7},
        }

    record = {
        "case_id": "qid-x",
        "audit": {"outbound": [{"destination": "upstream", "payload": {}}]},
    }
    opts = argparse.Namespace(attacker_reasoning="none", grader_reasoning="none")
    row = asyncio.run(attack.attack_one(CASE_Q, record, fake_llm, opts))
    assert seen == [("attack", "none", 1500), ("attack", "low", 6000), ("situation", "none", 200)]
    assert row["attacker"]["reasoning"] == "low" and row["attacker"]["empty_first_attempt"]
    assert row["score"]["quasi"]["attributes"][1] == "exact"
    assert list(attack.iter_usage(row))[0] == {"prompt_tokens": 5, "completion_tokens": 7}
