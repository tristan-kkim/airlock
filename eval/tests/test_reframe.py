"""Identity vs situation classification, unlinkability metrics, utility judging and its cache."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import httpx
import pytest

import attack
import compare
import protected
import reframe
import utility
from scoring import compute_metrics, score_case

EVAL_DIR = Path(__file__).resolve().parents[1]


def load_dataset() -> list[dict]:
    return [
        json.loads(line)
        for p in sorted((EVAL_DIR / "cases").glob("*.jsonl"))
        for line in p.read_text(encoding="utf-8").splitlines()
    ]


# --------------------------------------------------------------------------------------------
# Classification coverage
# --------------------------------------------------------------------------------------------


def test_every_protected_item_in_the_dataset_is_classified():
    cases = load_dataset()
    quasi_ids = set()
    for c in cases:
        prot = c["protected"]
        assert prot == protected.classify_case(c, strict=True), c["id"]
        items = prot["items"]
        values = {i["value"] for i in items if i["source"] != "quasi"}
        assert values == set(c["must_not_leak"]) | set(c["canaries"]), c["id"]
        assert all(i["class"] in protected.CLASSES for i in items), c["id"]
        assert all(i["class"] == protected.IDENTITY for i in items if i["source"] != "quasi")
        group = c["quasi_group"] or []
        assert sorted(i["index"] for i in items if i["source"] == "quasi") == list(
            range(len(group))
        )
        if group:
            quasi_ids.add(c["id"])
            n_sit = sum(1 for i in items if i["class"] == protected.SITUATION)
            assert prot["identity_k"] == max(2, (c["quasi_k"] or len(group)) - n_sit)
        assert prot["situation_sensitive"] == (c["category"] in protected.SITUATION_CATEGORIES)
    assert set(protected.QUASI_CLASSES) == quasi_ids  # no stale or missing table entries
    assert sum(protected.linkable_eligible(c) for c in cases) == 98
    assert not any(protected.has_identity(c) for c in cases if c["category"] == "benign")


def test_strict_classification_rejects_unclassified_quasi_attribute():
    case = {
        "id": "qid-ko-01",
        "category": "quasi_identifier",
        "must_not_leak": [],
        "canaries": [],
        "quasi_group": [["청람로지스"], ["새 속성"]],
        "quasi_k": 2,
    }
    with pytest.raises(KeyError):
        protected.classify_case(case, strict=True)
    lenient = protected.classify_case(case, strict=False)
    assert [i["class"] for i in lenient["items"]] == ["identity", "identity"]


def test_agent_scenarios_classify_every_private_fact():
    sys.path.insert(0, str(EVAL_DIR / "agent"))
    import run_agent_eval as ev

    scenarios = ev.load_scenarios()
    assert len(scenarios) == 16
    for s in scenarios:
        classes = protected.scenario_fact_classes(s)
        assert set(classes) == set(s["private_facts"])
        assert protected.IDENTITY in classes.values(), s["id"]
        assert protected.SITUATION in classes.values(), s["id"]
    broken = {**scenarios[0], "fact_classes": {}}
    assert any("fact_classes" in p for p in ev.validate_scenario(broken))
    with pytest.raises(ValueError):
        protected.scenario_fact_classes(
            {"id": "x", "private_facts": ["a"], "fact_classes": {"a": "who"}}
        )


# --------------------------------------------------------------------------------------------
# Metric math
# --------------------------------------------------------------------------------------------

QCASE = {
    "id": "t-q",
    "lang": "en",
    "category": "intent_leak_search",
    "task": "search",
    "query": "q",
    "context": "",
    "vault_terms": [],
    "canaries": [],
    "must_not_leak": [],
    "must_keep": [],
    "quasi_group": [["Acme"], ["firmware team"], ["layoffs"]],
    "quasi_k": 3,
    "protected": {
        "situation_sensitive": True,
        "identity_k": 2,
        "items": [
            {"source": "quasi", "index": 0, "value": ["Acme"], "class": "identity"},
            {"source": "quasi", "index": 1, "value": ["firmware team"], "class": "identity"},
            {"source": "quasi", "index": 2, "value": ["layoffs"], "class": "situation"},
        ],
    },
}


def record(query: str) -> dict:
    return {
        "status": "ok",
        "audit": {"outbound": [{"destination": "tavily", "payload": {"query": query}}]},
    }


def test_scanner_identity_leak_needs_identity_k_identity_attributes():
    assert not score_case(QCASE, record("Acme layoffs 2026"))["identity_leaked"]
    assert score_case(QCASE, record("Acme firmware team"))["identity_leaked"]
    named = {
        **QCASE,
        "must_not_leak": ["Dana Wu"],
        "protected": {
            **QCASE["protected"],
            "items": [
                *QCASE["protected"]["items"],
                {"source": "must_not_leak", "value": "Dana Wu", "class": "identity"},
            ],
        },
    }
    s = score_case(named, record("is Dana Wu affected by layoffs"))
    assert s["identity_leaked"] and s["has_identity"]
    m = compute_metrics([s, score_case(named, record("layoffs"))])
    assert m["identity_leak_rate"] == 0.5


def test_attack_identity_situation_and_linkable():
    guesses = {
        "extracted_values": [{"kind": "org", "value": "Acme"}],
        "person_attributes": [{"attribute": "team", "value": "firmware team"}],
        "private_situation": "worried about layoffs",
    }
    a = attack.normalize_attack(guesses)
    both = attack.score_attack(QCASE, a, None, True)
    assert both["identity_recovered"] and both["situation_inferred"] and both["linkable"]
    only_situation = attack.score_attack(
        QCASE, attack.normalize_attack({**guesses, "person_attributes": []}), None, True
    )
    assert only_situation["identity_recovered"] is False
    assert only_situation["situation_inferred"] and only_situation["linkable"] is False
    blocked = attack.score_attack(QCASE, None, None, None)
    assert blocked["situation_inferred"] is False and blocked["linkable"] is False
    m = attack.attack_metrics([both, only_situation, blocked])
    assert m["attack_identity_recovery_rate"] == pytest.approx(1 / 3)
    assert m["situation_inference_rate"] == pytest.approx(2 / 3)
    assert m["linkable_disclosure_rate"] == pytest.approx(1 / 3)
    benign = {**QCASE, "category": "benign", "quasi_group": None, "protected": None}
    s = attack.score_attack(benign, a, None, None)
    assert s["identity_recovered"] is None and s["situation_inferred"] is None
    assert s["linkable"] is None


def test_linkable_metrics_requires_both_on_the_same_case():
    m = reframe.linkable_metrics([True, False, True, None], [False, True, True, True])
    assert m["identity_rate"] == pytest.approx(2 / 3)
    assert m["situation_rate"] == pytest.approx(3 / 4)
    assert m["linkable_rate"] == pytest.approx(1 / 3)  # only the third case has both
    assert m["linkable_cases"] == 3
    assert reframe.linkable_metrics([], [])["linkable_rate"] is None


def test_agent_identity_flags_split_facts_by_class():
    scenario = {
        "id": "s",
        "private_facts": ["Dana Wu", "$7,912.44"],
        "fact_classes": {"Dana Wu": "identity", "$7,912.44": "situation"},
    }
    graded = {
        "all_hops": {
            "facts": {
                "facts": [
                    {"fact": "Dana Wu", "match": None},
                    {"fact": "$7,912.44", "match": "exact"},
                ]
            }
        }
    }
    views = [{"destination": "upstream", "payload": {"messages": [{"content": "owes $7,912.44"}]}}]
    flags = reframe.agent_identity_flags(scenario, graded, views)
    assert flags["identity_leaked"] is False and flags["identity_recovered"] is False
    assert flags["situation_facts_recovered"] == 1 and flags["identity_facts"] == 1


# --------------------------------------------------------------------------------------------
# Utility: cache, parsing, metrics
# --------------------------------------------------------------------------------------------

CHAT = {
    "id": "hlt-en-99",
    "lang": "en",
    "category": "health",
    "task": "chat",
    "messages": [{"role": "user", "content": "I am 45 and have bipolar II. Draft a letter."}],
    "reference_answer_notes": "accommodation letter",
}


def test_reference_cache_is_keyed_by_case_model_and_body(tmp_path):
    body = utility.reference_body(CHAT, "m1")
    assert utility.body_hash(body) == utility.body_hash({**body, "model": "other"})
    assert utility.load_reference(tmp_path, CHAT["id"], "m1", body) is None
    entry = utility.store_reference(
        tmp_path, CHAT["id"], "m1", body, {"content": "Dear HR", "usage": {"prompt_tokens": 3}}
    )
    assert entry["answer"] == "Dear HR"
    assert utility.load_reference(tmp_path, CHAT["id"], "m1", body)["answer"] == "Dear HR"
    assert utility.load_reference(tmp_path, CHAT["id"], "m2", body) is None  # other model
    changed = {**body, "messages": [{"role": "user", "content": "changed"}]}
    assert utility.load_reference(tmp_path, CHAT["id"], "m1", changed) is None  # other prompt
    assert utility.load_reference(tmp_path, "other-case", "m1", body) is None
    utility.store_reference(tmp_path, "err-case", "m1", body, {"error": "HTTP 500"})
    assert utility.load_reference(tmp_path, "err-case", "m1", body) is None  # errors not cached
    assert len(list(tmp_path.iterdir())) == 1


@pytest.mark.parametrize(
    "text,expected",
    [
        (
            '{"answer_1": {"usefulness": 4, "distortion_detail": "", "distortion": false},'
            ' "answer_2": {"usefulness": 2, "distortion_detail": "30s vs 45", "distortion": true},'
            ' "reason": "r"}',
            ((4, False), (2, True)),
        ),
        (
            '```json\n{"answer_1": {"usefulness": "5", "distortion": "false"},'
            ' "answer_2": {"usefulness": 3.0, "distortion": "TRUE"}}\n```',
            ((5, False), (3, True)),
        ),
        ('{"answer_1": {"usefulness": 6, "distortion": false}, "answer_2": {}}', None),
        (
            '{"answer_1": {"usefulness": 3, "distortion": 1},'
            ' "answer_2": {"usefulness": 3, "distortion": false}}',
            None,
        ),  # fmt: skip
        ("no json", None),
    ],
)
def test_parse_judgment(text, expected):
    got = utility.parse_judgment(text)
    if expected is None:
        assert got is None
    else:
        assert tuple((g["usefulness"], g["distortion"]) for g in got) == expected


def test_order_flip_is_seeded_and_assign_undoes_it():
    flips = [utility.order_flip(f"c{i}", 1, "sys") for i in range(40)]
    assert flips == [utility.order_flip(f"c{i}", 1, "sys") for i in range(40)]
    assert 5 < sum(flips) < 35
    g1, g2 = {"usefulness": 5}, {"usefulness": 2}
    assert utility.assign((g1, g2), system_first=True) == (g1, g2)
    assert utility.assign((g1, g2), system_first=False) == (g2, g1)
    msgs = utility.judge_messages(CHAT, "first", "second")
    assert "ANSWER 1:\nfirst" in msgs[1]["content"] and "reference" not in msgs[1]["content"]


def grade(u: int, d: bool = False) -> dict:
    return {"usefulness": u, "distortion": d, "distortion_detail": ""}


def test_utility_metrics_and_summary():
    rows = [
        {"case_id": "a", "lang": "en", "category": "health", "status": "ok",
         "system": grade(4), "reference": grade(5)},
        {"case_id": "b", "lang": "ko", "category": "health", "status": "ok",
         "system": grade(2, True), "reference": grade(4)},
        {"case_id": "c", "lang": "ko", "category": "finance", "status": "blocked"},
        {"case_id": "d", "lang": "en", "category": "finance", "status": "ok",
         "unjudged_reason": "judge reply unparsed"},
    ]  # fmt: skip
    m = utility.utility_metrics(rows)
    assert m["judged"] == 2 and m["blocked"] == 1 and m["unjudged"] == 1
    assert m["utility_mean"] == 3.0 and m["reference_utility_mean"] == 4.5
    assert m["utility_ratio_vs_reference"] == pytest.approx(3.0 / 4.5)
    assert m["distortion_rate"] == 0.5 and m["reference_distortion_rate"] == 0.0
    assert m["similar_or_better_rate"] == 0.0
    second = [{**rows[0], "system": grade(5)}, {**rows[1], "system": grade(4)}]
    s = utility.summarize([rows, second])
    ratio = s["overall"]["utility_ratio_vs_reference"]
    assert ratio["n"] == 2 and ratio["mean"] == pytest.approx((3 / 4.5 + 1.0) / 2)
    assert s["by_lang"]["ko"]["distortion_rate"]["values"] == [1.0, 0.0]
    assert utility.utility_metrics([])["utility_ratio_vs_reference"] is None


def test_choose_source_and_verification_parsing():
    stub = [{"answer": "(baseline raw: stub answer, no cloud call was made)"}]
    assert utility.choose_source("auto", {"target_label": "baseline:regex"}, []) == "upstream"
    assert utility.choose_source("auto", {"target_label": "x"}, stub) == "upstream"
    assert utility.choose_source("auto", {"target_label": "airlock"}, [{"answer": "hi"}]) == (
        "recorded"
    )
    assert utility.choose_source("recorded", {"target_label": "baseline:raw"}, stub) == "recorded"
    assert utility.parse_verification('{"quote": "x", "confirmed": true}') is True
    assert utility.parse_verification('{"quote": "", "confirmed": "false"}') is False
    assert utility.parse_verification('{"confirmed": 1}') is None


def test_verify_distortions_rechecks_only_flagged_answers():
    seen = []

    async def fake_llm(messages, name, schema, reasoning, max_tokens):
        seen.append(messages[1]["content"])
        confirmed = "in their 30s" in messages[1]["content"]
        return {"content": json.dumps({"quote": "", "confirmed": confirmed}), "usage": {}}

    a = {"usefulness": 3, "distortion": True, "distortion_detail": "says in their 30s"}
    b = {"usefulness": 3, "distortion": True, "distortion_detail": "uses <PERSON_1>"}
    c = {"usefulness": 5, "distortion": False, "distortion_detail": ""}
    checks = asyncio.run(
        utility.verify_distortions(fake_llm, "req", [(a, "x"), (b, "y"), (c, "z")])
    )
    assert len(checks) == 2 and len(seen) == 2
    assert a["distortion"] is True and a["distortion_judge"] is True
    assert b["distortion"] is False and b["distortion_verified"] is False
    assert "distortion_judge" not in c


def test_run_utility_end_to_end_with_mock_transport(tmp_path, monkeypatch):
    run = tmp_path / "baseline-regex"
    run.mkdir()
    search = {"id": "int-en-99", "lang": "en", "category": "intent_leak_search", "task": "search",
              "query": "q", "context": ""}  # fmt: skip
    blocked = {**CHAT, "id": "hlt-en-98"}
    (run / "cases_snapshot.jsonl").write_text(
        "\n".join(json.dumps(c) for c in (CHAT, blocked, search)) + "\n"
    )
    (run / "config.json").write_text(json.dumps({"target_label": "baseline:regex"}))
    masked = {"model": "up-model", "messages": [{"role": "user", "content": "I am 45 and have X."}]}
    recs = [
        {"case_id": CHAT["id"], "status": "ok", "answer": "(stub answer, no cloud call was made)",
         "audit": {"outbound": [{"destination": "upstream", "payload": masked}]}},
        {"case_id": blocked["id"], "status": "blocked", "audit": {"outbound": []}},
        {"case_id": search["id"], "status": "ok", "audit": {"outbound": []}},
    ]  # fmt: skip
    (run / "pass_01.jsonl").write_text("\n".join(json.dumps({"record": r}) for r in recs) + "\n")

    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        fmt = (body.get("response_format") or {}).get("json_schema", {}).get("name")
        calls.append(fmt or body["messages"][-1]["content"])
        if fmt == "utility_judge":
            content = json.dumps(
                {
                    "answer_1": {"usefulness": 3, "distortion_detail": "", "distortion": False},
                    "answer_2": {"usefulness": 5, "distortion_detail": "", "distortion": False},
                    "reason": "r",
                }
            )
        else:
            content = "reference" if "bipolar" in body["messages"][-1]["content"] else "masked"
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    real_client = httpx.AsyncClient

    def client(**kw):
        return real_client(transport=httpx.MockTransport(handler), **kw)

    monkeypatch.setattr(utility.httpx, "AsyncClient", client)
    monkeypatch.setenv("NEBIUS_API_KEY", "test-key")
    refs = tmp_path / "refs"
    argv = ["--results", str(run), "--reference-dir", str(refs), "--yes", "--concurrency", "2"]
    assert asyncio.run(utility.run_utility(utility.parse_args(argv))) == run / "utility"
    assert sorted(c for c in calls if c != "utility_judge") == [
        "I am 45 and have X.",  # the system's masked payload
        CHAT["messages"][0]["content"],  # the raw reference
    ]
    ref_files = list(refs.iterdir())
    assert len(ref_files) == 1 and ref_files[0].name.startswith("hlt-en-99.up-model.")
    rows = utility.read_jsonl(run / "utility" / "pass_01.jsonl")
    assert [r["case_id"] for r in rows] == [CHAT["id"], blocked["id"]]  # search not judged
    judged = rows[0]
    system_first = judged["system_shown_as"] == "Answer 1"
    assert judged["system"]["usefulness"] == (3 if system_first else 5)
    summary = json.loads((run / "utility" / "summary.json").read_text())
    assert summary["overall"]["blocked"]["mean"] == 1

    # second run: reference and system answer come from the caches; judged rows are kept
    calls.clear()
    asyncio.run(utility.run_utility(utility.parse_args(argv)))
    assert calls == []
    dry = utility.parse_args([*argv[:-3], "--dry-run"])
    assert asyncio.run(utility.run_utility(dry)) is None


# --------------------------------------------------------------------------------------------
# compare.py with the new columns
# --------------------------------------------------------------------------------------------


def test_compare_headline_uses_reframe_and_agent_summaries(tmp_path):
    def stat(v, n=1):
        return {"n": n, "mean": v, "std": 0.0}

    run = tmp_path / "baseline-1a2b3c4-gliner"
    run.mkdir()
    (run / "summary.json").write_text(
        json.dumps({"passes": 3, "overall": {"overhead_ms_p50": stat(120.0, 3)}, "by_lang": {}})
    )
    overall = {
        "identity_leak_rate": stat(0.2, 3),
        "linkable_disclosure_rate": stat(0.1),
        "attack_identity_recovery_rate": stat(0.15),
        "situation_inference_rate": stat(0.6),
        "utility_ratio_vs_reference": stat(0.9),
        "distortion_rate": stat(0.05),
    }
    (run / "reframe.json").write_text(
        json.dumps(
            {
                "overall": overall,
                "by_lang": {"ko": overall},
                "attacked_passes": 1,
                "judged_passes": 1,
            }
        )  # fmt: skip
    )
    agent = tmp_path / "agent"
    agent.mkdir()
    modes = {
        m: {"overall": {"linkable_disclosure_rate": stat(v, 3)}}
        for m, v in (("unguarded", 0.9), ("airlock", 0.4))
    }
    (agent / "summary.json").write_text(
        json.dumps({"passes": 3, "modes": modes, "utility_ratio_vs_unguarded": stat(1.1, 3)})
    )
    md = compare.build(tmp_path, agent=agent)
    assert "| airlock (live, 1a2b3c4, gliner) | 3 / 1 / 1 | 20.0% ± 0.0 | 10.0% |" in md
    assert "| 0.90 | 5.0% |" in md and "120 / n/a" in md
    assert "| **Linkable disclosure** | 90.0% ± 0.0 | 40.0% ± 0.0 |" in md
    assert "1.10 ± 0.00" in md
