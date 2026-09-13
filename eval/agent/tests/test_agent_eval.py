"""Offline checks for the agent-mode evaluation: scenarios, observer views, scoring."""

from __future__ import annotations

import sys
from pathlib import Path

AGENT_EVAL_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AGENT_EVAL_DIR))

import run_agent_eval as ev  # noqa: E402


def test_scenarios_are_valid_and_balanced() -> None:
    scenarios = ev.load_scenarios()
    assert len(scenarios) == 16
    assert [p for s in scenarios for p in ev.validate_scenario(s)] == []
    assert sum(s["lang"] == "ko" for s in scenarios) == 8
    topics = {s["topic"] for s in scenarios}
    assert len(topics) == 8
    for topic in topics:
        assert sorted(s["lang"] for s in scenarios if s["topic"] == topic) == ["en", "ko"]


def test_observer_views_union_of_upstream_messages_and_search_only() -> None:
    audit = {
        "hops": [
            {
                "destination": "upstream",
                "payload": {"messages": [{"role": "user", "content": "q"}]},
            },
            {"destination": "tavily", "payload": {"query": "generic query", "max_results": 5}},
            {"destination": "tavily", "decision": "block"},  # nothing sent
            {
                "destination": "upstream",
                "payload": {
                    "messages": [
                        {"role": "user", "content": "q"},
                        {"role": "tool", "content": "Dear Jane Roe"},
                    ]
                },
            },
            # a later turn masks what the earlier turn sent: both versions count
            {
                "destination": "upstream",
                "payload": {
                    "messages": [
                        {"role": "user", "content": "q"},
                        {"role": "tool", "content": "Dear <PERSON_1>"},
                    ]
                },
            },
        ]
    }
    views = ev.observer_views(audit)
    assert views["search"] == [{"destination": "tavily", "payload": {"query": "generic query"}}]
    upstream = views["all"][0]["payload"]["messages"]
    assert [m["content"] for m in upstream] == ["q", "Dear Jane Roe", "Dear <PERSON_1>"]
    assert views["all"][1:] == views["search"]
    assert ev.observer_views({"hops": []}) == {"all": [], "search": []}


def test_score_facts_uses_attack_matching() -> None:
    scenario = {"private_facts": ["Halcyon Freight Systems", "HFS-40418", "$11,250"]}
    attacked = {
        "extracted_values": [{"kind": "company", "value": "Halcyon Freight Systems, Inc."}],
        "person_attributes": [{"attribute": "employee id", "value": "HFS 40418"}],
        "private_situation": "",
    }
    scored = ev.score_facts(scenario, attacked)
    assert scored["n"] == 3
    assert [f["match"] for f in scored["facts"]][:2] == ["exact", "exact"]
    assert scored["exact"] == 2
    assert ev.score_facts(scenario, None)["exact"] == 0


def test_mode_metrics_rates() -> None:
    runs = [
        {"status": "finished", "searches": 2, "search_rewritten": 1, "search_blocked": 1,
         "steps": 5, "latency_s": 10.0},
        {"status": "blocked", "searches": 0, "search_rewritten": 0, "search_blocked": 0,
         "steps": 3, "latency_s": 20.0},
    ]  # fmt: skip
    graded = [
        {"all_hops": {"facts": {"n": 4, "exact": 2, "partial": 3}, "situation": True},
         "search_only": {"facts": {"n": 4, "exact": 0, "partial": 1}, "situation": False},
         "utility": {"score": 4}},
        {"all_hops": {"facts": {"n": 4, "exact": 0, "partial": 0}, "situation": False},
         "search_only": {"facts": {"n": 4, "exact": 0, "partial": 0}, "situation": False},
         "utility": {"score": 2}},
    ]  # fmt: skip
    m = ev.mode_metrics(runs, graded)
    assert m["fact_recovery"] == 2 / 8 and m["fact_recovery_partial"] == 3 / 8
    assert m["situation_inference"] == 0.5 and m["search_only_situation_inference"] == 0
    assert m["utility_mean"] == 3 and m["finished_rate"] == 0.5
    assert m["search_blocked_rate"] == 0.5 and m["search_rewritten_rate"] == 0.5
