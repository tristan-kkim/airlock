"""Per-case scoring and metric math."""

import math

import pytest

from scoring import (
    aggregate,
    case_failures,
    compute_metrics,
    describe,
    overhead_ms,
    render_markdown,
    score_case,
    sha256_text,
    summarize,
)


def mk_case(cid="c1", category="direct_pii", **kw):
    base = {
        "id": cid,
        "lang": "en",
        "category": category,
        "task": "chat",
        "messages": [{"role": "user", "content": "x"}],
        "vault_terms": [],
        "canaries": [],
        "must_not_leak": [],
        "must_keep": [],
        "quasi_group": None,
        "quasi_k": None,
    }
    base.update(kw)
    return base


def mk_record(
    outbound=None, status="ok", detections=None, decision="allow", reasons=None, timings=None
):
    return {
        "status": status,
        "http_status": 200 if status == "ok" else 422,
        "request_id": "r",
        "client_ms": 10.0,
        "audit": {
            "outbound": [{"destination": d, "payload": p} for d, p in (outbound or [])],
            "detections": detections or [],
            "gate": {"decision": decision, "reasons": reasons or []},
            "timings_ms": timings or {},
        },
    }


def up(text):
    return ("upstream", {"messages": [{"role": "user", "content": text}]})


def test_leak_detected_and_outcome_missed():
    c = mk_case(must_not_leak=["Avery Thornbury"], must_keep=["rent"])
    s = score_case(c, mk_record([up("Avery Thornbury late rent")]))
    assert s["leaked"] and s["value_leaked"] and s["exact_leaked"]
    assert s["values"][0]["outcome"] == "missed_leaked"
    assert s["must_keep_missing"] == []


def test_masked_value_is_detected_removed():
    c = mk_case(must_not_leak=["Avery Thornbury"])
    det = [
        {
            "text_sha256": sha256_text("Avery Thornbury"),
            "type": "PERSON",
            "action": "mask",
            "source": "llm",
        }
    ]
    s = score_case(c, mk_record([up("[[PERSON_1]] late rent")], detections=det))
    assert not s["leaked"]
    assert s["values"][0]["outcome"] == "detected_removed"


def test_leaked_despite_detection():
    c = mk_case(must_not_leak=["Avery Thornbury"])
    det = [{"text_sha256": sha256_text("Avery Thornbury"), "type": "PERSON", "action": "keep"}]
    s = score_case(c, mk_record([up("Avery Thornbury")], detections=det))
    assert s["values"][0]["outcome"] == "leaked_despite_detection"
    assert s["masking_detections"] == 0


def test_gate_save_attribution_by_hash_prefix():
    c = mk_case(must_not_leak=["Quillmere", "Tessaline"])
    reasons = [f"declared_term:ORG:{sha256_text('Quillmere')[:12]}"]
    s = score_case(c, mk_record([], status="blocked", decision="block", reasons=reasons))
    by_value = {v["value"]: v for v in s["values"]}
    assert (
        by_value["Quillmere"]["outcome"] == "gate_saved"
        and by_value["Quillmere"]["gate_attributed"]
    )
    assert (
        by_value["Tessaline"]["outcome"] == "gate_saved"
        and not by_value["Tessaline"]["gate_attributed"]
    )
    assert s["must_keep_missing"] is None  # nothing sent: not measurable


def test_blocked_but_something_was_already_sent_counts_as_leak():
    c = mk_case(task="search", must_not_leak=["Quillmere"])
    s = score_case(
        c,
        mk_record([("tavily", {"query": "Quillmere layoffs"})], status="blocked", decision="block"),
    )
    assert s["leaked"] and s["values"][0]["outcome"] == "missed_leaked"


def test_quasi_threshold_is_per_destination():
    group = [["Acme"], ["firmware"], ["layoffs"]]
    c = mk_case(task="search", quasi_group=group, quasi_k=3)
    split = mk_record([("tavily", {"query": "Acme layoffs"}), ("upstream", {"q": "firmware"})])
    s = score_case(c, split)
    assert s["quasi"]["max_found"] == 2 and not s["leaked"]
    joint = mk_record([("tavily", {"query": "Acme firmware layoffs"})])
    assert score_case(c, joint)["quasi"]["reidentified"]


def test_quasi_alternatives():
    c = mk_case(quasi_group=[["turned 52", "age 52"], ["Tulsa"]], quasi_k=2)
    assert score_case(c, mk_record([up("age 52 in Tulsa")]))["leaked"]
    assert not score_case(c, mk_record([up("in her 50s in Oklahoma")]))["leaked"]


def test_canary_flag():
    c = mk_case(must_not_leak=["pw=Q7rK2vX9"], canaries=["Q7rK2vX9"])
    s = score_case(c, mk_record([up("password Q7rK2vX9")]))
    assert s["canary_leaked"] and s["n_values_leaked"] == 1


def test_error_record():
    s = score_case(mk_case(), {"status": "error", "error": "boom"})
    assert s["status"] == "error"


def test_overhead_ms():
    assert overhead_ms({"detect": 100, "gate": 5, "upstream": 900, "total": 1010}) == 110
    assert overhead_ms({"detect": 100, "tavily": 400, "rerank": 50}) == 150
    assert overhead_ms({}) is None


def _scored_pass(leak_flags, benign_blocked=False):
    """Build a pass of 4 sensitive cases (leak flags given) + 1 benign case."""
    out = []
    for i, leak in enumerate(leak_flags):
        c = mk_case(f"s{i}", must_not_leak=["Avery Thornbury"], must_keep=["rent", "late"])
        text = "Avery Thornbury late rent" if leak else "[[PERSON_1]] rent"
        out.append(score_case(c, mk_record([up(text)])))
    b = mk_case("b0", category="benign", must_keep=["Alan Turing"])
    if benign_blocked:
        out.append(score_case(b, mk_record([], status="blocked", decision="block")))
    else:
        det = [{"text_sha256": sha256_text("Alan Turing"), "type": "PERSON", "action": "mask"}]
        out.append(score_case(b, mk_record([up("[[PERSON_1]] Enigma")], detections=det)))
    return out


def test_compute_metrics_rates():
    m = compute_metrics(_scored_pass([True, False, False, False]))
    assert m["leak_rate"] == pytest.approx(0.25)
    assert m["block_rate"] == 0
    assert m["benign_false_positive_rate"] == 1.0
    # must_keep: 4 sensitive cases x 2 + benign 1 = 9 strings
    # missing: "late" in 3 masked cases + "Alan Turing" in the benign case
    assert m["over_redaction_rate"] == pytest.approx(4 / 9)
    assert m["gate_save_rate"] == 0.0


def test_compute_metrics_over_block_benign():
    m = compute_metrics(_scored_pass([False] * 4, benign_blocked=True))
    assert m["over_block_benign"] == 1.0
    assert m["block_rate"] == pytest.approx(1 / 5)
    assert m["block_rate_sensitive"] == 0.0


def test_describe_uses_sample_std_and_range():
    d = describe([0.2, 0.4, None, 0.6])
    assert d["n"] == 3 and d["mean"] == pytest.approx(0.4)
    assert d["std"] == pytest.approx(0.2)  # sample (n-1) standard deviation
    assert (d["min"], d["max"]) == (0.2, 0.6)
    assert describe([0.5])["std"] == 0.0
    assert describe([None])["mean"] is None


def test_aggregate_across_passes():
    passes = [
        compute_metrics(_scored_pass(flags))
        for flags in ([True, False, False, False], [True, True, False, False], [False] * 4)
    ]
    agg = aggregate(passes)
    assert agg["leak_rate"]["values"] == [0.25, 0.5, 0.0]
    assert agg["leak_rate"]["mean"] == pytest.approx(0.25)
    assert agg["leak_rate"]["std"] == pytest.approx(0.25)
    assert "value_outcomes" not in agg


def test_persistent_vs_flaky_failures():
    passes = [
        _scored_pass(flags)
        for flags in (
            [True, True, False, False],
            [True, False, False, False],
            [True, True, False, False],
        )
    ]
    f = case_failures(passes)
    rows = {r["case_id"]: r for r in f["leaks"]}
    assert rows["s0"]["leaked_passes"] == 3 and rows["s0"]["persistent"]
    assert rows["s1"]["leaked_passes"] == 2 and not rows["s1"]["persistent"]
    assert "s2" not in rows
    assert [r["case_id"] for r in f["leaks"]] == ["s0", "s1"]
    assert rows["s0"]["leaked_values"]["Avery Thornbury"]["passes"] == 3


def test_summary_and_markdown_render():
    passes = [_scored_pass([True, False, False, False]) for _ in range(2)]
    cases = [mk_case(f"s{i}") for i in range(4)] + [mk_case("b0", category="benign")]
    summary = summarize(cases, passes, {"base_url": "http://x", "dataset_sha256": "abc"})
    assert summary["passes"] == 2
    assert len(summary["persistent_leaks"]) == 1
    md = render_markdown(summary)
    assert "| Leak rate (cases) | 25.0% | 0.0 pp | 25.0% to 25.0% |" in md
    assert not math.isnan(summary["overall"]["leak_rate"]["std"])
