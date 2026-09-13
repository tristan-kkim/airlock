"""Stratified case subsets and hash-verified reuse of attack and utility scores across passes."""

import asyncio
import collections
import json
from pathlib import Path

import httpx
import pytest
from test_attack import _summary

import attack
import compare
import protocol_estimate
import reuse
import run
import subset
import utility

CASES_DIR = Path(__file__).resolve().parents[1] / "cases"


def all_cases():
    return [
        json.loads(line)
        for p in sorted(CASES_DIR.glob("*.jsonl"))
        for line in p.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# --------------------------------------------------------------------------------------------
# Subsets
# --------------------------------------------------------------------------------------------


def test_allocate_is_proportional_and_exact():
    counts = subset.allocate({"a": 27, "b": 27, "c": 10, "d": 6}, 35)
    assert sum(counts.values()) == 35
    assert counts == {"a": 14, "b": 13, "c": 5, "d": 3}
    assert subset.allocate({"a": 2, "b": 1}, 10) == {"a": 2, "b": 1}


def test_stratified_subset_is_deterministic_and_stratified():
    cases = all_cases()
    ids = subset.stratified_ids(cases, 120, seed=0)
    assert len(ids) == 120 == len(set(ids))
    assert ids == subset.stratified_ids(list(reversed(cases)), 120, seed=0)  # order-free
    assert ids != subset.stratified_ids(cases, 120, seed=1)
    by_id = {c["id"]: c for c in cases}
    strata = collections.Counter(subset.stratum(by_id[i]) for i in ids)
    full = collections.Counter(subset.stratum(c) for c in cases)
    for key, n in full.items():
        assert abs(strata[key] - n * 120 / len(cases)) < 1  # largest remainder rounding
    chosen, info = subset.select(cases, "stratified:120", 0)
    assert [c["id"] for c in chosen] == [c["id"] for c in cases if c["id"] in set(ids)]
    assert info["case_ids"] == ids and info["cases"] == 120 and info["of"] == len(cases)
    assert sum(info["strata"].values()) == 120


def test_subset_ids_from_config_or_text(tmp_path):
    cases = all_cases()
    _, info = subset.select(cases, "stratified:20", 3)
    (tmp_path / "config.json").write_text(json.dumps({"subset": info}))
    same, again = subset.select(cases, f"ids:{tmp_path}", 99)
    assert again["case_ids"] == info["case_ids"] and len(same) == 20
    (tmp_path / "ids.txt").write_text("pii-en-01\nhlt-ko-02\n")
    picked, _ = subset.select(cases, f"ids:{tmp_path / 'ids.txt'}")
    assert {c["id"] for c in picked} == {"pii-en-01", "hlt-ko-02"}
    (tmp_path / "bad.txt").write_text("nope-01\n")
    with pytest.raises(ValueError):
        subset.select(cases, f"ids:{tmp_path / 'bad.txt'}")
    for spec in ("stratified", "stratified:0", "random:5", "ids:"):
        with pytest.raises(ValueError):
            subset.parse_spec(spec)
    assert subset.select(cases, None) == (cases, None)


def test_run_py_writes_subset_to_config(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from mock_airlock import create_app

    real_client = httpx.AsyncClient
    transport = httpx.ASGITransport(app=create_app(seed=0))
    monkeypatch.setattr(
        run.httpx, "AsyncClient", lambda **kw: real_client(transport=transport, **kw)
    )
    out = tmp_path / "run"
    opts = run.parse_args(
        ["--passes", "1", "--out", str(out), "--subset", "stratified:9", "--seed", "4", "--quiet"]
    )
    asyncio.run(run.main_async(opts))
    config = json.loads((out / "config.json").read_text())
    snapshot = [json.loads(x) for x in (out / "cases_snapshot.jsonl").read_text().splitlines()]
    assert config["cases"] == 9 and config["subset"]["seed"] == 4
    assert sorted(c["id"] for c in snapshot) == config["subset"]["case_ids"]
    assert config["subset"]["case_ids"] == subset.stratified_ids(all_cases(), 9, 4)


# --------------------------------------------------------------------------------------------
# Hashes
# --------------------------------------------------------------------------------------------


def record(case_id, text, answer="ok", status="ok"):
    return {
        "case_id": case_id,
        "status": status,
        "answer": answer,
        "audit": {
            "request_id": f"req-{text}-{answer}",  # volatile fields are not hashed
            "outbound": [
                {
                    "destination": "upstream",
                    "payload": {
                        "model": attack.ULTRA,
                        "messages": [{"role": "user", "content": text}],
                    },
                }
            ],
        },
    }


def test_payload_hashes():
    a, b = record("x", "hello"), record("x", "hello", answer="different")
    assert reuse.outbound_sha256(a) == reuse.outbound_sha256(b)
    reordered = json.loads(json.dumps(a))
    reordered["audit"]["outbound"][0] = dict(reversed(list(a["audit"]["outbound"][0].items())))
    assert reuse.outbound_sha256(reordered) == reuse.outbound_sha256(a)
    assert reuse.outbound_sha256(record("x", "hello!")) != reuse.outbound_sha256(a)
    assert reuse.judged_sha256(a, "upstream") == reuse.judged_sha256(b, "upstream")
    assert reuse.judged_sha256(a, "recorded") != reuse.judged_sha256(b, "recorded")


# --------------------------------------------------------------------------------------------
# attack.py reuse
# --------------------------------------------------------------------------------------------

CASE_A = {
    "id": "pii-x",
    "category": "direct_pii",
    "lang": "en",
    "task": "chat",
    "messages": [{"role": "user", "content": "Mail Avery Thornbury"}],
    "must_not_leak": ["Avery Thornbury"],
    "canaries": [],
}
CASE_B = {**CASE_A, "id": "pii-y", "messages": [{"role": "user", "content": "Call Bo Lind"}],
          "must_not_leak": ["Bo Lind"]}  # fmt: skip


def write_run(run_dir: Path, passes, label="baseline:regex"):
    run_dir.mkdir(parents=True)
    (run_dir / "cases_snapshot.jsonl").write_text(
        "\n".join(json.dumps(c) for c in (CASE_A, CASE_B)) + "\n"
    )
    (run_dir / "config.json").write_text(json.dumps({"target_label": label}))
    for i, records in enumerate(passes, start=1):
        (run_dir / f"pass_{i:02d}.jsonl").write_text(
            "\n".join(json.dumps({"record": r}) for r in records) + "\n"
        )


def fake_attack_llm(calls):
    def make(client, model):
        async def llm(messages, name, schema, reasoning, max_tokens):
            content = messages[-1]["content"]
            calls.append((name, "Avery" in content, "Lind" in content))
            found = "Avery Thornbury" if "Avery" in content else "Bo Lind"
            reply = {"extracted_values": [{"kind": "name", "value": found}],
                     "person_attributes": [], "private_situation": ""}  # fmt: skip
            usage = {"prompt_tokens": 10, "completion_tokens": 5}
            return {"content": json.dumps(reply), "model": model, "usage": usage}

        return llm

    return make


def test_attack_reuses_identical_passes_and_scores_changed_cases(tmp_path, monkeypatch):
    run_dir = tmp_path / "baseline-regex"
    p1 = [record("pii-x", "Mail Avery Thornbury"), record("pii-y", "Call Bo Lind")]
    p2 = [record("pii-x", "Mail Avery Thornbury"), record("pii-y", "Call Bo Lind, today")]
    write_run(run_dir, [p1, p2, p1])
    calls = []
    monkeypatch.setattr(attack, "make_llm", fake_attack_llm(calls))
    monkeypatch.setattr(attack, "read_env_key", lambda name="NEBIUS_API_KEY": "test")
    opts = attack.parse_args(
        ["--rescore", str(run_dir), "--passes", "3", "--reuse-identical-passes"]
    )
    out = asyncio.run(attack.run_attack(opts))
    assert len(calls) == 3  # pass 1: both cases; pass 2: only the changed case; pass 3: none
    rows = [
        {
            r["case_id"]: r
            for r in map(json.loads, (out / f"pass_0{i}.jsonl").read_text().splitlines())
        }
        for i in (1, 2, 3)
    ]
    assert "reused_from" not in rows[0]["pii-x"] and rows[0]["pii-x"]["payload_sha256"]
    assert rows[1]["pii-x"]["reused_from"] == {
        "pass": 1,
        "sha256": rows[0]["pii-x"]["payload_sha256"],
    }
    assert "reused_from" not in rows[1]["pii-y"] and rows[2]["pii-y"]["reused_from"]["pass"] == 1
    assert "attacker" not in rows[1]["pii-x"] and rows[1]["pii-x"]["score"]["n_exact"] == 1
    config = json.loads((out / "config.json").read_text())
    assert config["reuse"]["rows"] == 6 and config["reuse"]["rows_reused"] == 3
    assert config["reuse"]["by_pass"][1]["reused_within_run"] == 1
    assert config["estimate"]["attacker_calls"] == 3
    assert config["usage"]["prompt_tokens"] == 30  # reused rows add no usage
    summary = json.loads((out / "summary.json").read_text())
    before = summary["overall"]["attack_value_recovery_rate"]
    attack.score_only(run_dir)  # reused rows are rescored from the rows they point at
    after = json.loads((out / "summary.json").read_text())["overall"]["attack_value_recovery_rate"]
    assert before == after and after["mean"] == 1.0

    calls.clear()
    second = tmp_path / "final" / "baseline-regex"
    write_run(second, [p2, p2])
    opts = attack.parse_args(
        ["--rescore", str(second), "--passes", "2", "--reuse-identical-passes",
         "--reuse-from", str(run_dir)]
    )  # fmt: skip
    out2 = asyncio.run(attack.run_attack(opts))
    assert calls == [("attack", False, True)]  # pii-x from the earlier run; pii-y changed
    row = json.loads((out2 / "pass_01.jsonl").read_text().splitlines()[0])
    assert row["reused_from"]["results_dir"].endswith("baseline-regex")
    assert json.loads((out2 / "config.json").read_text())["reuse"]["rows_reused"] == 3

    calls.clear()
    opts = attack.parse_args(
        ["--rescore", str(second), "--passes", "1", "--reuse-from", str(run_dir),
         "--attack-model", attack.SUPER, "--out-name", "attack-super"]
    )  # fmt: skip
    asyncio.run(attack.run_attack(opts))
    assert len(calls) == 2  # other attacker model: nothing reusable


# --------------------------------------------------------------------------------------------
# utility.py reuse
# --------------------------------------------------------------------------------------------


def test_utility_reuses_identical_passes(tmp_path, monkeypatch):
    run_dir = tmp_path / "baseline-regex"
    p1 = [record("pii-x", "Mail Avery Thornbury"), record("pii-y", "Call Bo Lind")]
    p2 = [record("pii-x", "Mail Avery Thornbury"), record("pii-y", "Call Bo Lind, today")]
    write_run(run_dir, [p1, p2, p1])
    judge_calls, answer_calls = [], []

    async def fake_complete(client, body, retries=4):
        answer_calls.append(body["messages"][-1]["content"])
        return {"content": "Here you go.", "usage": {"prompt_tokens": 5, "completion_tokens": 5}}

    def make(client, model):
        async def llm(messages, name, schema, reasoning, max_tokens):
            judge_calls.append(name)
            grade = {"usefulness": 4, "distortion_detail": "", "distortion": False}
            return {"content": json.dumps({"answer_1": grade, "answer_2": grade, "reason": ""}),
                    "model": model, "usage": {}}  # fmt: skip

        return llm

    monkeypatch.setattr(utility, "complete", fake_complete)
    monkeypatch.setattr(attack, "make_llm", make)
    monkeypatch.setattr(attack, "read_env_key", lambda name="NEBIUS_API_KEY": "test")
    opts = utility.parse_args(
        ["--results", str(run_dir), "--passes", "3", "--yes", "--reuse-identical-passes",
         "--reference-dir", str(tmp_path / "refs")]
    )  # fmt: skip
    out = asyncio.run(utility.run_utility(opts))
    assert judge_calls.count("utility_judge") == 3
    assert len(answer_calls) == 2 + 3  # 2 references + 3 system answers (reused rows need none)
    rows = [
        {
            r["case_id"]: r
            for r in map(json.loads, (out / f"pass_0{i}.jsonl").read_text().splitlines())
        }
        for i in (1, 2, 3)
    ]
    assert rows[1]["pii-x"]["reused_from"]["pass"] == 1 and rows[1]["pii-x"]["pass"] == 2
    assert "judge" not in rows[1]["pii-x"] and rows[1]["pii-x"]["system"]["usefulness"] == 4
    assert "reused_from" not in rows[1]["pii-y"] and rows[2]["pii-y"]["reused_from"]
    config = json.loads((out / "config.json").read_text())
    assert config["reuse"]["rows_reused"] == 3 and config["reuse_identical_passes"] is True
    summary = json.loads((out / "summary.json").read_text())
    assert summary["overall"]["judged"]["values"] == [2.0, 2.0, 2.0]


# --------------------------------------------------------------------------------------------
# COMPARISON.md and the cost projection
# --------------------------------------------------------------------------------------------


def test_compare_marks_reused_scores(tmp_path):
    d = tmp_path / "baseline-raw"
    (d / "attack").mkdir(parents=True)
    (d / "utility").mkdir()
    (d / "summary.json").write_text(json.dumps(_summary(0.99, 0.98)))
    (d / "reframe.json").write_text(
        json.dumps({"overall": {}, "attacked_passes": 3, "judged_passes": 3})
    )
    info = {"rows": 729, "rows_reused": 486, "from": None, "note": reuse.REUSE_NOTE}
    stat = {"n": 3, "mean": 0.5, "std": 0.0}
    (d / "attack" / "summary.json").write_text(
        json.dumps(
            {
                "passes": 3,
                "overall": {k: stat for k, _ in compare.ATTACK_COLUMNS},
                "by_lang": {},
                "config": {"model": "m", "reuse": info},
            }
        )  # fmt: skip
    )
    (d / "utility" / "config.json").write_text(
        json.dumps({"reuse": {**info, "rows": 630, "rows_reused": 420, "from": "eval/results/x"}})
    )
    md = compare.build(tmp_path)
    assert "| raw (pass-through) | 3 / 3* / 3* |" in md
    assert reuse.REUSE_NOTE in md and "attack 486 of 729 rows" in md
    assert "utility 420 of 630 rows, pass 1 from `eval/results/x`" in md
    assert "| raw (pass-through) | 3* |" in md


def test_protocol_variants_include_airlock_upstream_and_reuse():
    rows = protocol_estimate.variant_rows()
    a, b, c = rows
    assert a["cases"] == b["cases"] == 243 and c["cases"] == 120
    for r in rows:
        assert r["airlock_upstream"]["calls"] > 0 and r["airlock_upstream"]["usd"] > 0
        assert r["total_reused"]["usd"] < r["total_once"]["usd"] < r["total_no_reuse"]["usd"]
        assert r["total_reused"]["tokens"] == pytest.approx(r["airlock"]["tokens"])
    assert b["airlock"]["tokens"] == pytest.approx(2 * a["airlock"]["tokens"], rel=0.01)
    assert c["total_once"]["tokens"] < b["total_once"]["tokens"]
    once = protocol_estimate.estimate(3, 3, ["raw"], 0, baseline_judge_passes=1)
    thrice = protocol_estimate.estimate(3, 3, ["raw"], 0)
    assert thrice["parts"]["attacker"]["calls"] == 3 * once["parts"]["attacker"]["calls"]
