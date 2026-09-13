"""End to end: harness against the in-process mock. Proves the harness catches the mock's holes."""

import argparse
import asyncio
import json
from pathlib import Path

import httpx
import pytest

pytest.importorskip("fastapi")

import run  # noqa: E402
from mock_airlock import create_app  # noqa: E402
from scoring import score_case, summarize  # noqa: E402

CASES_DIR = Path(__file__).resolve().parents[1] / "cases"


def opts(**kw):
    base = dict(
        model="airlock",
        max_results=5,
        concurrency=1,
        audit_retries=1,
        register_canaries=False,
        shuffle=False,
        seed=0,
        quiet=True,
    )
    base.update(kw)
    return argparse.Namespace(**base)


def load(ids):
    by_id = {}
    for p in CASES_DIR.glob("*.jsonl"):
        for line in p.read_text(encoding="utf-8").splitlines():
            c = json.loads(line)
            by_id[c["id"]] = c
    return [by_id[i] for i in ids]


async def run_cases(cases, passes=1, seed=0):
    transport = httpx.ASGITransport(app=create_app(seed=seed))
    async with httpx.AsyncClient(transport=transport, base_url="http://mock") as client:
        return [await run.run_pass(client, cases, p, opts()) for p in range(1, passes + 1)]


def scored(cases, raw):
    by_id = {c["id"]: c for c in cases}
    return {r["case_id"]: score_case(by_id[r["case_id"]], r) for r in raw}


def test_harness_catches_mock_holes():
    ids = [
        "adv-en-04",  # PII inside tool-call arguments (mock never inspects them)
        "adv-ko-02",  # phone number read out in Korean numerals
        "adv-en-03",  # base64-wrapped deploy key
        "sec-en-05",  # postgres DSN: detector misses, gate blocks
        "ben-en-02",  # 479001600: mock over-masks long numbers
        "qid-en-01",
    ]  # quasi-identifiers: mock detects none
    cases = load(ids)
    [raw] = asyncio.run(run_cases(cases))
    s = scored(cases, raw)

    tool = s["adv-en-04"]
    assert tool["status"] == "ok" and tool["leaked"]
    assert any(v["hits"] and "@example." in v["value"] for v in tool["values"])

    numerals = s["adv-ko-02"]
    variants = {h["variant"] for v in numerals["values"] for h in v["hits"]}
    assert "numeral_words" in variants

    b64 = s["adv-en-03"]
    assert any(h["variant"].startswith("decoded:") for v in b64["values"] for h in v["hits"])

    dsn = s["sec-en-05"]
    assert dsn["blocked"] and not dsn["leaked"]
    assert {v["outcome"] for v in dsn["values"]} == {"gate_saved"}

    benign = s["ben-en-02"]
    assert benign["masking_detections"] >= 1 and "479001600" in benign["must_keep_missing"]

    assert s["qid-en-01"]["quasi"]["reidentified"]


def test_audit_payload_is_what_harness_scans():
    cases = load(["pii-en-01"])
    [raw] = asyncio.run(run_cases(cases))
    rec = raw[0]
    assert rec["status"] == "ok" and rec["request_id"]
    outbound = rec["audit"]["outbound"]
    assert outbound and outbound[0]["destination"] == "upstream"
    # mock masks e-mail and phone in canonical format
    text = json.dumps(outbound[0]["payload"], ensure_ascii=False)
    assert "@example." not in text and "555-01" not in text


def test_multi_pass_summary_reports_spread():
    cases = load(["pii-en-01", "pii-en-04", "hlt-en-04", "vlt-en-02", "ben-en-01"])
    raw_passes = asyncio.run(run_cases(cases, passes=3))
    by_id = {c["id"]: c for c in cases}
    scored_passes = [[score_case(by_id[r["case_id"]], r) for r in p] for p in raw_passes]
    summary = summarize(cases, scored_passes, {"base_url": "mock"})
    lr = summary["overall"]["leak_rate"]
    assert lr["n"] == 3 and lr["min"] <= lr["mean"] <= lr["max"]
    assert summary["passes"] == 3
