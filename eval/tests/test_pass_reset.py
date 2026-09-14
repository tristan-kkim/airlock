"""Every pass starts from a clean server state, and the summary says whether passes repeat."""

import argparse
import asyncio
import json

import httpx
import pytest

import run
import scoring

CASE = {
    "id": "dir-en-01",
    "lang": "en",
    "category": "direct_pii",
    "task": "chat",
    "messages": [{"role": "user", "content": "hello"}],
    "vault_terms": [],
    "canaries": [],
    "must_not_leak": [],
    "must_keep": [],
}


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
        passes=3,
        reset_vault=True,
        conversation_scope="pass",
        auto_approve_review=False,
    )
    base.update(kw)
    return argparse.Namespace(**base)


def recording_client(log):
    def handler(request: httpx.Request) -> httpx.Response:
        log.append((request.method, request.url.path))
        if request.url.path == "/vault/reset":
            return httpx.Response(200, json={"reset": True, "detection_cache_cleared": 2})
        if request.url.path == "/v1/chat/completions":
            return httpx.Response(
                200,
                json={"choices": [{"message": {"role": "assistant", "content": "ok"}}]},
                headers={"x-airlock-request-id": "r1"},
            )
        if request.url.path.startswith("/audit/"):
            return httpx.Response(200, json={"request_id": "r1", "outbound": []})
        return httpx.Response(404, json={})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://airlock")


def test_reset_is_sent_before_every_pass():
    log = []

    async def go():
        async with recording_client(log) as client:
            return await run.run_passes(client, [CASE], opts())

    raw_passes, resets = asyncio.run(go())
    assert len(raw_passes) == 3
    assert [r["pass"] for r in resets] == [1, 2, 3]
    assert all(r["detection_cache_cleared"] == 2 for r in resets)
    paths = [p for _, p in log if p in ("/vault/reset", "/v1/chat/completions")]
    assert paths == ["/vault/reset", "/v1/chat/completions"] * 3


def test_no_reset_without_the_flag():
    log = []

    async def go():
        async with recording_client(log) as client:
            return await run.run_passes(client, [CASE], opts(reset_vault=False, passes=2))

    raw_passes, resets = asyncio.run(go())
    assert len(raw_passes) == 2 and resets == []
    assert ("POST", "/vault/reset") not in log


def test_failed_reset_aborts():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    async def go():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://airlock"
        ) as client:
            await run.run_passes(client, [CASE], opts())

    with pytest.raises(SystemExit):
        asyncio.run(go())


def record(case_id, payload, detect_ms):
    return {
        "case_id": case_id,
        "audit": {
            "outbound": [{"destination": "upstream", "payload": payload}] if payload else [],
            "timings_ms": {"detect": detect_ms},
        },
    }


def test_independence_check_flags_repeated_passes():
    passes = [
        [record("a", {"m": "same"}, 3000), record("b", {"m": "b1"}, 3000), record("c", None, 10)],
        [record("a", {"m": "same"}, 400), record("b", {"m": "b2"}, 500), record("c", None, 10)],
        [record("a", {"m": "same"}, 450), record("b", {"m": "b3"}, 450), record("c", None, 10)],
    ]
    ind = scoring.independence_check(passes, 0.6)
    assert ind["cases_compared"] == 2  # c sent nothing
    assert ind["identical_outbound_cases"] == 1
    assert ind["identical_outbound_rate"] == 0.5
    assert ind["detect_ms_p50_by_pass"] == [3000, 400, 450]
    assert ind["warning"] is None  # 50% is not above the threshold

    passes[1][1] = record("b", {"m": "b1"}, 500)
    passes[2][1] = record("b", {"m": "b1"}, 450)
    ind = scoring.independence_check(passes, 0.6)
    assert ind["identical_outbound_rate"] == 1.0
    assert "not independent" in ind["warning"]
    assert scoring.independence_check(passes, 0.0)["warning"] is None  # deterministic detector
    assert scoring.independence_check(passes, None)["warning"] is None
    assert "## Pass independence" in "\n".join(scoring._independence_lines(ind))


def test_independence_check_single_pass():
    ind = scoring.independence_check([[record("a", {"m": 1}, 5)]], 0.6)
    assert ind["cases_compared"] == 0 and ind["identical_outbound_rate"] is None
    assert json.dumps(ind)


def test_detector_temperature_from_health_or_flag():
    assert (
        run.detector_temperature(opts(detector_temperature=None), {"local_temperature": 0.6}) == 0.6
    )
    assert (
        run.detector_temperature(opts(detector_temperature=0.0), {"local_temperature": 0.6}) == 0.0
    )
    assert run.detector_temperature(opts(detector_temperature=None), {"status": "ok"}) is None
