"""A budget-exhausted (402) or persistently throttled (429) provider stops the whole batch."""

import argparse
import asyncio

import httpx
import pytest

import attack
import run
import utility


def counting_client(status, base_url="http://tf.test/v1"):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(status, json={"detail": f"status {status}"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url=base_url)
    return client, calls


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def instant(_seconds):
        return None

    monkeypatch.setattr(asyncio, "sleep", instant)


SCHEMA = {"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"]}


def test_attack_llm_402_makes_one_call():
    calls_seen = []

    async def go():
        client, calls = counting_client(402)
        calls_seen.append(calls)
        async with client:
            llm = attack.make_llm(client, attack.ULTRA, retries=4)
            await llm([{"role": "user", "content": "x"}], "t", SCHEMA, "none", 50)

    with pytest.raises(attack.ProviderAbort):
        asyncio.run(go())
    assert len(calls_seen[0]) == 1


def test_attack_llm_aborts_on_429_past_retries():
    calls_seen = []

    async def go():
        client, calls = counting_client(429)
        calls_seen.append(calls)
        async with client:
            llm = attack.make_llm(client, attack.ULTRA, retries=2)
            await llm([{"role": "user", "content": "x"}], "t", SCHEMA, "none", 50)

    with pytest.raises(attack.ProviderAbort, match="429"):
        asyncio.run(go())
    assert len(calls_seen[0]) == 3


def test_attack_llm_other_errors_still_become_error_rows():
    async def go():
        client, calls = counting_client(400)
        async with client:
            llm = attack.make_llm(client, attack.ULTRA, retries=2)
            return await llm([{"role": "user", "content": "x"}], "t", SCHEMA, "none", 50), calls

    result, calls = asyncio.run(go())
    assert result["error"].startswith("HTTP 400") and len(calls) == 1


def test_attack_main_exits_with_a_clear_message(monkeypatch):
    async def fake_run(opts):
        raise attack.ProviderAbort("HTTP 402 from Token Factory")

    monkeypatch.setattr(attack, "run_attack", fake_run)
    monkeypatch.setattr(
        attack,
        "parse_args",
        lambda argv: argparse.Namespace(score_only=False, grade_situation=False),
    )
    with pytest.raises(SystemExit, match="attack.py aborted: HTTP 402"):
        attack.main([])


@pytest.mark.parametrize("status,match", [(402, "402"), (429, "429")])
def test_utility_complete_aborts(status, match):
    async def go():
        client, _ = counting_client(status)
        async with client:
            await utility.complete(client, {"model": attack.ULTRA, "messages": []}, retries=1)

    with pytest.raises(attack.ProviderAbort, match=match):
        asyncio.run(go())


def test_utility_main_exits_with_a_clear_message(monkeypatch):
    async def fake_run(opts):
        raise attack.ProviderAbort("HTTP 402 from Token Factory")

    monkeypatch.setattr(utility, "run_utility", fake_run)
    monkeypatch.setattr(utility, "parse_args", lambda argv: argparse.Namespace(score_only=False))
    with pytest.raises(SystemExit, match="utility.py aborted"):
        utility.main([])


CASE = {
    "id": "dir-en-01",
    "lang": "en",
    "category": "direct_pii",
    "task": "chat",
    "messages": [{"role": "user", "content": "hello"}],
    "vault_terms": [],
}


def harness_opts():
    return argparse.Namespace(
        model="airlock",
        max_results=5,
        audit_retries=0,
        register_canaries=False,
        conversation_scope="pass",
        auto_approve_review=False,
        concurrency=1,
        shuffle=False,
        seed=0,
        quiet=True,
    )


def airlock_client(upstream_status, calls):
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(
            502,
            json={
                "error": {
                    "type": "airlock_upstream_error",
                    "message": f"upstream returned HTTP {upstream_status}",
                    "upstream_status": upstream_status,
                }
            },
        )

    return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://airlock")


@pytest.mark.parametrize("upstream_status,expected_calls", [(402, 1), (429, 5)])
def test_harness_aborts_the_pass(upstream_status, expected_calls):
    calls = []

    async def go():
        async with airlock_client(upstream_status, calls) as client:
            await run.run_pass(client, [CASE, {**CASE, "id": "dir-en-02"}], 1, harness_opts())

    with pytest.raises(run.UpstreamAbort, match=str(upstream_status)):
        asyncio.run(go())
    assert len(calls) == expected_calls  # the second case is never sent


def test_harness_other_upstream_errors_are_error_rows():
    calls = []

    async def go():
        async with airlock_client(500, calls) as client:
            return await run.execute_case(client, CASE, harness_opts())

    record = asyncio.run(go())
    assert record["status"] == "error" and len(calls) == 1
