"""Baseline servers answer every call the harness makes, in the shapes the harness expects."""

import argparse
import asyncio
import json
import sys
from pathlib import Path

import httpx
import pytest

pytest.importorskip("fastapi")

BASELINES_DIR = Path(__file__).resolve().parents[1] / "baselines"
sys.path.insert(0, str(BASELINES_DIR))

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402

import common  # noqa: E402
import gliner_pii  # noqa: E402  (heavy imports are lazy)
import raw  # noqa: E402
import regex_only  # noqa: E402
import run  # noqa: E402
from scoring import score_case  # noqa: E402

CASES_DIR = Path(__file__).resolve().parents[1] / "cases"


def opts(**kw):
    base = dict(
        model="airlock",
        max_results=5,
        concurrency=1,
        audit_retries=0,
        register_canaries=False,
        shuffle=False,
        seed=0,
        quiet=True,
        auto_approve_review=False,
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


async def run_cases(app, cases, **kw):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://baseline") as client:
        health = (await client.get("/healthz")).json()
        reset = await client.post("/vault/reset", json={})
        assert reset.status_code == 200 and reset.json()["reset"] is True
        return health, await run.run_pass(client, cases, 1, opts(**kw))


# One case per task shape: chat, search, declared vault terms, tool-call arguments, benign.
IDS = ["pii-en-01", "int-ko-01", "vlt-ko-01", "adv-en-04", "ben-en-02"]


class FakeDetector:
    """Flags every occurrence of the word 'secret'; exercises the pluggable detector path."""

    name = "fake"

    def detect(self, text, lang):
        out, start = [], text.find("secret")
        while start != -1:
            out.append(common.Span(start, start + 6, "SECRET", f"fake:{lang}", 0.9))
            start = text.find("secret", start + 1)
        return out


class FakeAnonymizer(FakeDetector):
    def anonymize(self, text, spans):
        for s in sorted(spans, key=lambda s: -s.start):
            text = text[: s.start] + f"<{s.type}>" + text[s.end :]
        return text


@pytest.mark.parametrize(
    "build",
    [
        raw.build,
        regex_only.build,
        lambda: common.create_app("fake", FakeDetector()),
        lambda: common.create_app("fake_anon", FakeAnonymizer()),
    ],
)
def test_contract_conformance(build):
    app = build()
    cases = load(IDS)
    health, records = asyncio.run(run_cases(app, cases))
    assert health["status"] == "ok" and health["cloud_calls"] is False
    by_id = {c["id"]: c for c in cases}
    for r in records:
        assert r["status"] == "ok", r
        audit = r["audit"]
        assert audit["request_id"] == r["request_id"]
        assert audit["gate"]["decision"] == "allow"
        [out] = audit["outbound"]
        assert out["destination"] == (
            "tavily" if by_id[r["case_id"]]["task"] == "search" else "upstream"
        )
        s = score_case(by_id[r["case_id"]], r)
        assert s["status"] == "ok" and s["n_outbound"] == 1


def test_raw_is_the_upper_bound():
    cases = load(IDS)
    _, records = asyncio.run(run_cases(raw.build(), cases))
    by_id = {c["id"]: c for c in cases}
    for r in records:
        s = score_case(by_id[r["case_id"]], r)
        assert s["masking_detections"] == 0
        if by_id[r["case_id"]]["task"] == "chat" and s["n_values"]:
            assert all(v["hits"] for v in s["values"]), r["case_id"]


def test_regex_masks_vault_terms_and_tool_arguments():
    cases = load(["vlt-ko-01", "adv-en-04"])
    _, records = asyncio.run(run_cases(regex_only.build(), cases))
    by_id = {c["id"]: c for c in cases}
    s = {r["case_id"]: score_case(by_id[r["case_id"]], r) for r in records}
    vault = {v["value"]: v for v in s["vlt-ko-01"]["values"]}
    assert not vault["탁라온"]["hits"] and vault["탁라온"]["outcome"] == "detected_removed"
    tool = s["adv-en-04"]
    assert not any(v["hits"] and "@example." in v["value"] for v in tool["values"])


def test_vault_terms_delete_and_reset():
    async def go():
        transport = httpx.ASGITransport(app=regex_only.build())
        async with httpx.AsyncClient(transport=transport, base_url="http://b") as c:
            assert (await c.post("/vault/terms", json={"terms": ["Acme", "Zed"]})).json()[
                "total"
            ] == 2
            r = await c.request("DELETE", "/vault/terms", json={"terms": ["Zed"]})
            assert r.json() == {"removed": 1, "total": 1}
            assert (await c.post("/vault/reset", json={})).json()["terms_removed"] == 1
            assert (await c.get("/audit/nope")).status_code == 404

    asyncio.run(go())


def test_masker_tool_arguments_and_placeholders():
    m = common.Masker(FakeDetector())
    mapping, dets = {}, []
    msgs = [
        {"role": "user", "content": [{"type": "text", "text": "a secret and a secret"}]},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [{"function": {"name": "f", "arguments": '{"x": "\\u0073ecret"}'}}],
        },
    ]
    out = m.mask_messages(msgs, mapping, dets)
    assert out[0]["content"][0]["text"] == "a <SECRET_1> and a <SECRET_1>"
    assert json.loads(out[1]["tool_calls"][0]["function"]["arguments"]) == {"x": "<SECRET_1>"}
    assert len(dets) == 3 and dets[0]["text_sha256"] == common.sha256("secret")
    assert msgs[0]["content"][0]["text"] == "a secret and a secret"  # input untouched


def test_language_segments_route_lines_and_keep_offsets():
    text = "에러가 나요\nDATABASE_URL=postgres://u:p@db/x\n\n김서윤 님께\n"
    segs = common.language_segments(text)
    assert [lang for _, _, lang in segs] == ["ko", "en", "ko"]
    for offset, seg, _ in segs:
        assert text[offset : offset + len(seg)] == seg
    assert "".join(seg for _, seg, _ in segs) == text


def test_overlaps_longest_wins():
    spans = [common.Span(0, 5, "A", "x"), common.Span(2, 9, "B", "x"), common.Span(9, 12, "C", "x")]
    assert [s.type for s in common.resolve_overlaps(spans)] == ["B", "C"]


def test_gliner_windows_cover_text_with_exact_offsets():
    text = " ".join(f"w{i}" for i in range(300))
    wins = list(gliner_pii.windows(text, max_words=50, max_chars=10_000))
    assert wins[0][0] == 0 and wins[-1][0] + len(wins[-1][1]) == len(text)
    for offset, chunk in wins:
        assert text[offset : offset + len(chunk)] == chunk
        assert len(chunk.split()) <= 50
    long_token = "x" * 2000
    assert list(gliner_pii.windows(long_token)) == [(0, long_token)]
    assert sum(len(g) for g in gliner_pii.LABEL_GROUPS) == 50
    assert all(len(g) <= 25 for g in gliner_pii.LABEL_GROUPS)


def test_presidio_detector_if_installed():
    pytest.importorskip("presidio_analyzer")
    spacy = pytest.importorskip("spacy")
    import presidio_ko

    try:
        spacy.load("ko_core_news_sm")
        spacy.load("en_core_web_sm")
    except OSError:
        pytest.skip("spaCy models not installed")
    det = presidio_ko.PresidioDetector("ko_core_news_sm", "en_core_web_sm")
    found = det.detect("minsu@example.com 로 연락 주세요", "ko")
    assert any(s.type == "EMAIL_ADDRESS" for s in found)


# --- 409 review handling in the harness -----------------------------------------------------


def review_app():
    """Airlock's review contract: 409 with review_id and proposed spans, then POST /review/{id}."""
    app = FastAPI()
    sent = {"messages": [{"role": "user", "content": "Avery Stone"}]}
    audit = {
        "req_held": {"request_id": "req_held", "outbound": [], "gate": {"decision": "review"}},
        "req_ok": {
            "request_id": "req_ok",
            "outbound": [{"destination": "upstream", "payload": sent}],
            "gate": {"decision": "allow", "reasons": []},
        },
    }
    calls = []

    @app.post("/v1/chat/completions")
    async def chat():
        err = {
            "type": "airlock_review_required",
            "review_id": "rev_1",
            "reasons": ["low_confidence"],
            "proposed": [{"span_id": "s1", "text": "Avery", "type": "PERSON"}],
            "request_id": "req_held",
        }
        return JSONResponse(
            {"error": err}, status_code=409, headers={"x-airlock-request-id": "req_held"}
        )

    @app.post("/review/{rid}")
    async def review(rid: str, request: Request):
        calls.append((rid, await request.json()))
        body = {"choices": [{"message": {"content": "ok"}}]}
        return JSONResponse(body, headers={"x-airlock-request-id": "req_ok"})

    @app.get("/audit/{rid}")
    async def get_audit(rid: str):
        if rid in audit:
            return audit[rid]
        return JSONResponse({"error": {"type": "not_found"}}, status_code=404)

    app.state.calls = calls
    return app


def _review_case():
    return {
        "id": "t-1",
        "category": "direct_pii",
        "lang": "en",
        "task": "chat",
        "messages": [{"role": "user", "content": "Avery Stone"}],
        "must_not_leak": ["Avery Stone"],
    }


async def _one(app, **kw):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://a") as client:
        return await run.execute_case(client, _review_case(), opts(**kw))


def test_review_required_counts_as_block_by_default():
    app = review_app()
    rec = asyncio.run(_one(app))
    assert rec["status"] == "blocked" and rec["audit"]["outbound"] == []
    assert rec["request_id"] == "req_held" and rec["block_reasons"] == [
        "review_required:low_confidence"
    ]
    assert app.state.calls == []
    s = score_case(_review_case(), rec)
    assert s["blocked"] and not s["leaked"]


def test_review_auto_approve_scores_what_was_sent():
    app = review_app()
    rec = asyncio.run(_one(app, auto_approve_review=True))
    assert app.state.calls == [("rev_1", {"approve": ["s1"], "reject": [], "add": []})]
    assert rec["status"] == "ok" and rec["request_id"] == "req_ok"
    assert score_case(_review_case(), rec)["leaked"]
