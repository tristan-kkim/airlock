"""Demo mode (AIRLOCK_DEMO=1): guards, recorded fallbacks, host allowlist, session isolation."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from airlock.agent_settings import AgentSettings
from airlock.config import load_settings
from airlock.demo.app import BANNER_TEXT, create_demo_app
from airlock.demo.config import (
    DEFAULT_CLOUD_DETECTOR_MODEL,
    DemoConfigError,
    DemoSettings,
    load_demo_settings,
    resolve_allowed_hosts,
)
from airlock.demo.guards import DailyBudget, SlidingWindowLimiter, client_ip, input_chars
from airlock.demo.presets import PRESETS, PRESETS_BY_ID, load_recorded
from airlock.demo.sessions import COOKIE_NAME, SessionSigner, SessionStore
from airlock.server import create_app
from tests.conftest import Harness, make_settings

JANE = "Hi, I'm Jane Park (jane.park@example.com). Draft a note to my manager."


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def demo_client(harness: Harness, clock: Clock):
    clients: list[TestClient] = []
    day = {"value": "2026-11-02"}

    def factory(settings_overrides: dict | None = None, **demo_overrides: Any) -> TestClient:
        harness.entities.setdefault("Jane Park", ("PERSON", "mask", ""))
        demo = DemoSettings(enabled=True, detector_backend="local").with_overrides(**demo_overrides)
        app = create_demo_app(
            make_settings(**(settings_overrides or {})),
            demo,
            transport=httpx.MockTransport(harness.handler),
            agent_settings=AgentSettings(),
            clock=clock,
            today=lambda: day["value"],
        )
        client = TestClient(app)
        client.__enter__()
        client.day = day  # type: ignore[attr-defined]
        clients.append(client)
        return client

    yield factory
    for c in clients:
        c.__exit__(None, None, None)


def chat(client: TestClient, text: str = JANE, **extra: Any) -> httpx.Response:
    body = {"model": "airlock", "messages": [{"role": "user", "content": text}], **extra}
    return client.post("/v1/chat/completions", json=body)


def gateway(client: TestClient):
    return client.app.gateway  # type: ignore[attr-defined]


def fake_recording(preset_id: str) -> dict[str, Any]:
    preset = PRESETS_BY_ID[preset_id]
    return {
        "preset_id": preset.id,
        "title": preset.title,
        "mode": preset.mode,
        "source": "recorded",
        "recorded_at": "2026-09-14T00:00:00Z",
        "typed": [{"label": "user", "text": preset.message}],
        "cloud_saw": [{"destination": "upstream", "label": "user", "text": "<PERSON_1> ..."}],
        "answer": "recorded answer",
    }


# ---------------------------------------------------------------- banner and headers
def test_banner_quickstart_link_and_security_headers(demo_client):
    client = demo_client()
    r = client.get("/")
    assert r.status_code == 200
    assert BANNER_TEXT in r.text
    assert "https://github.com/tristan-kkim/airlock#quickstart" in r.text
    assert 'id="demo-scenarios"' in r.text
    assert "llama.cpp sidecar" in r.text  # detector backend is labeled (local backend here)
    csp = r.headers["content-security-policy"]
    assert "script-src 'sha256-" in csp and "unsafe-inline" not in csp
    assert "frame-ancestors 'none'" in csp
    for name, value in {
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "no-referrer",
        "cache-control": "no-store",
    }.items():
        assert r.headers[name] == value
    cookie = r.headers["set-cookie"]
    assert (
        cookie.startswith(f"{COOKIE_NAME}=") and "HttpOnly" in cookie and "SameSite=Lax" in cookie
    )
    # API responses carry the headers too.
    assert client.get("/demo/status").headers["x-frame-options"] == "DENY"


def test_cloud_backend_is_labeled_in_banner(demo_client):
    client = demo_client(detector_backend="cloud")
    assert f"Token Factory {DEFAULT_CLOUD_DETECTOR_MODEL}" in client.get("/").text


def test_local_mode_has_no_banner(client):
    r = client.get("/")
    assert r.status_code == 200
    assert BANNER_TEXT not in r.text and "demo-scenarios" not in r.text


def test_only_allowlisted_routes_are_reachable(demo_client):
    client = demo_client()
    for path in ("/docs", "/openapi.json", "/redoc"):
        assert client.get(path).status_code == 404
    assert client.get("/healthz").json()["demo"] is True
    assert client.get("/readyz").status_code == 200


# ---------------------------------------------------------------- rate limits
def test_session_rate_limit_then_window_resets(demo_client, clock, harness):
    client = demo_client(session_limit=3, ip_limit=100)
    for _ in range(3):
        assert chat(client).status_code == 200
    r = chat(client)
    assert r.status_code == 429
    assert r.json()["error"]["type"] == "demo_rate_limited"
    assert int(r.headers["retry-after"]) > 0
    assert len(harness.upstream_requests) == 3  # the limited request never left
    clock.t += 601
    assert chat(client).status_code == 200


def test_ip_rate_limit_spans_sessions(demo_client):
    client = demo_client(session_limit=100, ip_limit=2)
    assert chat(client).status_code == 200
    client.cookies.clear()  # a fresh session from the same IP
    assert chat(client).status_code == 200
    client.cookies.clear()
    assert chat(client).json()["error"]["type"] == "demo_rate_limited"


def test_rate_limited_preset_serves_recorded_run(demo_client):
    client = demo_client(session_limit=1)
    gateway(client).recorded = {"chat-medical-en": fake_recording("chat-medical-en")}
    assert chat(client).status_code == 200
    r = client.post("/demo/presets/chat-medical-en/run", json={})
    assert r.status_code == 200
    assert r.json()["source"] == "recorded" and r.json()["fallback_reason"] == "rate_limited"


def test_client_ip_trusts_only_configured_proxy_hops():
    scope = {"client": ("10.0.0.9", 1), "headers": [(b"x-forwarded-for", b"6.6.6.6, 1.2.3.4")]}
    assert client_ip(scope, 0) == "10.0.0.9"  # header ignored without a trusted proxy
    assert client_ip(scope, 1) == "1.2.3.4"  # the entry the proxy appended, not the spoofable one
    assert client_ip(scope, 2) == "6.6.6.6"
    fly = {**scope, "headers": [*scope["headers"], (b"fly-client-ip", b"9.9.9.9")]}
    assert client_ip(fly, 1, "Fly-Client-IP") == "9.9.9.9"
    assert client_ip(scope, 0, "fly-client-ip") == "10.0.0.9"  # header absent: socket peer


def test_sliding_window_limiter_unit(clock):
    limiter = SlidingWindowLimiter(2, 10, clock=clock)
    limiter.hit("a")
    limiter.hit("a")
    assert limiter.check("a") == pytest.approx(10)
    assert limiter.check("b") == 0
    clock.t += 10
    assert limiter.check("a") == 0 and limiter.remaining("a") == 2


# ---------------------------------------------------------------- budget
def test_budget_exhaustion_blocks_free_text_and_presets_fall_back(demo_client, harness):
    client = demo_client(daily_requests=2)
    gateway(client).recorded = {"chat-rent-ko": fake_recording("chat-rent-ko")}
    assert chat(client).status_code == 200
    assert chat(client).status_code == 200
    r = chat(client)
    assert r.status_code == 429
    error = r.json()["error"]
    assert error["type"] == "demo_budget_reached" and error["page"] == "/demo/budget"
    assert len(harness.upstream_requests) == 2

    preset = client.post("/demo/presets/chat-rent-ko/run", json={}).json()
    assert preset["source"] == "recorded"
    assert preset["fallback_reason"] == "budget_exhausted"
    assert preset["answer"] == "recorded answer"
    assert len(harness.upstream_requests) == 2  # the recorded run cost nothing

    # A preset without a recording gets a clear error instead.
    assert client.post("/demo/presets/chat-medical-en/run", json={}).status_code == 429
    status = client.get("/demo/status").json()
    assert status["budget"]["exhausted"] is True
    page = client.get("/demo/budget")
    assert "budget for today is used up" in page.text and "recorded run" in page.text

    client.day["value"] = "2026-11-03"  # type: ignore[attr-defined]
    assert chat(client).status_code == 200


def test_cloud_call_budget_counts_paid_hosts(demo_client, harness):
    client = demo_client(daily_cloud_calls=1)
    assert chat(client).status_code == 200  # local detector is free; one upstream call
    assert gateway(client).budget.cloud_calls == 1
    assert chat(client).json()["error"]["type"] == "demo_budget_reached"


def test_out_of_credit_exhausts_budget(demo_client, harness):
    client = demo_client()
    original = harness.handler

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "upstream.test":
            return httpx.Response(402, json={"detail": "insufficient balance"})
        return original(request)

    gateway(client).transport.inner = httpx.MockTransport(handler)
    assert chat(client).status_code == 502
    assert gateway(client).budget.status()["out_of_credit"] is True
    assert chat(client).json()["error"]["type"] == "demo_budget_reached"


def test_daily_budget_unit():
    day = {"v": "d1"}
    budget = DailyBudget(1, 0, today=lambda: day["v"])
    assert not budget.exhausted
    budget.spend_request()
    assert budget.exhausted
    day["v"] = "d2"
    assert not budget.exhausted and budget.requests == 0


def test_live_preset_run_shows_three_views(demo_client, harness):
    client = demo_client()
    harness.entities["jane.park@example.com"] = ("CONTACT", "mask", "")
    r = client.post("/demo/presets/chat-medical-en/run", json={})
    assert r.status_code == 200
    data = r.json()
    assert data["source"] == "live" and data["fallback_reason"] is None
    assert "Jane Park" in data["typed"][0]["text"]
    cloud = json.dumps(data["cloud_saw"], ensure_ascii=False)
    assert "Jane Park" not in cloud and "<PERSON_1>" in cloud
    assert data["answer"] == "ok"
    assert data["gate"]["decision"] == "allow"
    assert {"type": "PERSON", "action": "mask"}.items() <= data["detections"][0].items()


def test_failed_live_preset_serves_recorded_run(demo_client, harness):
    client = demo_client()
    gateway(client).recorded = {"chat-medical-en": fake_recording("chat-medical-en")}
    harness.local_down = False

    def boom(request: httpx.Request) -> httpx.Response:
        if request.url.host == "upstream.test":
            return httpx.Response(500, json={"detail": "down"})
        return harness.handler(request)

    gateway(client).transport.inner = httpx.MockTransport(boom)
    data = client.post("/demo/presets/chat-medical-en/run", json={}).json()
    assert data["source"] == "recorded" and data["fallback_reason"] == "live_error"


def test_recorded_mode_never_calls_out(demo_client, harness):
    client = demo_client(presets="recorded")
    gateway(client).recorded = {"chat-medical-en": fake_recording("chat-medical-en")}
    data = client.post("/demo/presets/chat-medical-en/run", json={}).json()
    assert data["fallback_reason"] == "recorded_mode"
    assert harness.upstream_requests == [] and harness.local_requests == []


def test_every_preset_has_a_shipped_recording():
    recorded = load_recorded()
    assert set(recorded) == {p.id for p in PRESETS}
    for data in recorded.values():
        assert data["source"] == "recorded" and data["recorded_at"]
        assert data["typed"] and data["cloud_saw"]


def test_presets_cover_modes_and_languages():
    assert 4 <= len(PRESETS) <= 6
    assert {p.mode for p in PRESETS} == {"chat", "search", "agent"}
    assert {p.lang for p in PRESETS} == {"en", "ko"}


# ---------------------------------------------------------------- host allowlist
def test_allowed_hosts_local_mode_keeps_loopback_only():
    env = {"AIRLOCK_ALLOWED_HOSTS": "demo.example.com,*,localhost"}
    assert resolve_allowed_hosts(env) == ("localhost",)
    assert resolve_allowed_hosts({"AIRLOCK_ALLOWED_HOSTS": "demo.example.com"}) == (
        "127.0.0.1",
        "localhost",
        "::1",
    )
    assert resolve_allowed_hosts({}) == ("127.0.0.1", "localhost", "::1")


def test_allowed_hosts_demo_mode_honors_public_host():
    env = {"AIRLOCK_DEMO": "1", "AIRLOCK_ALLOWED_HOSTS": "demo.example.com"}
    assert resolve_allowed_hosts(env) == ("demo.example.com",)


def test_local_server_rejects_public_host_even_if_listed(monkeypatch, harness):
    monkeypatch.delenv("AIRLOCK_DEMO", raising=False)
    monkeypatch.setenv("AIRLOCK_ALLOWED_HOSTS", "demo.example.com")
    settings = load_settings(env_file=None)
    assert settings.allowed_hosts == ("127.0.0.1", "localhost", "::1")
    app = create_app(
        settings.with_overrides(vault_path=":memory:", audit_db=":memory:", audit_hash_key="k"),
        transport=httpx.MockTransport(harness.handler),
    )
    with TestClient(app, base_url="http://demo.example.com") as c:
        assert c.get("/healthz").status_code == 400
    with TestClient(app, base_url="http://127.0.0.1") as c:
        assert c.get("/healthz").status_code == 200


def test_demo_server_accepts_public_host_and_rejects_others(demo_client):
    client = demo_client({"allowed_hosts": ("demo.example.com",)})
    client.base_url = httpx.URL("http://demo.example.com")
    assert client.get("/").status_code == 200
    client.base_url = httpx.URL("http://evil.example.net")
    assert client.get("/").status_code == 400
    assert client.get("/demo/status").status_code == 400
    assert client.get("/healthz").status_code == 200  # probes skip the Host check


def test_cloud_backend_requires_demo_mode():
    with pytest.raises(DemoConfigError):
        load_demo_settings({"AIRLOCK_DETECTOR_BACKEND": "cloud"})
    demo = load_demo_settings({"AIRLOCK_DETECTOR_BACKEND": "cloud", "AIRLOCK_DEMO": "1"})
    assert (
        demo.detector_backend == "cloud"
        and demo.cloud_detector_model == DEFAULT_CLOUD_DETECTOR_MODEL
    )


def test_cloud_backend_sends_detection_to_token_factory(harness, clock):
    """The adapter reuses LocalModel: the same JSON-schema request, sent to Token Factory."""
    seen: list[dict[str, Any]] = []
    harness.entities["Jane Park"] = ("PERSON", "mask", "")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "upstream.test":
            body = json.loads(request.content)
            if body["model"] == DEFAULT_CLOUD_DETECTOR_MODEL:
                assert request.headers["authorization"] == "Bearer test-nebius-key"
                seen.append(body)
                return harness._local(request)
        if request.url.host == "local.test":
            raise AssertionError("cloud backend must not call the local server")
        return harness.handler(request)

    app = create_demo_app(
        make_settings(),
        DemoSettings(enabled=True, detector_backend="cloud"),
        transport=httpx.MockTransport(handler),
        agent_settings=AgentSettings(),
        clock=clock,
    )
    with TestClient(app) as client:
        assert chat(client).status_code == 200
        assert client.get("/healthz").json()["local_model"].startswith("Token Factory")
    assert seen and seen[0]["response_format"]["type"] == "json_schema"
    assert "Jane Park" not in json.dumps(harness.upstream_requests[-1]["messages"])
    assert gateway(client).budget.cloud_calls == 2  # detector + upstream both counted


def test_cloud_backend_fails_closed_without_key(harness, clock):
    app = create_demo_app(
        make_settings(nebius_api_key=None),
        DemoSettings(enabled=True, detector_backend="cloud"),
        transport=httpx.MockTransport(harness.handler),
        agent_settings=AgentSettings(),
        clock=clock,
    )
    with TestClient(app) as client:
        r = chat(client)
        assert r.status_code == 422
        assert r.json()["error"]["reasons"] == [
            "local_detector_unavailable:CloudDetectorNotConfigured"
        ]
        assert client.get("/readyz").json()["live_configured"] is False


# ---------------------------------------------------------------- input caps
def test_input_char_cap_rejects_before_detection(demo_client, harness):
    client = demo_client(max_input_chars=50)
    r = chat(client, "x" * 60)
    assert r.status_code == 413
    assert r.json()["error"]["type"] == "demo_input_too_large"
    assert harness.local_requests == [] and harness.upstream_requests == []
    assert gateway(client).budget.requests == 0  # a rejected input does not spend the budget


def test_body_byte_cap(demo_client, harness):
    client = demo_client(max_body_bytes=300, max_input_chars=10_000)
    r = client.post(
        "/v1/search",
        content=json.dumps({"query": "y" * 400}),
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 413
    assert harness.tavily_requests == []


def test_output_tokens_and_agent_steps_are_clamped(demo_client, harness):
    client = demo_client(max_tokens=200)
    assert chat(client, max_tokens=5000, n=3).status_code == 200
    sent = harness.upstream_requests[-1]
    assert sent["max_tokens"] == 200 and sent["n"] == 1
    assert chat(client).status_code == 200
    assert harness.upstream_requests[-1]["max_tokens"] == 200  # a default cap when omitted


def test_input_chars_unit():
    assert input_chars({"a": "abc", "b": [{"c": "de"}, 5, None]}) == 5


def test_post_requires_json_content_type(demo_client):
    client = demo_client()
    r = client.post(
        "/demo/presets/chat-medical-en/run", content=b"x", headers={"content-type": "text/plain"}
    )
    assert r.status_code == 415


# ---------------------------------------------------------------- session isolation
def test_vault_and_audit_are_isolated_per_session(demo_client, harness):
    alice = demo_client()
    assert alice.post("/vault/terms", json={"terms": ["Project Nightjar"]}).json()["total"] == 1
    r = chat(alice, "Tell Jane Park about Project Nightjar.")
    assert r.status_code == 200
    alice_id = r.headers["x-airlock-request-id"]
    assert len(alice.get("/audit").json()["records"]) == 1

    bob = TestClient(alice.app)  # same server, no cookie: a new session
    bob.__enter__()
    try:
        assert bob.get("/audit").json()["records"] == []
        assert bob.get(f"/audit/{alice_id}").status_code == 404
        assert bob.post("/vault/terms", json={"terms": ["Other"]}).json()["total"] == 1
        # Bob's session does not know Alice's declared term, so it is not enforced for him.
        chat(bob, "Project Nightjar status?")
        assert "Project Nightjar" in json.dumps(harness.upstream_requests[-1])
        assert len(gateway(alice).sessions) == 2
    finally:
        bob.__exit__(None, None, None)
    assert "Project Nightjar" not in json.dumps(harness.upstream_requests[0])


def test_forged_session_cookie_is_replaced(demo_client):
    client = demo_client()
    client.cookies.set(COOKIE_NAME, "attacker-chosen.id")
    r = client.get("/demo/status")
    assert r.headers["set-cookie"].split(";")[0] != f"{COOKIE_NAME}=attacker-chosen.id"


def test_session_signer_unit():
    signer = SessionSigner()
    sid = signer.mint()
    assert signer.verify(sid) == sid
    assert signer.verify(sid[:-1] + ("A" if sid[-1] != "A" else "B")) is None
    assert SessionSigner().verify(sid) is None  # a restart invalidates ids
    assert signer.verify(None) is None and signer.verify("no-dot") is None


def test_sessions_expire_after_ttl_and_close(clock):
    asyncio.run(_sessions_expire(clock))


async def _sessions_expire(clock):
    closed: list[str] = []

    class FakeServices:
        async def aclose(self) -> None:
            closed.append("x")

    class FakeApp:
        def __init__(self) -> None:
            self.state = type("S", (), {"services": FakeServices()})()

    store = SessionStore(FakeApp, ttl_s=60, max_sessions=2, clock=clock)  # type: ignore[arg-type]
    await store.get("a")
    clock.t += 30
    await store.get("b")
    clock.t += 31
    assert await store.expire() == 1 and store.peek("a") is None and store.peek("b") is not None
    await store.get("c")
    await store.get("d")  # over capacity: the oldest idle session goes
    assert len(store) == 2 and store.peek("b") is None
    assert len(closed) == 2


def test_detector_failure_in_live_preset_serves_recorded_run(demo_client, harness):
    client = demo_client()
    gateway(client).recorded = {"chat-medical-en": fake_recording("chat-medical-en")}
    harness.local_timeout = True
    # Free text still fails closed and says so.
    assert chat(client).json()["error"]["reasons"] == ["local_detector_malformed:timeout"]
    data = client.post("/demo/presets/chat-medical-en/run", json={}).json()
    assert data["source"] == "recorded" and data["fallback_reason"] == "live_error"
    assert harness.upstream_requests == []
