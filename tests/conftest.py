"""Offline test harness: the local model, Token Factory and Tavily are all mocked."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from airlock.config import ProtectionLevel, Settings
from airlock.server import create_app

LOCAL = "http://local.test/v1"
UPSTREAM = "http://upstream.test/v1"
TAVILY = "http://tavily.test"
TEST_HASH_KEY = "test-audit-hash-key"


def make_settings(**overrides: Any) -> Settings:
    base = Settings(
        local_base_url=LOCAL,
        upstream_base_url=UPSTREAM,
        tavily_base_url=TAVILY,
        nebius_api_key="test-nebius-key",
        tavily_api_key="test-tavily-key",
        vault_path=":memory:",
        audit_db=":memory:",
        protection_level=ProtectionLevel.BALANCED,
        allowed_hosts=("testserver", "127.0.0.1", "localhost"),
        audit_hash_key=TEST_HASH_KEY,
    )
    return base.with_overrides(**overrides)


def completion(
    content: str | None, tool_calls: list[dict] | None = None, finish_reason: str = "stop"
) -> dict[str, Any]:
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1,
        "model": "nvidia/nemotron-3-ultra",
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
    }


@dataclass
class Harness:
    # text -> (type, action, replacement) returned by the fake local detector
    entities: dict[str, tuple[str, str, str]] = field(default_factory=dict)
    local_down: bool = False
    local_garbage: bool = False
    local_timeout: bool = False
    # Raw detector output override, and the finish_reason the fake local server reports.
    local_content: Callable[[str], str] | None = None
    local_finish: str = "stop"
    # Spans returned whether or not they occur in the draft (simulated hallucinations).
    extra_spans: list[dict[str, str]] = field(default_factory=list)
    rewrite: Callable[[str, str | None], str] = lambda q, c: "generic query"
    upstream_reply: Callable[[dict[str, Any]], dict[str, Any]] = lambda p: completion("ok")
    tavily_results: list[dict[str, Any]] = field(
        default_factory=lambda: [
            {"title": "Result A", "url": "https://a.example", "content": "alpha", "score": 0.9},
            {"title": "Result B", "url": "https://b.example", "content": "beta", "score": 0.8},
        ]
    )
    upstream_requests: list[dict[str, Any]] = field(default_factory=list)
    upstream_raw: list[bytes] = field(default_factory=list)
    tavily_requests: list[dict[str, Any]] = field(default_factory=list)
    local_requests: list[dict[str, Any]] = field(default_factory=list)

    # ---- fake servers -------------------------------------------------------
    def _local(self, request: httpx.Request) -> httpx.Response:
        if self.local_down:
            raise httpx.ConnectError("connection refused", request=request)
        if self.local_timeout:
            raise httpx.ReadTimeout("timed out", request=request)
        body = json.loads(request.content)
        self.local_requests.append(body)
        system = body["messages"][0]["content"]
        user = body["messages"][1]["content"]
        if self.local_garbage:
            content = "I cannot help with that."
        elif "privacy gate of Airlock" in system:
            if self.local_content is not None:
                content = self.local_content(user)
            else:
                spans = [
                    {"text": t, "type": typ, "action": act, "replacement": rep}
                    for t, (typ, act, rep) in self.entities.items()
                    if t in user
                ]
                content = json.dumps({"spans": spans + self.extra_spans}, ensure_ascii=False)
            return httpx.Response(200, json=completion(content, finish_reason=self.local_finish))
        elif "search rewriter" in system:
            data = json.loads(user)
            content = json.dumps({"query": self.rewrite(data["query"], data["private_context"])})
        elif "result ranker" in system:
            n = len(json.loads(user)["results"])
            content = json.dumps({"order": list(reversed(range(n)))})
        else:
            return httpx.Response(400, json={"error": "unknown prompt"})
        return httpx.Response(200, json=completion(content))

    def _upstream(self, request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer test-nebius-key"
        self.upstream_raw.append(request.content)
        payload = json.loads(request.content)
        self.upstream_requests.append(payload)
        return httpx.Response(200, json=self.upstream_reply(payload))

    def _tavily(self, request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        self.tavily_requests.append(payload)
        return httpx.Response(
            200,
            json={
                "query": payload["query"],
                "answer": "tavily answer",
                "results": self.tavily_results,
            },
        )

    def handler(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host == "local.test":
            return self._local(request)
        if host == "upstream.test":
            return self._upstream(request)
        if host == "tavily.test":
            return self._tavily(request)
        raise AssertionError(f"unexpected network call to {request.url}")


@pytest.fixture
def harness() -> Harness:
    return Harness()


@pytest.fixture
def make_client(harness: Harness):
    clients: list[TestClient] = []

    def factory(**overrides: Any) -> TestClient:
        app = create_app(make_settings(**overrides), transport=httpx.MockTransport(harness.handler))
        client = TestClient(app)
        client.__enter__()
        clients.append(client)
        return client

    yield factory
    for c in clients:
        c.__exit__(None, None, None)


@pytest.fixture
def client(make_client) -> TestClient:
    return make_client()
