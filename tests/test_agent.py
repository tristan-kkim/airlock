"""Agent mode: egress hops, search-intent guard, step cap, SSE, unguarded flag. All offline."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from airlock.agent import SEARCH_BLOCKED_NOTE, STEP_LIMIT_NOTE, UnguardedNotAllowed, make_docs
from airlock.agent_settings import AgentSettings, load_agent_settings
from airlock.audit import AuditRecord, scrub
from airlock.server import create_app
from tests.conftest import completion, make_settings

NAME = "Daniel Okafor"
ORG = "Brightwater Logistics"
PHONE = "010-2345-6789"
DOC = (
    f"# Notice of position elimination\n\nDear {NAME},\n\nYour role at {ORG} ends on 15 October. "
    f"Call HR at {PHONE}. Severance: six weeks of pay."
)
QUESTION = "I got a layoff notice. Should I sign the separation agreement?"
SAFETY = "http://safety.test/v1"


def call(name: str, args: dict[str, Any], idx: int = 1) -> dict[str, Any]:
    return {
        "id": f"call_{name}_{idx}",
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(args)},
    }


def script(*steps: Callable[[dict[str, Any]], dict[str, Any]] | dict[str, Any]):
    """Upstream replies in order; the last one repeats."""
    state = {"i": 0}

    def reply(payload: dict[str, Any]) -> dict[str, Any]:
        step = steps[min(state["i"], len(steps) - 1)]
        state["i"] += 1
        return step(payload) if callable(step) else step

    return reply


def tool_reply(*calls: dict[str, Any]) -> dict[str, Any]:
    return completion(None, tool_calls=list(calls), finish_reason="tool_calls")


STANDARD = (
    tool_reply(call("list_local_docs", {})),
    tool_reply(call("read_local_doc", {"doc_id": "doc-1"})),
    tool_reply(call("web_search", {"query": "<ORG_1> layoff <PERSON_1> severance how to respond"})),
    tool_reply(call("finish", {"answer": "Talk to <PERSON_1>'s lawyer before signing."})),
)


class AgentHarness:
    """Wraps the shared harness: fake search rewriter, intent judge and safety model."""

    def __init__(self, harness):
        self.h = harness
        self.rewrites: list[Callable[[dict[str, Any]], str]] = [
            lambda d: "employee severance rights"
        ]
        self.judge: Callable[[str], str] = lambda q: "no"
        self.safety: Callable[[str], httpx.Response] = lambda q: _safety("safe")
        self.rewrite_inputs: list[dict[str, Any]] = []
        self.judge_inputs: list[str] = []
        self.safety_requests: list[dict[str, Any]] = []
        self._original = harness.handler
        harness.entities = {NAME: ("PERSON", "mask", ""), ORG: ("ORG", "mask", "")}
        harness.handler = self.handler

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == "safety.test":
            body = json.loads(request.content)
            self.safety_requests.append(body)
            return self.safety(body["messages"][0]["content"])
        if request.url.host == "local.test":
            body = json.loads(request.content)
            system = body["messages"][0]["content"]
            user = body["messages"][1]["content"]
            if "search firewall" in system:
                data = json.loads(user)
                self.rewrite_inputs.append(data)
                fn = self.rewrites[min(len(self.rewrite_inputs) - 1, len(self.rewrites) - 1)]
                content = json.dumps({"query": fn(data)})
                self.h.local_requests.append(body)
                return httpx.Response(200, json=completion(content))
            if "privacy judge inside Airlock" in system:
                query = user.removeprefix("<input>\n").removesuffix("\n</input>")
                self.judge_inputs.append(query)
                self.h.local_requests.append(body)
                content = json.dumps({"violates_policy": self.judge(query)})
                return httpx.Response(200, json=completion(content))
        return self._original(request)


def _safety(verdict: str, categories: str = "") -> httpx.Response:
    text = f"User Safety: {verdict}"
    if categories:
        text += f"\nSafety Categories: {categories}"
    return httpx.Response(200, json=completion(text))


@pytest.fixture
def agent(harness):
    return AgentHarness(harness)


@pytest.fixture
def make_agent_client(agent):
    clients: list[TestClient] = []

    def factory(agent_settings: AgentSettings | None = None, **overrides: Any) -> TestClient:
        app = create_app(
            make_settings(**overrides),
            transport=httpx.MockTransport(agent.h.handler),
            agent_settings=agent_settings or AgentSettings(safety_base_url=SAFETY),
        )
        client = TestClient(app)
        client.__enter__()
        clients.append(client)
        return client

    yield factory
    for c in clients:
        c.__exit__(None, None, None)


def run_events(client, question=QUESTION, docs=None, **kwargs) -> list[dict[str, Any]]:
    runner = client.app.state.agent_runner
    docs = make_docs([("notice.md", DOC)] if docs is None else docs)

    async def go():
        return [e async for e in runner.events(question, docs, **kwargs)]

    return client.portal.call(go)


def final_of(events):
    return next(e for e in events if e["type"] == "final")


def audit_of(events):
    return events[-1]["audit"]


# ---------------------------------------------------------------------------------------------


def test_every_hop_is_audited(make_agent_client, agent) -> None:
    agent.h.upstream_reply = script(*STANDARD)
    client = make_agent_client()
    events = run_events(client)
    final = final_of(events)
    assert final["status"] == "finished"
    assert final["answer"] == f"Talk to {NAME}'s lawyer before signing."

    audit = audit_of(events)
    assert audit["kind"] == "agent"
    hops = audit["hops"]
    assert [(h["destination"], h["kind"], h["decision"]) for h in hops] == [
        ("upstream", "prompt", "allow"),
        ("upstream", "tool_result", "allow"),
        ("upstream", "tool_result", "allow"),
        ("tavily", "search_query", "rewritten"),
        ("upstream", "tool_result", "allow"),
    ]
    assert [h["hop"] for h in hops] == [1, 2, 3, 4, 5]
    # The hop payloads are exactly what reached each remote party, and nothing else left.
    upstream_hops = [h["payload"] for h in hops if h["destination"] == "upstream"]
    assert upstream_hops == [json.loads(raw) for raw in agent.h.upstream_raw]
    assert [h["payload"] for h in hops if h["destination"] == "tavily"] == agent.h.tavily_requests
    assert [o["destination"] for o in audit["outbound"]] == [h["destination"] for h in hops]
    search = hops[3]["meta"]
    assert search["outbound_query"] == "employee severance rights"
    assert len(search["original_query_hmac"]) == 64
    assert search["judge"] == {"flagged": False, "model": "nemotron-3-nano-4b", "answer": "no"}
    assert audit["meta"]["searches"] == 1 and audit["meta"]["search_rewritten"] == 1
    # The stored record is the same one served by /audit.
    stored = client.get(f"/audit/{audit['request_id']}").json()
    assert stored["hops"] == hops


def test_raw_documents_never_reach_upstream_or_search_in_guarded_mode(
    make_agent_client, agent
) -> None:
    agent.h.upstream_reply = script(*STANDARD)
    client = make_agent_client()
    events = run_events(client)
    assert final_of(events)["status"] == "finished"

    wire = b"".join(agent.h.upstream_raw).decode()
    for original in (NAME, ORG, PHONE, DOC):
        assert original not in wire
    assert "Your role at <ORG_1> ends on 15 October" in wire  # the document did go, sanitized
    assert all(
        NAME not in json.dumps(t) and ORG not in json.dumps(t) for t in agent.h.tavily_requests
    )
    # The search rewriter saw the private query (locally) with placeholders restored.
    assert agent.rewrite_inputs[0]["query"] == f"{ORG} layoff {NAME} severance how to respond"
    assert DOC[:40] in agent.rewrite_inputs[0]["private_context"]

    audit = audit_of(events)
    blob = json.dumps({k: v for k, v in audit.items()}, ensure_ascii=False)
    for original in (NAME, ORG, PHONE):
        assert original not in blob


def test_search_guard_retries_after_judge_flag(make_agent_client, agent) -> None:
    agent.h.upstream_reply = script(*STANDARD)
    agent.rewrites = [
        lambda d: "Brightwater-style logistics layoff lawyer",
        lambda d: "severance law",
    ]
    agent.judge = lambda q: "yes" if "logistics" in q else "no"
    client = make_agent_client()
    events = run_events(client)
    hop = next(e for e in events if e["type"] == "hop" and e["destination"] == "tavily")
    assert hop["decision"] == "rewritten"
    assert hop["outbound_query"] == "severance law"
    assert [a["judge"]["flagged"] for a in hop["attempts"]] == [True, False]
    # The retry is told what was rejected.
    assert agent.rewrite_inputs[1]["rejected"] == ["Brightwater-style logistics layoff lawyer"]
    assert agent.h.tavily_requests == [
        {
            "query": "severance law",
            "max_results": 5,
            "search_depth": "basic",
            "include_answer": False,
        }
    ]
    stored = audit_of(events)["hops"][3]
    # A rejected candidate is stored only as a keyed hash.
    assert "logistics" not in json.dumps(stored["meta"])
    assert stored["meta"]["attempts"][0]["candidate_hmac"]


def test_search_guard_gate_rejects_candidate_with_original(make_agent_client, agent) -> None:
    agent.h.upstream_reply = script(*STANDARD)
    agent.rewrites = [lambda d: f"{ORG} severance policy", lambda d: "severance policy"]
    client = make_agent_client()
    events = run_events(client)
    hop = next(e for e in events if e["type"] == "hop" and e["destination"] == "tavily")
    assert hop["outbound_query"] == "severance policy"
    first = hop["attempts"][0]
    assert first["gate_reasons"] and first["gate_reasons"][0].startswith("vault_original:ORG:")
    assert first["judge"] is None  # the judge never sees a candidate the gate rejected
    assert agent.judge_inputs == ["severance policy"]


def test_search_blocked_after_retry_and_run_continues(make_agent_client, agent) -> None:
    seen: list[dict[str, Any]] = []

    def finish_after_block(payload):
        seen.append(payload)
        return tool_reply(call("finish", {"answer": "Answer without the search."}))

    agent.h.upstream_reply = script(*STANDARD[:3], finish_after_block)
    agent.rewrites = [lambda d: "layoff at a Portland logistics firm"]
    agent.judge = lambda q: "yes"
    client = make_agent_client()
    events = run_events(client)
    final = final_of(events)
    assert final["status"] == "finished" and final["search_blocked"] == 1
    assert agent.h.tavily_requests == []
    assert len(agent.rewrite_inputs) == 2  # one retry, then block
    tool_msg = seen[0]["messages"][-1]
    assert tool_msg["role"] == "tool" and tool_msg["content"] == SEARCH_BLOCKED_NOTE
    hop = audit_of(events)["hops"][3]
    assert hop["destination"] == "tavily" and hop["decision"] == "block"
    assert hop["reasons"] == ["search_intent_revealed"]
    assert "payload" not in hop and hop["meta"]["outbound_query"] is None


def test_judge_failure_fails_closed(make_agent_client, agent) -> None:
    agent.h.upstream_reply = script(*STANDARD)
    agent.judge = lambda q: "maybe"  # schema violation
    client = make_agent_client()
    events = run_events(client)
    hop = next(e for e in events if e["type"] == "hop" and e["destination"] == "tavily")
    assert hop["decision"] == "block"
    assert agent.h.tavily_requests == []


def test_safety_judge_custom_policy(make_agent_client, agent) -> None:
    agent.h.upstream_reply = script(*STANDARD)
    agent.rewrites = [lambda d: "severance for <ORG_1> staff", lambda d: "severance rights"]
    client = make_agent_client(AgentSettings(search_judge="safety", safety_base_url=SAFETY))
    # A placeholder is a gate failure, so make the safety model decide the second attempt.
    agent.safety = lambda q: _safety("safe")
    events = run_events(client)
    hop = next(e for e in events if e["type"] == "hop" and e["destination"] == "tavily")
    assert hop["outbound_query"] == "severance rights"
    assert hop["judge"]["model"] == "nemotron-3.5-content-safety"
    req = agent.safety_requests[0]
    kwargs = req["chat_template_kwargs"]
    assert kwargs["enable_thinking"] is False and kwargs["request_categories"] == "/categories"
    assert "Web Search Query Privacy Policy" in kwargs["custom_policy"]
    assert req["temperature"] == 0.01 and req["max_tokens"] == 100
    assert agent.judge_inputs == []  # nano judge not used in safety mode


@pytest.mark.parametrize(
    ("response", "flagged"),
    [
        (_safety("unsafe", "Naming a specific private company"), True),
        (_safety("safe"), False),
        (httpx.Response(200, json=completion("I think this is fine.")), True),
        (httpx.Response(500, json={}), True),
    ],
)
def test_safety_judge_parsing_fails_closed(make_agent_client, agent, response, flagged) -> None:
    client = make_agent_client(AgentSettings(search_judge="safety", safety_base_url=SAFETY))
    agent.safety = lambda q: response
    judge = client.app.state.agent_runner.guard.judge

    async def go():
        return await judge.judge("layoff list at <ORG_1>")

    verdict = client.portal.call(go)
    assert verdict.flagged is flagged
    assert agent.safety_requests[-1]["messages"][0]["content"] == "layoff list at [REDACTED]"


def test_both_judges_union(make_agent_client, agent) -> None:
    client = make_agent_client(AgentSettings(search_judge="both", safety_base_url=SAFETY))
    agent.judge = lambda q: "no"
    agent.safety = lambda q: _safety("unsafe")
    judge = client.app.state.agent_runner.guard.judge

    async def go():
        return await judge.judge("q")

    verdict = client.portal.call(go)
    assert verdict.flagged is True
    assert verdict.as_dict()["nano"]["flagged"] is False
    assert verdict.as_dict()["safety"]["flagged"] is True


def test_step_cap(make_agent_client, agent) -> None:
    agent.h.upstream_reply = script(tool_reply(call("list_local_docs", {})))
    client = make_agent_client(AgentSettings(max_steps=3, safety_base_url=SAFETY))
    events = run_events(client)
    final = final_of(events)
    assert final["status"] == "max_steps" and final["steps"] == 3
    assert len(agent.h.upstream_requests) == 3
    last = agent.h.upstream_requests[-1]
    assert [t["function"]["name"] for t in last["tools"]] == ["finish"]
    assert last["messages"][-1] == {"role": "user", "content": STEP_LIMIT_NOTE}
    assert events[-1]["type"] == "done"
    # A request cannot raise the configured cap.
    agent.h.upstream_requests.clear()
    events = run_events(client, max_steps=10)
    assert final_of(events)["steps"] == 3


def test_blocked_upstream_turn_stops_the_run(make_agent_client, agent) -> None:
    agent.h.upstream_reply = script(*STANDARD)
    client = make_agent_client(canaries=("CANARY-91ab",))
    events = run_events(client, docs=[("a.md", "internal note CANARY-91ab")])
    assert final_of(events)["status"] == "blocked"
    audit = audit_of(events)
    assert audit["hops"][-1]["decision"] == "block"
    assert audit["hops"][-1]["reasons"][0].startswith("canary:")
    assert all(b"CANARY-91ab" not in raw for raw in agent.h.upstream_raw)


def test_local_model_down_blocks_before_anything_leaves(make_agent_client, agent) -> None:
    agent.h.local_down = True
    client = make_agent_client()
    events = run_events(client)
    assert final_of(events)["status"] == "blocked"
    assert agent.h.upstream_requests == []
    hop = audit_of(events)["hops"][0]
    assert hop["decision"] == "block"
    assert hop["reasons"] == ["local_detector_unavailable:LocalModelUnavailable"]


def test_sse_event_shape(make_agent_client, agent) -> None:
    agent.h.upstream_reply = script(*STANDARD)
    client = make_agent_client()
    body = {"question": QUESTION, "docs": [{"name": "notice.md", "text": DOC}]}
    with client.stream("POST", "/v1/agent/run?stream=1", json=body) as r:
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/event-stream")
        raw = "".join(r.iter_text())
    events = []
    for block in raw.strip().split("\n\n"):
        lines = block.split("\n")
        assert lines[0].startswith("event: ") and lines[1].startswith("data: ")
        data = json.loads(lines[1][6:])
        assert data["type"] == lines[0][7:]
        events.append(data)
    types = [e["type"] for e in events]
    assert types[0] == "run_started" and types[-2:] == ["final", "done"]
    assert "audit" not in events[-1]
    hops = [e for e in events if e["type"] == "hop"]
    for e in hops:
        assert {"hop", "step", "destination", "kind", "decision", "reasons"} <= set(e)
    up = hops[0]
    assert up["destination"] == "upstream" and {"outbound", "local"} <= set(up)
    search = next(e for e in hops if e["destination"] == "tavily")
    assert {"local_query", "model_query", "outbound_query", "judge", "attempts"} <= set(search)
    assert search["model_query"] == "<ORG_1> layoff <PERSON_1> severance how to respond"
    assert events[-2]["answer"] == f"Talk to {NAME}'s lawyer before signing."
    assert client.get(f"/audit/{events[-1]['request_id']}").json()["kind"] == "agent"


def test_json_endpoint_is_always_guarded(make_agent_client, agent, monkeypatch) -> None:
    agent.h.upstream_reply = script(*STANDARD)
    client = make_agent_client(AgentSettings(allow_unguarded=True, safety_base_url=SAFETY))
    body = {"question": QUESTION, "docs": [{"name": "n.md", "text": DOC}], "guard": False}
    r = client.post("/v1/agent/run", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "finished"
    assert NAME not in b"".join(agent.h.upstream_raw).decode()


def test_unguarded_requires_explicit_opt_in(make_agent_client, agent) -> None:
    assert AgentSettings().allow_unguarded is False
    assert load_agent_settings({}).allow_unguarded is False
    assert load_agent_settings({"AIRLOCK_ALLOW_UNGUARDED": "1"}).allow_unguarded is True

    agent.h.upstream_reply = script(*STANDARD)
    client = make_agent_client()
    with pytest.raises(UnguardedNotAllowed):
        run_events(client, guard=False)
    assert agent.h.upstream_requests == []

    # Evaluation mode: raw documents and raw queries go out, and every hop is still audited.
    agent.h.upstream_reply = script(
        tool_reply(call("list_local_docs", {})),
        tool_reply(call("read_local_doc", {"doc_id": "doc-1"})),
        tool_reply(call("web_search", {"query": f"{ORG} layoff {NAME}"})),
        tool_reply(call("finish", {"answer": "done"})),
    )
    open_client = make_agent_client(AgentSettings(allow_unguarded=True, safety_base_url=SAFETY))
    events = run_events(open_client, guard=False)
    assert final_of(events)["status"] == "finished"
    assert DOC in [m.get("content") for m in agent.h.upstream_requests[-1]["messages"]]
    assert agent.h.tavily_requests[-1]["query"] == f"{ORG} layoff {NAME}"
    audit = audit_of(events)
    assert audit["meta"]["guard"] is False
    assert [h["destination"] for h in audit["hops"]].count("tavily") == 1
    assert all(h["meta"]["guard"] is False for h in audit["hops"])
    assert agent.rewrite_inputs == []  # no local rewriting in unguarded mode


def test_scrub_covers_hop_metadata_but_not_payloads() -> None:
    record = AuditRecord("agent")
    record.hops.append(
        {"hop": 1, "reasons": [f"x:{NAME}"], "meta": {"note": NAME}, "payload": {"q": NAME}}
    )
    data = scrub(record.to_dict(), [NAME])
    assert data["hops"][0]["reasons"] == ["x:[REDACTED]"]
    assert data["hops"][0]["meta"] == {"note": "[REDACTED]"}
    assert data["hops"][0]["payload"] == {"q": NAME}  # evidence stays verbatim


def test_search_guard_local_rewriter_down_blocks_only_the_search(make_agent_client, agent) -> None:
    seen = []

    def finish(payload):
        seen.append(payload)
        return tool_reply(call("finish", {"answer": "ok"}))

    agent.h.upstream_reply = script(*STANDARD[:3], finish)

    original = agent.handler

    def handler(request):
        if request.url.host == "local.test":
            system = json.loads(request.content)["messages"][0]["content"]
            if "search firewall" in system:
                return httpx.Response(503, json={})
        return original(request)

    agent.h.handler = handler
    client = make_agent_client()
    events = run_events(client)
    assert final_of(events)["status"] == "finished"
    hop = next(e for e in events if e["type"] == "hop" and e["destination"] == "tavily")
    assert hop["decision"] == "block"
    assert hop["reasons"] == ["local_rewriter_unavailable:LocalModelUnavailable"]
    assert agent.h.tavily_requests == []


def test_value_detected_in_one_document_is_masked_in_all_documents_of_the_turn(
    make_agent_client, agent
) -> None:
    """The detector finds the name only in the letter, not in the note read in the same turn."""
    agent.h.entities = {}
    agent.h.local_content = lambda user: json.dumps(
        {
            "spans": [
                {"text": "Zed Quillfeather", "type": "PERSON", "action": "mask", "replacement": ""}
            ]
        }  # fmt: skip
        if "Dear Zed Quillfeather" in user
        else {"spans": []}
    )
    agent.h.upstream_reply = script(
        tool_reply(
            call("read_local_doc", {"doc_id": "doc-1"}, 1),
            call("read_local_doc", {"doc_id": "doc-2"}, 2),
        ),
        tool_reply(call("finish", {"answer": "ok <PERSON_1>"})),
    )  # fmt: skip
    client = make_agent_client()
    docs = [
        ("a.md", "Dear Zed Quillfeather, your role ends."),
        ("b.md", "Zed Quillfeather signed."),
    ]
    events = run_events(client, docs=docs)
    assert final_of(events)["status"] == "finished"
    assert final_of(events)["answer"] == "ok Zed Quillfeather"
    wire = b"".join(agent.h.upstream_raw).decode()
    assert "Quillfeather" not in wire
    assert "<PERSON_1> signed." in wire


def test_truncated_finish_arguments_are_salvaged() -> None:
    from airlock.agent import salvage_answer

    assert salvage_answer('{"answer": "Line one\\nLine \\"two\\"') == 'Line one\nLine "two"'
    assert salvage_answer('{"answer": "complete"}') == "complete"
    assert salvage_answer("{}") == ""


def test_name_inside_a_longer_span_in_one_document_is_masked_alone_in_another(
    make_agent_client, agent
) -> None:
    """Overlap resolution keeps the longer quasi-identifier; the name still appears elsewhere."""
    agent.h.entities = {}
    phrase = "the only night nurse Mira Solberg"

    def detect(user: str) -> str:
        if phrase in user:
            spans = [
                {"text": phrase, "type": "QUASI_IDENTIFIER", "action": "mask", "replacement": ""},
                {"text": "Mira Solberg", "type": "PERSON", "action": "mask", "replacement": ""},
            ]
        else:
            spans = []
        return json.dumps({"spans": spans})

    agent.h.local_content = detect
    agent.h.upstream_reply = script(
        tool_reply(
            call("read_local_doc", {"doc_id": "doc-1"}, 1),
            call("read_local_doc", {"doc_id": "doc-2"}, 2),
        ),
        tool_reply(call("finish", {"answer": "ok"})),
    )
    client = make_agent_client()
    docs = [("a.md", f"Report: {phrase} was late."), ("b.md", "Signed, Mira Solberg.")]
    events = run_events(client, docs=docs)
    assert final_of(events)["status"] == "finished"
    wire = b"".join(agent.h.upstream_raw).decode()
    assert "Solberg" not in wire


def test_search_result_holding_an_undecodable_private_value_is_withheld(
    make_agent_client, agent
) -> None:
    """The gate decodes a percent-encoded URL the masker cannot see: drop that result only."""
    agent.h.tavily_results = [
        {
            "title": "Profile",
            "url": "https://people.example/Daniel%20Okafor",
            "content": "a public page",
            "score": 0.5,
        }
    ]
    seen = []

    def finish(payload):
        seen.append(payload)
        return tool_reply(call("finish", {"answer": "ok"}))

    agent.h.upstream_reply = script(*STANDARD[:3], finish)
    client = make_agent_client()
    events = run_events(client)
    final = final_of(events)
    assert final["status"] == "finished"
    assert final["results_withheld"] == 1
    assert seen[0]["messages"][-1]["content"].startswith("These web_search results were withheld")
    assert all("Okafor" not in raw.decode() for raw in agent.h.upstream_raw)


def test_document_holding_an_undecodable_private_value_still_blocks(
    make_agent_client, agent
) -> None:
    agent.h.upstream_reply = script(*STANDARD)
    client = make_agent_client()
    docs = [("notice.md", DOC), ("links.md", "See https://people.example/Daniel%20Okafor")]
    agent.h.upstream_reply = script(
        tool_reply(
            call("read_local_doc", {"doc_id": "doc-1"}, 1),
            call("read_local_doc", {"doc_id": "doc-2"}, 2),
        ),
        tool_reply(call("finish", {"answer": "ok"})),
    )
    events = run_events(client, docs=docs)
    assert final_of(events)["status"] == "blocked"
    assert all("Okafor" not in raw.decode() for raw in agent.h.upstream_raw)


def test_finish_without_answer_is_repaired_once(make_agent_client, agent) -> None:
    seen = []

    def again(payload):
        seen.append(payload)
        return tool_reply(call("finish", {"answer": "Here is the answer."}, 2))

    agent.h.upstream_reply = script(tool_reply(call("finish", {})), again)
    client = make_agent_client(AgentSettings(max_steps=1, safety_base_url=SAFETY))
    events = run_events(client)
    final = final_of(events)
    assert final["status"] == "finished" and final["answer"] == "Here is the answer."
    assert final["finish_repaired"] == 1 and final["steps"] == 2
    assert seen[0]["messages"][-1]["content"].startswith("error: finish was received")
    assert [t["function"]["name"] for t in seen[0]["tools"]] == ["finish"]
