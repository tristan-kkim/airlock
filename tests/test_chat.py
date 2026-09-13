import hashlib
import hmac
import json

import httpx
import pytest

from airlock import pipeline
from airlock.config import ProtectionLevel
from tests.conftest import TEST_HASH_KEY, completion

NAME = "Tristan Kim"
PHONE = "010-1234-5678"
EMAIL = "tristan.kim@example.com"
ORG = "Hanbit Clinic"


def chat(client, messages, headers=None, **extra):
    return client.post(
        "/v1/chat/completions",
        json={"model": "anything", "messages": messages, **extra},
        headers=headers or {},
    )


def outbound_text(harness, i=-1) -> str:
    return harness.upstream_raw[i].decode()


def test_masking_round_trip_and_rehydration(client, harness) -> None:
    harness.entities = {NAME: ("PERSON", "mask", ""), ORG: ("ORG", "mask", "")}
    harness.upstream_reply = lambda p: completion(
        "Dear [[PERSON_1]], I will call [[CONTACT_1]] and email [[CONTACT_2]] about [[ORG_1]]."
    )
    prompt = f"I am {NAME} from {ORG}. Call me at {PHONE} or {EMAIL}."
    r = chat(client, [{"role": "user", "content": prompt}])
    assert r.status_code == 200, r.text
    assert r.headers["x-airlock-request-id"].startswith("req_")

    sent = outbound_text(harness)
    for original in (NAME, PHONE, EMAIL, ORG):
        assert original not in sent
    user_msg = harness.upstream_requests[0]["messages"][-1]["content"]
    assert (
        user_msg == "I am [[PERSON_1]] from [[ORG_1]]. Call me at [[CONTACT_1]] or [[CONTACT_2]]."
    )
    assert harness.upstream_requests[0]["model"] == "nvidia/Nemotron-3-Ultra-550b-a55b"

    answer = r.json()["choices"][0]["message"]["content"]
    assert answer == f"Dear {NAME}, I will call {PHONE} and email {EMAIL} about {ORG}."


def test_audit_record_matches_wire_and_has_no_originals(client, harness) -> None:
    harness.entities = {NAME: ("PERSON", "mask", "")}
    secret = "sk-proj-Zx8Qw3Er5Ty7Ui9Op1As2Df4"
    r = chat(
        client,
        [{"role": "user", "content": f"{NAME} here, my key is {secret} and phone {PHONE}"}],
        user="tristan-account-42",
    )
    assert r.status_code == 200
    rid = r.headers["x-airlock-request-id"]
    audit = client.get(f"/audit/{rid}").json()

    assert audit["request_id"] == rid and audit["kind"] == "chat"
    assert audit["gate"] == {"decision": "allow", "reasons": []}
    assert audit["outbound"][0]["destination"] == "upstream"
    assert audit["outbound"][0]["payload"] == json.loads(harness.upstream_raw[0])
    assert "user" not in audit["outbound"][0]["payload"]  # identifiers are not forwarded

    blob = json.dumps(audit, ensure_ascii=False)
    for original in (NAME, secret, PHONE):
        assert original not in blob
    hashes = {d["text_sha256"] for d in audit["detections"]}
    key = TEST_HASH_KEY.encode()
    assert hmac.new(key, NAME.encode(), hashlib.sha256).hexdigest() in hashes
    assert hmac.new(key, secret.encode(), hashlib.sha256).hexdigest() in hashes
    # Plain SHA-256 (brute-forceable for short values) never appears.
    assert hashlib.sha256(PHONE.encode()).hexdigest() not in json.dumps(audit)
    sources = {d["source"] for d in audit["detections"]}
    assert {"llm", "regex"} <= sources
    assert set(audit["timings_ms"]) >= {"detect", "gate", "upstream", "total"}


def test_fail_closed_when_local_model_down(client, harness) -> None:
    harness.local_down = True
    r = chat(client, [{"role": "user", "content": "hello, nothing private here"}])
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["type"] == "airlock_blocked"
    assert err["reasons"] == ["local_detector_unavailable:LocalModelUnavailable"]
    assert harness.upstream_requests == []
    audit = client.get(f"/audit/{err['request_id']}").json()
    assert audit["gate"]["decision"] == "block"
    assert audit["outbound"] == []


def test_fail_closed_on_unparseable_detector_output(client, harness) -> None:
    harness.local_garbage = True
    r = chat(client, [{"role": "user", "content": "hello"}])
    assert r.status_code == 422
    assert r.json()["error"]["reasons"] == ["local_detector_unavailable:LocalModelBadOutput"]
    assert harness.upstream_requests == []


def test_gate_blocks_when_detector_misses_a_vault_term(client, harness, monkeypatch) -> None:
    """The LLM misses the name and vault matching is broken (simulated bug): the gate blocks."""
    assert client.post("/vault/terms", json={"terms": [NAME]}).json()["added"] == 1
    harness.entities = {}  # the local model finds nothing
    monkeypatch.setattr(pipeline, "find_term", lambda text, term: [])

    r = chat(client, [{"role": "user", "content": f"Write a bio for {NAME}."}])
    assert r.status_code == 422, r.text
    err = r.json()["error"]
    assert err["type"] == "airlock_blocked"
    assert err["reasons"][0].startswith("declared_term:PERSON:")
    assert NAME not in r.text
    assert harness.upstream_requests == []


def test_gate_scans_fields_the_sanitizer_does_not_rewrite(client, harness) -> None:
    client.post("/vault/terms", json={"terms": ["Project Nightjar"], "type": "ORG"})
    tools = [
        {
            "type": "function",
            "function": {
                "name": "lookup",
                "description": "Search Project Nightjar tickets",
                "parameters": {"type": "object", "properties": {}},
            },
        }
    ]
    r = chat(client, [{"role": "user", "content": "find open tickets"}], tools=tools)
    assert r.status_code == 422
    assert r.json()["error"]["reasons"][0].startswith("declared_term:ORG:")
    assert harness.upstream_requests == []


def test_canary_blocks(make_client, harness) -> None:
    client = make_client(canaries=("CANARY-7f3a91",))
    r = chat(client, [{"role": "user", "content": "debug dump: CANARY-7f3a91"}])
    # The regex/LLM detectors do not know the canary, so it reaches the gate and is blocked.
    assert r.status_code == 422
    assert r.json()["error"]["reasons"][0].startswith("canary:")


def test_images_are_blocked_as_uninspectable(client, harness) -> None:
    content = [
        {"type": "text", "text": "what is in this picture?"},
        {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}},
    ]
    r = chat(client, [{"role": "user", "content": content}])
    assert r.status_code == 422
    assert r.json()["error"]["reasons"] == ["uninspectable_content:image_url"]


def test_multi_turn_placeholder_consistency(client, harness) -> None:
    harness.entities = {NAME: ("PERSON", "mask", ""), "Jane Park": ("PERSON", "mask", "")}
    harness.upstream_reply = lambda p: completion("Noted, [[PERSON_1]].")
    turn1 = [{"role": "user", "content": f"My name is {NAME}."}]
    r1 = chat(client, turn1)
    assert r1.status_code == 200
    conv = r1.headers["x-airlock-conversation-id"]
    assert r1.json()["choices"][0]["message"]["content"] == f"Noted, {NAME}."

    harness.upstream_reply = lambda p: completion("[[PERSON_2]] is [[PERSON_1]]'s manager.")
    turn2 = [
        *turn1,
        {"role": "assistant", "content": f"Noted, {NAME}."},
        {"role": "user", "content": f"Jane Park manages {NAME.lower()}. Who manages whom?"},
    ]
    r2 = chat(client, turn2)
    assert r2.status_code == 200
    assert r2.headers["x-airlock-conversation-id"] == conv
    sent = harness.upstream_requests[1]["messages"]
    assert sent[-3]["content"] == "My name is [[PERSON_1]]."
    assert sent[-2]["content"] == "Noted, [[PERSON_1]]."
    assert sent[-1]["content"] == "[[PERSON_2]] manages [[PERSON_1]]. Who manages whom?"
    assert r2.json()["choices"][0]["message"]["content"] == f"Jane Park is {NAME}'s manager."

    # A client that keeps placeholders in its history works too.
    turn3 = [*turn1, {"role": "assistant", "content": "Noted, [[PERSON_1]]."}]
    turn3.append({"role": "user", "content": "Repeat my name."})
    r3 = chat(client, turn3)
    assert r3.status_code == 200
    assert harness.upstream_requests[2]["messages"][-2]["content"] == "Noted, [[PERSON_1]]."


def test_explicit_conversation_header_scopes_placeholders(client, harness) -> None:
    harness.entities = {NAME: ("PERSON", "mask", ""), "Jane Park": ("PERSON", "mask", "")}
    h = {"x-airlock-conversation-id": "demo-1"}
    chat(client, [{"role": "user", "content": "Jane Park called."}], headers=h)
    chat(client, [{"role": "user", "content": f"{NAME} called."}], headers=h)
    assert harness.upstream_requests[1]["messages"][-1]["content"] == "[[PERSON_2]] called."


def test_tool_call_arguments_are_rehydrated(client, harness) -> None:
    harness.entities = {NAME: ("PERSON", "mask", "")}
    harness.upstream_reply = lambda p: completion(
        None,
        tool_calls=[
            {
                "id": "call_1",
                "type": "function",
                "function": {
                    "name": "send_sms",
                    "arguments": json.dumps({"to": "[[CONTACT_1]]", "text": "Hi [[PERSON_1]]"}),
                },
            }
        ],
    )
    r = chat(client, [{"role": "user", "content": f"Text {NAME} at {PHONE}: hi"}])
    assert r.status_code == 200
    call = r.json()["choices"][0]["message"]["tool_calls"][0]
    assert json.loads(call["function"]["arguments"]) == {"to": PHONE, "text": f"Hi {NAME}"}


def test_reasoning_content_hidden_unless_requested_and_content_trimmed(client, harness) -> None:
    harness.entities = {NAME: ("PERSON", "mask", "")}

    def reply(p):
        body = completion("\n\nHello [[PERSON_1]]")
        body["choices"][0]["message"]["reasoning_content"] = "The user [[PERSON_1]] wants..."
        return body

    harness.upstream_reply = reply
    msgs = [{"role": "user", "content": f"I am {NAME}"}]
    hidden = chat(client, msgs).json()["choices"][0]["message"]
    assert hidden == {"role": "assistant", "content": f"Hello {NAME}"}
    shown = chat(client, msgs, headers={"x-airlock-include-reasoning": "1"}).json()
    assert shown["choices"][0]["message"]["reasoning_content"] == f"The user {NAME} wants..."


def test_generalization_and_protection_levels(make_client, harness) -> None:
    harness.entities = {
        "34 years old": ("QUASI_IDENTIFIER", "generalize", "in their 30s"),
        NAME: ("PERSON", "mask", ""),
    }
    text = f"{NAME} is 34 years old."

    for level, expected in [
        (ProtectionLevel.BALANCED, "[[PERSON_1]] is in their 30s."),
        (ProtectionLevel.STRICT, "[[PERSON_1]] is [[QUASI_IDENTIFIER_1]]."),
        (ProtectionLevel.MINIMAL, "[[PERSON_1]] is 34 years old."),
    ]:
        client = make_client(protection_level=level)
        r = chat(client, [{"role": "user", "content": text}])
        assert r.status_code == 200, (level, r.text)
        assert harness.upstream_requests[-1]["messages"][-1]["content"] == expected, level


def test_generalization_that_leaks_original_falls_back_to_mask(client, harness) -> None:
    harness.entities = {"Gangnam": ("LOCATION", "generalize", "near Gangnam station")}
    r = chat(client, [{"role": "user", "content": "I live in Gangnam."}])
    assert r.status_code == 200
    assert harness.upstream_requests[0]["messages"][-1]["content"] == "I live in [[LOCATION_1]]."


def test_passthrough_fields(client, harness) -> None:
    tools = [{"type": "function", "function": {"name": "f", "parameters": {"type": "object"}}}]
    chat(
        client,
        [{"role": "user", "content": "hi"}],
        reasoning_effort="none",
        tools=tools,
        tool_choice="auto",
        temperature=0.2,
        metadata={"user_email": "x@example.com"},
    )
    sent = harness.upstream_requests[0]
    assert sent["reasoning_effort"] == "none"
    assert sent["tools"] == tools and sent["tool_choice"] == "auto"
    assert "metadata" not in sent


def test_fallback_model_on_upstream_error(client, harness) -> None:
    def reply(p):
        if p["model"] == "nvidia/Nemotron-3-Ultra-550b-a55b":
            raise _Status(503)
        return completion("from fallback")

    original_upstream = harness._upstream

    def upstream(request: httpx.Request) -> httpx.Response:
        try:
            return original_upstream(request)
        except _Status as s:
            return httpx.Response(s.code, json={"error": {"message": "model is unavailable"}})

    harness._upstream = upstream  # type: ignore[method-assign]
    harness.upstream_reply = reply
    r = chat(client, [{"role": "user", "content": "hi"}], reasoning_effort="none")
    assert r.status_code == 200
    assert r.json()["choices"][0]["message"]["content"] == "from fallback"
    audit = client.get(f"/audit/{r.headers['x-airlock-request-id']}").json()
    assert [o["payload"]["model"] for o in audit["outbound"]] == [
        "nvidia/Nemotron-3-Ultra-550b-a55b",
        "nvidia/nemotron-3-super-120b-a12b",
    ]
    assert "reasoning_effort" not in audit["outbound"][1]["payload"]
    assert audit["meta"]["fallback"] is True
    assert audit["meta"]["model_used"] == "nvidia/nemotron-3-super-120b-a12b"


class _Status(Exception):
    def __init__(self, code: int):
        self.code = code


def _sse(chunks: list[dict]) -> bytes:
    return "".join(f"data: {json.dumps(c)}\n\n" for c in chunks).encode() + b"data: [DONE]\n\n"


def _chunk(delta: dict, finish=None) -> dict:
    return {
        "id": "c1",
        "object": "chat.completion.chunk",
        "created": 1,
        "model": "m",
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
    }


def test_streaming_rehydrates_split_placeholders(client, harness) -> None:
    harness.entities = {NAME: ("PERSON", "mask", "")}
    body = _sse(
        [
            _chunk({"role": "assistant", "content": "\n\nHi [["}),
            _chunk({"reasoning_content": "secret thoughts about [[PERSON_1]]"}),
            _chunk({"content": "PERS"}),
            _chunk({"content": "ON_1]], call [[CONTACT"}),
            _chunk({"content": "_1]] [x]"}),
            _chunk({}, finish="stop"),
        ]
    )

    def upstream(request: httpx.Request) -> httpx.Response:
        harness.upstream_requests.append(json.loads(request.content))
        return httpx.Response(200, content=body, headers={"content-type": "text/event-stream"})

    harness._upstream = upstream  # type: ignore[method-assign]
    msgs = [{"role": "user", "content": f"I am {NAME}, phone {PHONE}"}]
    with client.stream(
        "POST", "/v1/chat/completions", json={"messages": msgs, "stream": True}
    ) as r:
        assert r.status_code == 200
        assert r.headers["x-airlock-request-id"].startswith("req_")
        lines = [ln for ln in r.iter_lines() if ln.startswith("data: ")]
    assert harness.upstream_requests[0]["stream"] is True
    assert lines[-1] == "data: [DONE]"
    text = ""
    for ln in lines[:-1]:
        for choice in json.loads(ln[6:])["choices"]:
            assert "reasoning_content" not in choice["delta"]
            text += choice["delta"].get("content") or ""
    assert text == f"Hi {NAME}, call {PHONE} [x]"


@pytest.mark.parametrize("path", ["/healthz", "/"])
def test_health_and_ui(client, path) -> None:
    r = client.get(path)
    assert r.status_code == 200


def test_rejects_non_json_posts_and_foreign_hosts(client, harness) -> None:
    r = client.post(
        "/v1/chat/completions",
        content=json.dumps({"messages": [{"role": "user", "content": "hi"}]}),
        headers={"content-type": "text/plain"},
    )
    assert r.status_code == 415
    assert client.get("/healthz", headers={"host": "evil.example"}).status_code == 400
    assert harness.local_requests == [] and harness.upstream_requests == []
