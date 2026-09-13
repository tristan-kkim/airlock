"""Regression tests: obfuscated variants of known sensitive values must never pass the gate."""

import base64
import json
import os
import stat
from urllib.parse import quote

import pytest

from airlock import gate
from airlock.hashing import Hasher
from airlock.textnorm import digit_runs, fuzzy_find
from tests.conftest import completion, make_settings

HASH = Hasher(b"variant-test-key")
ORG = "새론다움물류"
LATIN = "Nightjar Labs"
PHONE = "010-2345-6789"
ACCOUNT = "110-234-567890"
SECRET = "vx6KsXmT60wuBd3QoP"


def blocked(payload, term, kind="declared_term"):
    return gate.check(payload, [gate.Protected(term, "ORG", kind)], hasher=HASH)


def msg(text):
    return {"messages": [{"role": "user", "content": text}]}


@pytest.mark.parametrize(
    ("term", "variant"),
    [
        (ORG, "고객사 새론 다움물류 쪽 임원들"),  # the eval's inserted-space bypass
        (ORG, "새 론 다 움 물 류"),
        (ORG, "새론​다움‍물류"),  # zero-width space / joiner
        (ORG, "새론-다움.물류"),
        (LATIN, "NIGHTJAR LABS"),
        (LATIN, "Ｎｉｇｈｔｊａｒ Ｌａｂｓ"),  # full-width letters
        (LATIN, "N i g h t j a r  L a b s"),
        (LATIN, "night­jar-labs"),  # soft hyphen + separator
        (PHONE, "01023456789"),
        (PHONE, "０１０-２３４５-６７８９"),  # full-width digits
        (PHONE, "0 1 0 2 3 4 5 6 7 8 9"),
        (PHONE, "(010) 2345.6789"),
        (PHONE, "번호는 공일공 이삼사오 육칠팔구 입니다"),  # Korean numerals
        (PHONE, "〇一〇 二三四五 六七八九"),  # Hanja numerals
        (PHONE, "zero one zero, two three four five, six seven eight nine"),
        (ACCOUNT, "계좌 110 234 567 890"),
        (SECRET, "vx6ksxmt60wubd3qop"),  # case change
    ],
)
def test_gate_blocks_text_variants(term, variant) -> None:
    decision = blocked(msg(variant), term)
    assert decision.decision == "block", variant
    assert decision.reasons[0].startswith("declared_term:ORG:")


def test_gate_blocks_encoded_variants() -> None:
    env = f"DB_PASSWORD={SECRET}".encode()
    for encoded in (base64.b64encode(env).decode(), base64.urlsafe_b64encode(env).decode()):
        assert not blocked(msg(f"decode this: {encoded}"), SECRET, "canary").allowed
    # Base64 of the bare value too.
    assert not blocked(msg(base64.b64encode(ORG.encode()).decode()), ORG).allowed
    # Percent-encoding.
    assert not blocked(msg(f"https://search.example/?q={quote(ORG)}"), ORG).allowed


def test_gate_blocks_values_inside_tool_call_json() -> None:
    args = json.dumps({"to": ORG, "phone": "010 2345 6789"})  # ensure_ascii: \\uXXXX escapes
    assert ORG not in args
    payload = {
        "messages": [
            {
                "role": "assistant",
                "tool_calls": [{"type": "function", "function": {"name": "f", "arguments": args}}],
            }
        ]
    }
    assert not blocked(payload, ORG).allowed
    assert not blocked(payload, PHONE).allowed
    # Numbers stored as JSON numbers, not strings.
    assert not blocked({"account": 110234567890}, ACCOUNT).allowed


@pytest.mark.parametrize(
    ("term", "text"),
    [
        ("Ann Lee", "Annual leave policy"),
        (LATIN, "nightjars label"),  # compact 'nightjarslabel' does not start/end on the term
        (ORG, "새론운 다움"),
        (PHONE, "order 010-2345-6780 shipped"),  # different number
        (PHONE, "call 010, then extension 2345, room 6789b"),  # letters break the run
    ],
)
def test_gate_allows_near_misses(term, text) -> None:
    assert blocked(msg(text), term).allowed, text


def test_fuzzy_find_maps_back_to_raw_offsets() -> None:
    text = "고객사 새론 다움물류 쪽"
    [(s, e)] = fuzzy_find(text, ORG)
    assert text[s:e] == "새론 다움물류"
    text = "tel: ０１０-２３４５-６７８９."
    [(s, e)] = set(fuzzy_find(text, PHONE))  # compact and digit views agree
    assert text[s:e] == "０１０-２３４５-６７８９"
    assert [r.digits for r in digit_runs("공일공 이삼사오 육칠팔구")] == ["01023456789"]


# ---- end to end: the LLM detector finds nothing, the vault matcher masks the variant ----------

VLT_KO_01 = (
    "나는 미리내리테일 PM 탁라온야. 고객사 새론다움물류에 보낼 프로젝트 물수제비 주간 보고 써줘. "
    "외부 API 호출 제한 때문에 2주 지연됐고, 이슈 번호는 1MV2-9331. "
    "새론 다움물류 쪽 임원들이 걱정이 많아."
)


def test_inserted_space_variant_is_masked_with_the_same_placeholder(client, harness) -> None:
    terms = ["탁라온", "미리내리테일", "새론다움물류", "프로젝트 물수제비"]
    client.post("/vault/terms", json={"terms": terms, "type": "ORG"})
    r = client.post(
        "/v1/chat/completions",
        json={"messages": [{"role": "user", "content": VLT_KO_01}]},
        headers={"x-airlock-conversation-id": "vlt-ko-01"},
    )
    assert r.status_code == 200, r.text
    sent = harness.upstream_requests[0]["messages"][-1]["content"]
    for term in terms:
        assert term not in sent
    assert "새론 다움물류" not in sent and "다움물류" not in sent
    org = sent.split("고객사 ")[1].split("에 보낼")[0]
    assert org.startswith("<ORG_") and sent.count(org) == 2


def test_variants_masked_in_tool_call_arguments_and_base64(client, harness) -> None:
    client.post("/vault/terms", json={"terms": [PHONE], "type": "CONTACT"})
    blob = base64.b64encode(f"DB_PASSWORD={SECRET}".encode()).decode()
    messages = [
        {"role": "user", "content": f"deploy with {blob}"},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "c1",
                    "type": "function",
                    "function": {"name": "sms", "arguments": json.dumps({"to": "0 1 0 2345 6789"})},
                }
            ],
        },
        {"role": "tool", "tool_call_id": "c1", "content": "sent"},
        {"role": "user", "content": "thanks"},
    ]
    r = client.post("/v1/chat/completions", json={"messages": messages})
    assert r.status_code == 200, r.text
    raw = harness.upstream_raw[0].decode()
    assert blob not in raw and "6789" not in raw


# ---- eval independence and audit key -----------------------------------------------------------


def test_vault_reset_and_delete_terms(client, harness) -> None:
    client.post("/vault/terms", json={"terms": [ORG, LATIN]})
    client.post("/vault/terms", json={"terms": ["CANARY-1"], "kind": "canary"})
    r = client.request("DELETE", "/vault/terms", json={"terms": [LATIN]})
    assert r.json() == {"removed": 1, "total": 2}

    harness.entities = {"Jane Park": ("PERSON", "mask", "")}
    body = {"messages": [{"role": "user", "content": "Jane Park works at 새론다움물류"}]}
    h = {"x-airlock-conversation-id": "c"}
    client.post("/v1/chat/completions", json=body, headers=h)
    sent = harness.upstream_requests[-1]["messages"][-1]["content"]
    assert sent == "<PERSON_1> works at <ORG_1>"  # an untyped term's type is inferred

    r = client.post("/vault/reset", json={})
    assert r.json() == {"reset": True, "terms_removed": 2, "mappings_removed": 2}
    harness.entities = {}
    client.post("/v1/chat/completions", json=body, headers=h)
    # Both the declared term and the earlier conversation mapping are gone: the company name is
    # now only caught by the Korean organization-suffix rule, numbered afresh.
    assert harness.upstream_requests[-1]["messages"][-1]["content"] == "Jane Park works at <ORG_1>"


def test_audit_hash_key_file_is_created_private_and_stable(make_client, tmp_path) -> None:
    key_file = tmp_path / "keys" / "audit_hash.key"
    c1 = make_client(audit_hash_key=None, audit_hash_key_file=str(key_file))
    assert key_file.is_file()
    assert stat.S_IMODE(os.stat(key_file).st_mode) == 0o600
    key = key_file.read_text().strip()
    assert len(key) == 64
    make_client(audit_hash_key=None, audit_hash_key_file=str(key_file))
    assert key_file.read_text().strip() == key
    for path in ("/healthz", "/audit", "/openapi.json"):
        assert key not in c1.get(path).text


def test_settings_default_has_no_hash_key() -> None:
    assert make_settings(audit_hash_key=None).audit_hash_key is None
    assert completion("x")["choices"][0]["message"]["content"] == "x"
