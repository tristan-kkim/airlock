import json

from airlock import gate
from airlock.detect.llm import LocalModelBadOutput, extract_json, parse_spans
from airlock.detect.spans import Placement, Span, find_term, resolve_overlaps
from airlock.hashing import Hasher
from airlock.rehydrate import rehydrate_arguments, rehydrate_text
from airlock.vault import Vault

HASH = Hasher(b"unit-test-key")


def test_longest_span_wins() -> None:
    short = Span("Kim", "PERSON", source="llm")
    long = Span("Tristan Kim", "PERSON", source="llm")
    chosen = resolve_overlaps([Placement(8, 11, short), Placement(0, 11, long)])
    assert [p.span.text for p in chosen] == ["Tristan Kim"]


def test_term_matching_boundaries() -> None:
    assert find_term("Annual report for Ann", "Ann") == [(18, 21)]
    assert find_term("김민수는 회의에 갔다", "김민수") == [(0, 3)]
    assert find_term("TRISTAN  kim", "Tristan Kim") == [(0, 12)]


def test_vault_same_original_same_placeholder() -> None:
    vault = Vault(":memory:")
    s = vault.session("c1")
    assert s.mask("Tristan Kim", "PERSON").outbound == "[[PERSON_1]]"
    assert s.mask("tristan kim", "PERSON").outbound == "[[PERSON_1]]"
    assert s.mask("Jane Doe", "PERSON").outbound == "[[PERSON_2]]"
    assert s.mask("010-1234-5678", "CONTACT").outbound == "[[CONTACT_1]]"
    # A fresh session object for the same conversation sees the same mappings.
    again = vault.session("c1")
    assert again.mask("Jane Doe", "PERSON").outbound == "[[PERSON_2]]"
    assert again.original_for("PERSON_1") == "Tristan Kim"
    # Other conversations are independent.
    assert vault.session("c2").mask("Jane Doe", "PERSON").outbound == "[[PERSON_1]]"


def test_gate_blocks_vault_original_anywhere() -> None:
    payload = {
        "messages": [{"role": "user", "content": "hello [[PERSON_1]]"}],
        "tools": [{"function": {"description": "look up TRISTAN KIM"}}],
    }
    decision = gate.check(
        payload, hasher=HASH, protected=[gate.Protected("Tristan Kim", "PERSON", "vault_original")]
    )
    assert decision.decision == "block"
    assert decision.reasons[0].startswith("vault_original:PERSON:")
    assert "Tristan" not in json.dumps(decision.as_dict())


def test_gate_normalizes_fullwidth_and_catches_secrets() -> None:
    payload = {
        "messages": [
            {"role": "user", "content": "ｔｒｉｓｔａｎ says sk-abcdefghijklmnopqrstu12345"}
        ]
    }
    decision = gate.check(
        payload, hasher=HASH, protected=[gate.Protected("tristan", "PERSON", "declared_term")]
    )
    assert decision.decision == "block"
    kinds = {r.split(":")[0] for r in decision.reasons}
    assert kinds == {"declared_term", "secret_pattern"}


def test_gate_allows_clean_payload() -> None:
    payload = {"messages": [{"role": "user", "content": "Summarize [[PERSON_1]]'s annual report"}]}
    decision = gate.check(
        payload, hasher=HASH, protected=[gate.Protected("Ann", "PERSON", "vault_original")]
    )
    assert decision.allowed


def test_parse_spans_drops_hallucinations() -> None:
    data = {
        "spans": [
            {"text": "Jane", "type": "PERSON", "action": "mask", "replacement": ""},
            {"text": "Bob", "type": "PERSON", "action": "mask", "replacement": ""},
            {"text": "x", "type": "PERSON", "action": "mask", "replacement": ""},
            {"text": "Acme", "type": "NOT_A_TYPE", "action": "mask", "replacement": ""},
        ]
    }
    spans = parse_spans(data, "Jane works at Acme")
    assert [s.text for s in spans] == ["Jane"]


def test_extract_json_tolerates_think_and_fences() -> None:
    assert extract_json('<think>hmm</think>\n```json\n{"spans": []}\n```') == {"spans": []}
    try:
        extract_json("no json here")
    except LocalModelBadOutput:
        pass
    else:
        raise AssertionError("expected LocalModelBadOutput")


def test_rehydrate_text_and_tool_arguments() -> None:
    vault = Vault(":memory:")
    s = vault.session("c")
    s.mask('Kim "The Boss" Lee', "PERSON")
    assert rehydrate_text("Hi [[PERSON_1]] and [PERSON_1] and [[PERSON_9]]", s) == (
        'Hi Kim "The Boss" Lee and Kim "The Boss" Lee and [[PERSON_9]]'
    )
    args = rehydrate_arguments('{"to": "[[PERSON_1]]"}', s)
    assert json.loads(args) == {"to": 'Kim "The Boss" Lee'}
