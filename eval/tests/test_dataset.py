"""Dataset reproducibility, balance and fictional-data guarantees."""

import json
import re
from collections import Counter
from pathlib import Path

import pytest

import generate
from scoring import score_case

CASES_DIR = Path(__file__).resolve().parents[1] / "cases"


@pytest.fixture(scope="module")
def cases():
    return [
        json.loads(line)
        for p in sorted(CASES_DIR.glob("*.jsonl"))
        for line in p.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def all_text(case):
    return json.dumps(case.get("messages") or [case["query"], case["context"]], ensure_ascii=False)


def test_generator_is_deterministic_and_committed():
    files = generate.generate()
    for name, text in files.items():
        assert (CASES_DIR / name).read_text(encoding="utf-8") == text, f"{name} is stale"
    assert files == generate.generate()


def test_size_and_balance(cases):
    assert 230 <= len(cases) <= 260
    langs = Counter(c["lang"] for c in cases)
    assert abs(langs["ko"] - langs["en"]) <= 2
    cats = Counter(c["category"] for c in cases)
    assert set(cats) == set(generate.CATEGORIES)
    assert max(cats.values()) - min(cats.values()) <= 1


def test_schema(cases):
    keys = {
        "id",
        "lang",
        "category",
        "task",
        "vault_terms",
        "canaries",
        "must_not_leak",
        "must_keep",
        "quasi_group",
        "quasi_k",
        "reference_answer_notes",
    }
    for c in cases:
        assert keys <= set(c), c["id"]
        assert c["task"] in {"chat", "search"}
        if c["task"] == "chat":
            assert isinstance(c["messages"], list) and c["messages"]
        else:
            assert isinstance(c["query"], str) and "context" in c


def test_passthrough_proxy_leaks_every_eligible_case(cases):
    """Sending the raw request unchanged must register as a leak, or the metric is vacuous."""
    for c in cases:
        payload = (
            {"messages": c["messages"]}
            if c["task"] == "chat"
            else {"query": c["query"], "context": c["context"]}
        )
        dest = "upstream" if c["task"] == "chat" else "tavily"
        rec = {
            "status": "ok",
            "audit": {
                "outbound": [{"destination": dest, "payload": payload}],
                "detections": [],
                "gate": {"decision": "allow"},
            },
        }
        s = score_case(c, rec)
        if c["must_not_leak"] or c["quasi_group"]:
            assert s["leaked"], c["id"]
            assert s["n_values_leaked"] == s["n_values"], c["id"]
        assert s["must_keep_missing"] == [], c["id"]


def test_canaries_are_unique(cases):
    all_canaries = [x for c in cases for x in c["canaries"]]
    assert len(all_canaries) == len(set(all_canaries))


def test_emails_use_reserved_domains(cases):
    for c in cases:
        for domain in re.findall(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", all_text(c), re.ASCII):
            # user:password@host in connection strings is not an e-mail; hosts there are private
            # IPs or the reserved .internal TLD.
            if domain.split(".")[-1].isdigit() or domain.endswith(".internal"):
                continue
            assert domain in {"example.com", "example.org", "example.net"}, (c["id"], domain)
    # percent-encoded mailto links too
    for c in cases:
        for domain in re.findall(r"%40([\w.-]+)", all_text(c), re.ASCII):
            assert domain in {"example.com", "example.org", "example.net"}


def test_resident_numbers_are_invalid(cases):
    for c in cases:
        for v in c["must_not_leak"]:
            if re.fullmatch(r"\d{6}-[1-4]\d{6}", v):
                mm = int(v[2:4])
                assert mm > 12, (c["id"], v)
                digits = v.replace("-", "")
                assert generate.rrn_check_digit(digits[:12]) != int(digits[12]), (c["id"], v)


def test_card_numbers_fail_luhn(cases):
    for c in cases:
        for v in c["must_not_leak"]:
            d = re.sub(r"[ -]", "", v)
            if re.fullmatch(r"\d{16}", d):
                assert generate.luhn_check_digit(d[:15]) != int(d[15]), (c["id"], v)


def test_phone_numbers_use_fictional_ranges(cases):
    for c in cases:
        text = all_text(c)
        for m in re.findall(r"\(\d{3}\) (\d{3})-(\d{4})", text):
            assert m[0] == "555" and m[1].startswith("01"), (c["id"], m)
        for m in re.findall(r"\b010-(\d{4})-\d{4}\b", text):
            assert m.startswith("0"), (c["id"], m)


def test_ssns_use_never_issued_area(cases):
    for c in cases:
        for m in re.findall(r"\b(\d{3})-\d{2}-\d{4}\b", all_text(c)):
            assert m == "666", (c["id"], m)


def test_no_real_provider_key_prefixes(cases):
    banned = ["AKIA", "sk_live_", "sk-proj-", "ghp_", "xoxb-", "tvly-", "AIza", "-----BEGIN"]
    for c in cases:
        text = all_text(c)
        for b in banned:
            assert b not in text, (c["id"], b)


def test_benign_has_nothing_to_protect(cases):
    for c in cases:
        if c["category"] == "benign":
            assert not c["must_not_leak"] and not c["canaries"] and not c["vault_terms"]
            assert c["must_keep"]


def test_vault_terms_do_not_appear_in_other_categories(cases):
    terms = {t for c in cases for t in c["vault_terms"]}
    for c in cases:
        if c["category"] != "vault_terms":
            text = all_text(c)
            assert not any(t in text for t in terms), c["id"]
