import pytest

from airlock.detect.patterns import detect_patterns, high_confidence_hits, shannon_entropy


def rules(text: str) -> dict[str, str]:
    return {s.rule: s.text for s in detect_patterns(text)}


@pytest.mark.parametrize(
    ("text", "rule", "value"),
    [
        ("연락처는 010-1234-5678 입니다", "kr_mobile", "010-1234-5678"),
        ("call +82 10-9876-5432 today", "kr_mobile", "+82 10-9876-5432"),
        ("사무실 02-555-1234", "kr_landline", "02-555-1234"),
        ("주민번호 900101-1234567", "kr_rrn", "900101-1234567"),
        ("국민은행 123456-78-901234 로 입금", "kr_bank_account", "123456-78-901234"),
        ("mail me: minsu.kim@example.co.kr", "email", "minsu.kim@example.co.kr"),
        ("card 4111 1111 1111 1111 exp", "card_number", "4111 1111 1111 1111"),
        ("OPENAI_API_KEY=sk-proj-abcDEF1234567890abcdef12", "openai_style_key", None),
        ("token nb-AbCdEf0123456789ghIJkl here", "nebius_key", "nb-AbCdEf0123456789ghIJkl"),
        ("id AKIAIOSFODNN7EXAMPLE end", "aws_access_key_id", "AKIAIOSFODNN7EXAMPLE"),
        ("ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8", "github_token", None),
        (
            "auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N",
            "jwt",
            None,
        ),
        (
            "DATABASE_URL=postgres://admin:hunter22@db.internal:5432/prod",
            "connection_string",
            "postgres://admin:hunter22@db.internal:5432/prod",
        ),
    ],
)
def test_rules_detect(text: str, rule: str, value: str | None) -> None:
    found = rules(text)
    assert rule in found, found
    if value is not None:
        assert found[rule] == value


def test_openai_key_value_is_exact() -> None:
    key = "sk-proj-abcDEF1234567890abcdef12"
    assert rules(f"OPENAI_API_KEY={key}")["openai_style_key"] == key


def test_entropy_catches_unknown_token_but_not_hashes() -> None:
    token = "q8Zr2LmX9vTb4NpK7wYc1HsD6gFj3AeU"
    assert shannon_entropy(token) > 4.2
    assert "entropy" in rules(f"secret: {token}")
    assert "entropy" not in rules("commit 3f786850e387550fdab836ed7e6dc881de23001b")
    assert "entropy" not in rules("uuid 123e4567-e89b-12d3-a456-426614174000")
    assert "entropy" not in rules("the_quick_brown_fox_jumps_over_the_lazy_dog")


def test_no_false_positives_on_plain_text() -> None:
    text = "On 2026-09-13 we shipped version 1.2.3 of the app to 1,024 users in Seoul."
    assert detect_patterns(text) == []


def test_invalid_rrn_date_is_ignored() -> None:
    assert "kr_rrn" not in rules("번호 991350-1234567")


def test_placeholders_are_not_redetected() -> None:
    assert detect_patterns("hello [[SECRET_1]] and [[CONTACT_2]]") == []


def test_high_confidence_hits_for_gate() -> None:
    hits = high_confidence_hits("x sk-abcdefghijklmnopqrstuvwxyz123 y 900101-1234567")
    assert {name for name, _ in hits} == {"openai_style_key", "kr_rrn"}
    assert high_confidence_hits("phone 010-1234-5678") == []
