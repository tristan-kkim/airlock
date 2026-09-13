"""Deterministic detectors: Korean-aware PII regexes, secret token patterns, entropy check.

Every rule is pure and offline. Rules flagged `high_confidence` are also enforced by the gate on
the final outbound payload, independently of whatever the detectors did earlier.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass

from airlock.detect.spans import PLACEHOLDER_RE, Span


def _luhn_ok(value: str) -> bool:
    digits = [int(c) for c in value if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _rrn_ok(value: str) -> bool:
    """Korean resident registration number: YYMMDD-GXXXXXX with a plausible birth date."""
    digits = re.sub(r"\D", "", value)
    if len(digits) != 13:
        return False
    month, day, gender = int(digits[2:4]), int(digits[4:6]), digits[6]
    return 1 <= month <= 12 and 1 <= day <= 31 and gender in "12345678"


def _account_ok(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if not 10 <= len(digits) <= 16:
        return False
    # Phone numbers and dates are handled by their own rules.
    if re.fullmatch(r"01[016789]-?\d{3,4}-?\d{4}", value) or re.fullmatch(
        r"0\d{1,2}-\d{3,4}-\d{4}", value
    ):
        return False
    return not _rrn_ok(value)


def _password_like(value: str) -> bool:
    """A concrete password, not a word: Latin letters plus digits or symbols, no Hangul."""
    value = value.rstrip(".,!?)")  # "The password is incorrect." is not a password
    return (
        bool(re.search(r"[A-Za-z]", value))
        and bool(re.search(r"[\d\W_]", value))
        and not re.search(r"[가-힣]", value)
    )


@dataclass(frozen=True)
class Rule:
    name: str
    type: str
    pattern: re.Pattern[str]
    group: int = 0
    validator: Callable[[str], bool] | None = None
    high_confidence: bool = False
    priority: int = 50


_NB = r"(?<![A-Za-z0-9_])"  # left boundary
_NA = r"(?![A-Za-z0-9_])"  # right boundary

RULES: tuple[Rule, ...] = (
    # ---- secrets (high confidence: enforced by the gate as well) ----
    Rule(
        "private_key_block",
        "SECRET",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY-----"
        ),
        high_confidence=True,
        priority=1,
    ),
    Rule(
        "connection_string",
        "SECRET",
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|"
            r"sqlserver|clickhouse)://[^\s:@/'\"<>]+:[^\s@/'\"<>]+@[^\s'\"<>]+",
            re.IGNORECASE,
        ),
        high_confidence=True,
        priority=2,
    ),
    Rule(
        "jwt",
        "SECRET",
        re.compile(_NB + r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}" + _NA),
        high_confidence=True,
        priority=3,
    ),
    Rule(
        "openai_style_key",
        "SECRET",
        re.compile(_NB + r"sk-(?:proj-|ant-|live-|test-)?[A-Za-z0-9_\-]{20,}" + _NA),
        high_confidence=True,
        priority=4,
    ),
    Rule(
        "nebius_key",
        "SECRET",
        re.compile(_NB + r"nb-[A-Za-z0-9_\-]{20,}" + _NA),
        high_confidence=True,
        priority=4,
    ),
    Rule(
        "tavily_key",
        "SECRET",
        re.compile(_NB + r"tvly-(?:dev-|prod-)?[A-Za-z0-9_\-]{20,}" + _NA),
        high_confidence=True,
        priority=4,
    ),
    Rule(
        "aws_access_key_id",
        "SECRET",
        re.compile(_NB + r"(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}" + _NA),
        high_confidence=True,
        priority=4,
    ),
    Rule(
        "aws_secret_access_key",
        "SECRET",
        re.compile(
            r"aws_secret_access_key\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
            re.IGNORECASE,
        ),
        group=1,
        high_confidence=True,
        priority=4,
    ),
    Rule(
        "github_token",
        "SECRET",
        re.compile(_NB + r"(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})" + _NA),
        high_confidence=True,
        priority=4,
    ),
    Rule(
        "slack_token",
        "SECRET",
        re.compile(_NB + r"xox[abprs]-[A-Za-z0-9-]{10,}" + _NA),
        high_confidence=True,
        priority=4,
    ),
    Rule(
        "google_api_key",
        "SECRET",
        re.compile(_NB + r"AIza[0-9A-Za-z_\-]{35}" + _NA),
        high_confidence=True,
        priority=4,
    ),
    Rule(
        "bearer_token",
        "SECRET",
        re.compile(r"\bBearer\s+([A-Za-z0-9._~+/\-]{20,}=*)"),
        group=1,
        priority=10,
    ),
    Rule(
        "password_assignment",
        "SECRET",
        re.compile(
            r"(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|비밀번호|패스워드)"
            r"\s*[=:]\s*[\"']?([^\s\"',;]{6,})",
            re.IGNORECASE,
        ),
        group=1,
        priority=11,
    ),
    Rule(
        "password_phrase",
        "SECRET",
        re.compile(
            r"(?:password|passwd|passcode|비밀번호|패스워드|암호)\s*(?:is|was|:|=|가|는|은|이)?\s*"
            r"[\"'“‘]?([^\s\"'“”‘’,;]{6,64})",
            re.IGNORECASE,
        ),
        group=1,
        validator=_password_like,
        priority=12,
    ),
    # ---- Korean identifiers ----
    Rule(
        "kr_rrn",
        "ID_NUMBER",
        re.compile(r"(?<!\d)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])-?[1-8]\d{6}(?!\d)"),
        validator=_rrn_ok,
        high_confidence=True,
        priority=20,
    ),
    Rule(
        "kr_mobile",
        "CONTACT",
        re.compile(r"(?<![\d+])(?:\+82[\s-]?1[016789]|01[016789])[\s.-]?\d{3,4}[\s.-]?\d{4}(?!\d)"),
        priority=21,
    ),
    Rule(
        "kr_landline",
        "CONTACT",
        re.compile(r"(?<![\d+])(?:\+82[\s-]?|0)(?:2|[3-6][1-5])[\s.)-]\d{3,4}[\s.-]\d{4}(?!\d)"),
        priority=22,
    ),
    Rule(
        "email",
        "CONTACT",
        re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![A-Za-z])"),
        priority=23,
    ),
    Rule(
        "card_number",
        "FINANCIAL",
        re.compile(r"(?<!\d)(?:\d{4}[ -]?){3}\d{1,7}(?!\d)"),
        validator=_luhn_ok,
        priority=24,
    ),
    Rule(
        "kr_bank_account",
        "FINANCIAL",
        re.compile(r"(?<![\d-])\d{2,6}-\d{2,6}-\d{2,7}(?:-\d{1,3})?(?![\d-])"),
        validator=_account_ok,
        priority=30,
    ),
    Rule(
        "intl_phone",
        "CONTACT",
        re.compile(r"(?<![\w+])\+(?!82)\d{1,3}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,4}){2,4}(?!\d)"),
        priority=31,
    ),
)

HIGH_CONFIDENCE_RULES: tuple[Rule, ...] = tuple(r for r in RULES if r.high_confidence)

# ---- entropy ----
_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9+/_=.\-])[A-Za-z0-9+/_=\-]{24,}(?![A-Za-z0-9+/_=\-])")
ENTROPY_MIN_LEN = 24
ENTROPY_THRESHOLD = 4.2  # bits/char; pure hex tops out at 4.0 so git SHAs and UUIDs pass


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_like_secret(token: str) -> bool:
    if len(token) < ENTROPY_MIN_LEN:
        return False
    if not (re.search(r"[A-Za-z]", token) and re.search(r"\d", token)):
        return False
    if re.fullmatch(r"[0-9a-fA-F\-]+", token):  # hashes, UUIDs
        return False
    if re.fullmatch(r"[a-z_\-]+\d*", token) or re.fullmatch(r"[A-Z_\-]+\d*", token):
        return False  # snake_case identifiers
    return shannon_entropy(token) >= ENTROPY_THRESHOLD


def _iter_rule_matches(rule: Rule, text: str):
    for m in rule.pattern.finditer(text):
        value = m.group(rule.group)
        if not value:
            continue
        if rule.validator is not None and not rule.validator(value):
            continue
        yield m.start(rule.group), m.end(rule.group), value


def _inside_placeholder(text: str, start: int, end: int) -> bool:
    return any(p.start() <= start and end <= p.end() for p in PLACEHOLDER_RE.finditer(text))


def detect_patterns(text: str) -> list[Span]:
    """Run all regex rules plus the entropy check. Returns spans with offsets."""
    spans: list[Span] = []
    for rule in RULES:
        for start, end, value in _iter_rule_matches(rule, text):
            if _inside_placeholder(text, start, end):
                continue
            spans.append(
                Span(
                    text=value, type=rule.type, source="regex", start=start, end=end, rule=rule.name
                )
            )
    for m in _TOKEN_RE.finditer(text):
        token = m.group(0)
        if _looks_like_secret(token) and not _inside_placeholder(text, m.start(), m.end()):
            spans.append(
                Span(
                    text=token,
                    type="SECRET",
                    source="entropy",
                    start=m.start(),
                    end=m.end(),
                    rule="entropy",
                )
            )
    return spans


def high_confidence_hits(text: str) -> list[tuple[str, str]]:
    """(rule name, matched value) for every high-confidence rule hit. Used by the gate."""
    hits: list[tuple[str, str]] = []
    for rule in HIGH_CONFIDENCE_RULES:
        for start, end, value in _iter_rule_matches(rule, text):
            if _inside_placeholder(text, start, end):
                continue
            hits.append((rule.name, value))
    return hits
