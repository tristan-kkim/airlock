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


def _words(block: str) -> list[str]:
    return block.split()


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


_PUBLIC_ID_PREFIXES = frozenset(
    _words(
        """
        ISO SHA UTF AES RSA RFC PEP CVE CWE HTTP TLS SSL IEC IEEE DIN MIL GPT COVID SARS DDR
        USB PCI LTE JIS ANSI NIST FIPS OWASP GHSA ASTM ICD NDC IPV ECMA ES KS BS EN RS MP
        ATC HL SOC PCIE WPA WCAG DSM ASC IFRS GAAP IRS FORM
        """
    )
)


def _ticket_ok(value: str) -> bool:
    prefix = value.split("-", 1)[0]
    if prefix in _PUBLIC_ID_PREFIXES:
        return False
    if re.fullmatch(r"[A-Z0-9]{4}", prefix):
        # 4-character mixed prefix (Q5F6-0648): needs a letter, and a year-like prefix is a date
        return bool(re.search(r"[A-Z]", prefix)) and not prefix.isdigit()
    return True


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
        # A wallet recovery phrase: 12 to 24 lower-case words after its name.
        "seed_phrase",
        "SECRET",
        re.compile(
            r"(?:(?:seed|recovery|mnemonic|backup|secret)\s+(?:phrase|words)|mnemonic|"
            r"시드\s*(?:문구|구문)|복구\s*(?:문구|구문)|니모닉)"
            r"[^\n\"'“‘]{0,20}?[\"'“‘]?((?:[a-z]{3,8}\s+){11,23}[a-z]{3,8})(?![a-z])",
            re.IGNORECASE,
        ),
        group=1,
        priority=12,
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
    Rule(
        # 비밀번호 38966240, OTP 030846, 인증번호 5521: a code after the cue, no separator needed.
        "code_after_cue",
        "SECRET",
        re.compile(
            r"(?:비밀번호|패스워드|암호|OTP|인증\s?번호|인증\s?코드|보안\s?코드|PIN|핀\s?번호|"
            r"passcode|passcodes|verification code|security code|door code|gate code|access code|"
            r"one-time code|pin code)"
            r"\s*(?:는|은|가|이|:|=|is|was|번호는)?\s*[\"'“‘]?"
            r"(?P<v>[A-Za-z0-9!@#$%^&*._\-]{3,63}[A-Za-z0-9!@#$%^&*])"
            r"(?!년|월|일|자리|회|번째|개|시간|분|초|원|명|퍼센트|%|자|차|대|층|호|번(?!호)|[A-Za-z0-9])",
            re.IGNORECASE,
        ),
        group=1,
        validator=lambda v: bool(re.search(r"\d", v)) and not re.fullmatch(r"(?:19|20)\d{2}", v),
        priority=13,
    ),
    Rule(
        # https://hooks.slack.com/services/T.../B.../xxx, discord webhooks, /webhook/<token>
        "webhook_url",
        "SECRET",
        re.compile(
            r"https?://(?:[^\s/'\"<>]*hook[^\s/'\"<>]*(/[A-Za-z0-9_\-/.~]{8,})"
            r"|[^\s/'\"<>]+(/(?:api/)?webhook[sb2]*/[A-Za-z0-9_\-/.~]{8,}))",
            re.IGNORECASE,
        ),
        group=-1,
        validator=lambda v: bool(re.search(r"\d", v)) and bool(re.search(r"[A-Za-z]", v)),
        priority=14,
    ),
    Rule(
        # Signed or keyed URL parameters: X-Amz-Signature=..., sig=..., access_token=...
        "signed_url_param",
        "SECRET",
        re.compile(
            r"[?&](?:X-Amz-Signature|X-Amz-Credential|X-Amz-Security-Token|X-Goog-Signature|sig|"
            r"signature|token|access_token|api_key|apikey|key|auth|secret|client_secret)="
            r"([A-Za-z0-9%._~+/\-]{12,})",
            re.IGNORECASE,
        ),
        group=1,
        validator=lambda v: bool(re.search(r"\d", v)) and bool(re.search(r"[A-Za-z]", v)),
        priority=15,
    ),
    # ---- Korean identifiers ----
    Rule(
        "kr_case_number",
        "ID_NUMBER",
        re.compile(
            r"(?<!\d)(?:19|20)\d{2}\s?(?:가합|가단|가소|나|다|고합|고단|고정|노|도|구합|구단|누|두|"
            r"드단|드합|르|머|카합|카단|카기|타경|허|후|형|즈단|즈기|느단|느합|개회|하단|하면|회단|"
            r"회합)\s?\d{2,7}(?!\d)"
        ),
        priority=19,
    ),
    Rule(
        "kr_address",
        "LOCATION",
        re.compile(
            r"(?:(?:서울|부산|대구|인천|광주|대전|울산|세종|경기|강원|충북|충남|충청북도|충청남도|"
            r"전북|전남|전라북도|전라남도|경북|경남|경상북도|경상남도|제주)[가-힣]*\s+)?"
            r"(?:[가-힣]{1,6}(?:시|군|구)\s+){1,3}(?:[가-힣]{1,6}(?:읍|면|동)\s+)?"
            r"(?:[가-힣0-9]{1,12}(?:로|길)\s*\d{1,5}(?:-\d{1,4})?|[가-힣0-9]{1,6}(?:동|리|가)\s+\d{1,5}"
            r"(?:-\d{1,4})?(?:번지)?)"
            r"(?:\s*,?\s*(?:[가-힣A-Za-z0-9]{1,12}\s+)?\d{1,4}\s?동(?:\s*\d{1,5}\s?호)?"
            r"|\s*,?\s*\d{1,5}\s?호)?"
        ),
        priority=25,
    ),
    Rule(
        "street_address",
        "LOCATION",
        re.compile(
            r"(?<![\w-])\d{1,6}\s+(?:[A-Z][a-z'’]+\s+){1,3}(?:Street|St|Lane|Ln|Avenue|Ave|Road|Rd|"
            r"Drive|Dr|Boulevard|Blvd|Way|Court|Ct|Place|Pl|Terrace|Circle|Parkway|Pkwy)\b\.?"
            r"(?:,?\s*(?:Apt|Apartment|Unit|Suite|Ste|#)\.?\s*[\w-]+)?"
        ),
        priority=25,
    ),
    Rule(
        # Ticket, case and document IDs: JIRA-4821, HFS-40418, CV-26-004417, Q5F6-0648.
        "ticket_id",
        "ID_NUMBER",
        re.compile(
            r"(?<![A-Za-z0-9_\-])(?:[A-Z]{2,5}(?:-\d{2})?-\d{3,}|[A-Z0-9]{4}-\d{4})(?![A-Za-z0-9_\-])"
        ),
        validator=lambda v: _ticket_ok(v),
        priority=26,
    ),
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
_URL_RE = re.compile(r"https?://[^\s'\"<>)\]]+")
ENTROPY_MIN_LEN = 24
_ENV_KEY_HEAD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=(?=[^=])")
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
        group = rule.group
        if group == -1:  # the first alternative's group that matched
            group = next((i for i, g in enumerate(m.groups(), start=1) if g), 0)
        value = m.group(group)
        if not value:
            continue
        if rule.validator is not None and not rule.validator(value):
            continue
        yield m.start(group), m.end(group), value


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
    for url in _URL_RE.finditer(text):
        # Tokens inside URL paths (the entropy rule below needs a non-path boundary).
        offset = url.start()
        for seg in re.finditer(r"(?<=/)[A-Za-z0-9_\-]{20,}(?=[/?#]|$)", url.group()):
            token = seg.group()
            start, end = offset + seg.start(), offset + seg.end()
            if _looks_like_secret(token) and not _inside_placeholder(text, start, end):
                spans.append(
                    Span(text=token, type="SECRET", source="entropy", start=start, end=end,
                         rule="url_path_token")  # fmt: skip
                )
    for m in _TOKEN_RE.finditer(text):
        token, start = m.group(0), m.start()
        if (key := _ENV_KEY_HEAD.match(token)) and len(token) - key.end() >= 8:
            # "PAYMENTS_API_KEY=pmk_live_...": the variable name is code the answer needs.
            token, start = token[key.end() :], start + key.end()
        if _looks_like_secret(token) and not _inside_placeholder(text, start, start + len(token)):
            spans.append(
                Span(
                    text=token,
                    type="SECRET",
                    source="entropy",
                    start=start,
                    end=start + len(token),
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
