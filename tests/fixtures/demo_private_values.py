"""Private values each demo preset declares, and the check that none of them left the server.

Used twice: by `scripts/demo/record_presets.py`, which verifies every live run's full audit before
accepting it as a recording, and by `tests/test_demo_recordings.py`, which scans the committed
recordings. All values are the fictional ones in `airlock/demo/presets.py`.

A value matches case-insensitively after NFKC normalization. Between two digits any single space,
hyphen or dot is optional ("010-5555-0142" also finds "01055550142"). A value that starts or ends
with a letter or digit must not touch another Latin letter or digit on that side ("Tom" does not
match "custom"); Hangul values match anywhere, since Korean particles attach to the name.

Deliberately NOT declared, because the preset's purpose needs them in the cloud and the policy
keeps them: the diagnosis in chat-medical-en, the rent amount and the bank name in chat-rent-ko,
and the dates and severance terms in agent-resignation-ko.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Iterator
from typing import Any

PRIVATE_VALUES: dict[str, tuple[str, ...]] = {
    "chat-medical-en": (
        # names, contacts, organization
        "Jane Park", "Jane", "Park", "Tom Reyes", "Tom", "Reyes",
        "jane.park@example.com", "jane.park", "010-5555-0142",
        "Hanbit Clinic", "Hanbit",
        # quasi-identifier: exact age (coarsened to a decade)
        "34",
    ),
    "chat-rent-ko": (
        "김민수", "이영희",
        "900101-1234567", "900101", "1234567",
        "110-234-567890",
    ),
    "chat-secrets-en": (
        "postgres://admin:hunter22@db.internal:5432/prod",
        "admin:hunter22", "hunter22",
        "sk-proj-Zx8Qw3Er5Ty7Ui9Op1As2Df4Gh6Jk", "Zx8Qw3Er5Ty7Ui9Op1As2Df4Gh6Jk",
    ),
    "search-layoff-en": (
        "Minji Lee", "Minji",
        "Seoul Mirae Bank", "Seoul Mirae", "Mirae",
        "20231187",
        # quasi-identifier: exact job title
        "senior analyst",
    ),
    "agent-resignation-ko": (
        "박성훈", "Park Sung-hoon", "Sunghoon", "Sung-hoon", "Seonghun", "Seong-hun",
        "DN-19044", "19044",
        "동해누리정밀", "동해누리", "Donghae Nuri",
        # quasi-identifiers: exact team names
        "품질보증팀", "생산기술팀",
    ),
}  # fmt: skip

# Every inner tuple must match somewhere in the answer (search: result titles and snippets);
# any one alternative in a tuple is enough.
ANSWER_KEYWORDS: dict[str, tuple[tuple[str, ...], ...]] = {
    "chat-medical-en": (("flexib",), ("hours", "schedule")),
    "chat-rent-ko": (("월세",),),
    "chat-secrets-en": (("database", "postgres"), ("connect",)),
    "search-layoff-en": (("severance", "layoff", "terminat", "eliminat"),),
    "agent-resignation-ko": (("실업급여",), ("위로금", "합의서")),
}

# Fields of a recording that are not outbound: the visitor's own input, the rehydrated answer
# (which is meant to show the real values again) and inbound web results.
NOT_OUTBOUND = frozenset({"typed", "answer", "results"})

PLACEHOLDER = re.compile(r"<[A-Z][A-Z_]*_\d+>")


def _norm(text: str) -> str:
    return unicodedata.normalize("NFKC", text).casefold()


def _pattern(value: str) -> re.Pattern[str]:
    v = re.sub(r"(?<=\d)[\s.\-](?=\d)", "", _norm(value))
    parts: list[str] = []
    for i, ch in enumerate(v):
        if ch.isspace():
            parts.append(r"\s+")
            continue
        if i and v[i - 1].isdigit() and ch.isdigit():
            parts.append(r"[\s.\-]?")
        parts.append(re.escape(ch))
    body = "".join(parts)
    edge = r"[0-9a-z]"
    if re.match(edge, v[0]):
        body = f"(?<!{edge})" + body
    if re.match(edge, v[-1]):
        body += f"(?!{edge})"
    return re.compile(body)


def strings(value: Any) -> Iterator[str]:
    """Every string in a JSON value, keys included."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from strings(v)
    elif isinstance(value, list | tuple):
        for v in value:
            yield from strings(v)


def find_private_values(payloads: Iterable[Any], preset_id: str) -> list[str]:
    """Declared private values of `preset_id` found in any string of `payloads`."""
    texts = [_norm(s) for p in payloads for s in strings(p)]
    return [
        value
        for value in PRIVATE_VALUES[preset_id]
        if any(_pattern(value).search(t) for t in texts)
    ]


def recording_outbound(recording: dict[str, Any]) -> dict[str, Any]:
    """The parts of a recording that describe what left the server (cloud_saw, gate, stats…)."""
    return {k: v for k, v in recording.items() if k not in NOT_OUTBOUND}


def answer_problems(recording: dict[str, Any]) -> list[str]:
    """Why a recording's answer is unusable: empty, off-topic or with leftover placeholders."""
    preset_id = recording["preset_id"]
    if recording.get("mode") == "search":
        text = "\n".join(
            f"{r.get('title') or ''}\n{r.get('snippet') or ''}"
            for r in recording.get("results") or []
        )
    else:
        text = recording.get("answer") or ""
    if not text.strip():
        return ["empty answer"]
    problems = []
    low = _norm(text)
    for group in ANSWER_KEYWORDS[preset_id]:
        if not any(_norm(k) in low for k in group):
            problems.append(f"off-topic: none of {list(group)}")
    if recording.get("mode") != "search" and PLACEHOLDER.search(text):
        problems.append("placeholder left in answer")
    return problems
