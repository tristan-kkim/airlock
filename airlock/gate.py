"""The deterministic gate. It inspects the exact outbound payload and decides allow/block.

No model is consulted here. The gate blocks if any of the following is still present anywhere in
the payload (every JSON string, keys included):

* an original the vault replaced for this request or conversation
* a user-declared sensitive term
* a canary string
* a high-confidence secret or ID pattern (API keys, private keys, JWTs, Korean RRN, ...)

"Present" includes variants. Each string is examined as written, NFKC + casefolded with format
characters removed, compacted (all whitespace and punctuation removed, so "새론 다움물류" matches
"새론다움물류"), and as digit runs where Korean/Hanja/English numerals count as digits. Strings are
also decoded (embedded JSON, percent-encoding, base64/base64url tokens) up to two layers deep and
the decoded text is examined the same way.

It also blocks when the pipeline reports something it could not inspect (e.g. images).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any, Literal

from airlock.detect.patterns import high_confidence_hits
from airlock.detect.spans import normalize, term_pattern
from airlock.textnorm import decoded_layers, fold, fuzzy_find

_SEP = "\n\x00\n"


@dataclass(frozen=True)
class Protected:
    text: str
    type: str
    code: Literal["vault_original", "declared_term", "canary"]


@dataclass
class GateDecision:
    decision: Literal["allow", "block"]
    reasons: list[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    def as_dict(self) -> dict[str, Any]:
        return {"decision": self.decision, "reasons": list(self.reasons)}


def iter_strings(obj: Any) -> Iterator[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from iter_strings(v)
    elif isinstance(obj, list | tuple):
        for v in obj:
            yield from iter_strings(v)
    elif isinstance(obj, int | float) and not isinstance(obj, bool):
        yield str(obj)


def reason(code: str, type_: str, text: str, hasher: Callable[[str], str]) -> str:
    """Reasons carry a short keyed hash, never the sensitive text itself."""
    return f"{code}:{type_}:{hasher(text)[:12]}"


def _present(needle: str, texts: list[str], folded_blob: str, raw_blob: str) -> bool:
    if term_pattern(needle).search(raw_blob):
        return True
    if term_pattern(needle, normalized=True).search(folded_blob):
        return True
    return any(fuzzy_find(t, needle) for t in texts)


def check(
    payload: Any,
    protected: Iterable[Protected],
    *,
    hasher: Callable[[str], str],
    extra_reasons: Iterable[str] = (),
) -> GateDecision:
    strings = list(iter_strings(payload))
    texts = strings + decoded_layers(strings)
    raw_blob = _SEP.join(texts)
    folded_blob = _SEP.join(fold(t) for t in texts)

    reasons: list[str] = list(extra_reasons)
    seen: set[str] = set()
    for item in protected:
        needle = item.text.strip()
        if len(needle) < 2:
            continue
        key = f"{item.code}\x00{normalize(needle)}"
        if key in seen:
            continue
        seen.add(key)
        if _present(needle, texts, folded_blob, raw_blob):
            reasons.append(reason(item.code, item.type, needle, hasher))

    for rule_name, value in high_confidence_hits(raw_blob):
        r = reason("secret_pattern", rule_name, value, hasher)
        if r not in reasons:
            reasons.append(r)

    return GateDecision("block" if reasons else "allow", reasons)
