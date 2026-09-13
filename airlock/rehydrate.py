"""Map placeholders and surrogates in upstream responses back to the local originals.

Placeholder matching is lenient about brackets and case (see `airlock.placeholders`), but only
keys that exist in this conversation's vault are replaced, so `List<T_1>` or a stray `[x]` is
untouched. Surrogates (`AIRLOCK_SUBSTITUTION=surrogate`) are found as written or reformatted, and
the Korean particle after a restored value is corrected (`airlock.surrogate.rehydrate`).
"""

from __future__ import annotations

import copy
import json
from typing import Any

from airlock import placeholders, surrogate
from airlock.vault import VaultSession


def rehydrate_text(text: str, session: VaultSession, *, json_escape: bool = False) -> str:
    transform = (lambda s: json.dumps(s, ensure_ascii=False)[1:-1]) if json_escape else str
    out = placeholders.rehydrate(text, session.original_for, transform)
    pairs = session.surrogate_pairs()
    return surrogate.rehydrate(out, pairs, transform) if pairs else out


def _walk(obj: Any, session: VaultSession) -> Any:
    if isinstance(obj, str):
        return rehydrate_text(obj, session)
    if isinstance(obj, list):
        return [_walk(v, session) for v in obj]
    if isinstance(obj, dict):
        return {k: _walk(v, session) for k, v in obj.items()}
    return obj


def rehydrate_arguments(arguments: str, session: VaultSession) -> str:
    """Tool-call arguments are a JSON string: rehydrate values without breaking the JSON."""
    try:
        parsed = json.loads(arguments)
    except (json.JSONDecodeError, TypeError):
        return rehydrate_text(arguments, session, json_escape=True)
    return json.dumps(_walk(parsed, session), ensure_ascii=False)


REASONING_FIELDS = ("reasoning_content", "reasoning")


def _rehydrate_message(
    msg: dict[str, Any], session: VaultSession, *, include_reasoning: bool = False
) -> None:
    for key in REASONING_FIELDS:
        if not include_reasoning:
            msg.pop(key, None)
    for key in ("content", "refusal", *REASONING_FIELDS):
        value = msg.get(key)
        if isinstance(value, str):
            msg[key] = rehydrate_text(value, session)
        elif isinstance(value, list):
            msg[key] = _walk(value, session)
    if isinstance(msg.get("content"), str):
        # Some models (e.g. Nemotron 3 Super) prefix the answer with blank lines.
        msg["content"] = msg["content"].lstrip()
    for call in msg.get("tool_calls") or []:
        fn = call.get("function") if isinstance(call, dict) else None
        if isinstance(fn, dict) and isinstance(fn.get("arguments"), str):
            fn["arguments"] = rehydrate_arguments(fn["arguments"], session)
    fc = msg.get("function_call")
    if isinstance(fc, dict) and isinstance(fc.get("arguments"), str):
        fc["arguments"] = rehydrate_arguments(fc["arguments"], session)


class StreamRehydrator:
    """Rehydrates a text stream whose chunks may split a placeholder ("<PER" + "SON_1>").

    Text is released as soon as it cannot be the start of a placeholder; a possible partial
    placeholder at the end of the buffer is held back until the next chunk decides it.
    """

    def __init__(self, session: VaultSession, max_hold: int = 64):
        self.session = session
        self.max_hold = max_hold
        self.buffer = ""

    def feed(self, text: str) -> str:
        self.buffer += text
        buf = self.buffer
        cut = len(buf)
        for i in range(max(0, len(buf) - self.max_hold), len(buf)):
            if buf[i] in placeholders.OPENER_CHARS and placeholders.PARTIAL_RE.fullmatch(buf, i):
                cut = i
                break
        surrogates = [s for s, _, _ in self.session.surrogate_pairs()]
        if surrogates:
            # A surrogate split across chunks, or one whose particle has not arrived yet.
            cut = min(cut, len(buf) - surrogate.pending_tail(buf, surrogates))
        ready, self.buffer = buf[:cut], buf[cut:]
        return rehydrate_text(ready, self.session)

    def flush(self) -> str:
        ready, self.buffer = self.buffer, ""
        return rehydrate_text(ready, self.session)


def rehydrate_response(
    response: dict[str, Any], session: VaultSession, *, include_reasoning: bool = False
) -> dict[str, Any]:
    out = copy.deepcopy(response)
    for choice in out.get("choices") or []:
        if not isinstance(choice, dict):
            continue
        if isinstance(choice.get("message"), dict):
            _rehydrate_message(choice["message"], session, include_reasoning=include_reasoning)
    return out
