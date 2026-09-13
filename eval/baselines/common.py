"""Eval baseline server: the Airlock HTTP subset the harness uses, with a pluggable masker.

A baseline never calls a cloud service. It records the payload it WOULD send upstream (chat) or to
the search API (search) in an audit record shaped like Airlock's, and answers with a stub. The
harness then scans those payloads exactly as it scans Airlock's, so leak numbers are comparable.

Endpoints: GET /healthz, POST /v1/chat/completions, POST /v1/search, GET /audit/{id},
POST /vault/terms, DELETE /vault/terms, POST /vault/reset.

What every masking baseline gets, so the comparison is about the detector and not the plumbing:
* every string a chat request carries in `messages` is masked: `content` (string or text parts) and
  tool-call `arguments` (JSON arguments are decoded, masked leaf by leaf and re-encoded)
* declared vault terms are masked case-insensitively, with no word boundary (Korean particles)
* the search `context` stays local, only the masked `query` is recorded as outbound (as in Airlock)
* detections are cached per (text, language): every detector here is deterministic
No baseline has a gate, placeholder rehydration or quasi-identifier generalization.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

UPSTREAM_MODEL = "nvidia/Nemotron-3-Ultra-550b-a55b"
_HANGUL = re.compile("[\u1100-\u11ff\u3130-\u318f\uac00-\ud7a3]")


@dataclass
class Span:
    start: int
    end: int
    type: str
    source: str
    score: float | None = None


class Detector(Protocol):
    """Finds sensitive spans in one text segment of a known language ("ko" or "en").

    A detector may also define `anonymize(text, spans) -> str` to apply its own replacement
    engine; otherwise spans become numbered `<TYPE_N>` placeholders.
    """

    name: str

    def detect(self, text: str, lang: str) -> list[Span]: ...


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def guess_lang(text: str) -> str:
    return "ko" if _HANGUL.search(text) else "en"


def language_segments(text: str) -> list[tuple[int, str, str]]:
    """Split text into runs of lines with the same language: (offset, segment, lang).

    A Korean prompt that pastes an English config gets its code lines routed to the English
    pipeline and its prose to the Korean one. Newlines stay inside segments, offsets are exact.
    """
    out: list[tuple[int, str, str]] = []
    pos = 0
    for line in text.splitlines(keepends=True):
        lang = guess_lang(line) if line.strip() else (out[-1][2] if out else "en")
        if out and out[-1][2] == lang:
            start, seg, _ = out[-1]
            out[-1] = (start, seg + line, lang)
        else:
            out.append((pos, line, lang))
        pos += len(line)
    return out


def term_spans(text: str, terms: list[str]) -> list[Span]:
    spans = []
    for term in terms:
        for m in re.finditer(re.escape(term), text, flags=re.IGNORECASE):
            spans.append(Span(m.start(), m.end(), "DECLARED_TERM", "vault"))
    return spans


def resolve_overlaps(spans: list[Span]) -> list[Span]:
    """Longest span wins; ties go to the earlier start, then the higher score."""
    ordered = sorted(spans, key=lambda s: (-(s.end - s.start), s.start, -(s.score or 0.0)))
    chosen: list[Span] = []
    for s in ordered:
        if s.end > s.start and all(s.end <= c.start or s.start >= c.end for c in chosen):
            chosen.append(s)
    return sorted(chosen, key=lambda s: s.start)


def _detection(original: str, span: Span) -> dict[str, Any]:
    return {
        "text_sha256": sha256(original),
        "type": span.type,
        "action": "mask",
        "source": span.source,
        "score": span.score,
    }


@dataclass
class Masker:
    """Applies a detector plus declared terms to text; spans become <TYPE_N> placeholders."""

    detector: Detector | None
    honor_vault_terms: bool = True
    terms: list[str] = field(default_factory=list)
    _cache: dict[tuple[str, str], list[Span]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def spans(self, text: str) -> list[Span]:
        found: list[Span] = []
        if self.detector is not None:
            for offset, seg, lang in language_segments(text):
                key = (seg, lang)
                with self._lock:
                    cached = self._cache.get(key)
                if cached is None:
                    cached = self.detector.detect(seg, lang)
                    with self._lock:
                        self._cache[key] = cached
                found.extend(
                    Span(s.start + offset, s.end + offset, s.type, s.source, s.score)
                    for s in cached
                )
        if self.honor_vault_terms:
            found.extend(term_spans(text, self.terms))
        return resolve_overlaps(found)

    def mask(self, text: str, mapping: dict[str, str], detections: list[dict[str, Any]]) -> str:
        spans = [s for s in self.spans(text) if text[s.start : s.end].strip()]
        anonymize = getattr(self.detector, "anonymize", None)
        if anonymize is not None:
            # The detector brings its own replacement engine (Presidio's AnonymizerEngine).
            for s in spans:
                detections.append(_detection(text[s.start : s.end], s))
            return anonymize(text, spans) if spans else text
        out, pos = [], 0
        for s in spans:
            original = text[s.start : s.end]
            if original not in mapping:
                n = sum(1 for v in mapping.values() if v.startswith(f"<{s.type}_")) + 1
                mapping[original] = f"<{s.type}_{n}>"
            detections.append(_detection(original, s))
            out.append(text[pos : s.start])
            out.append(mapping[original])
            pos = s.end
        out.append(text[pos:])
        return "".join(out)

    def mask_json_leaves(self, obj: Any, mapping, detections) -> Any:
        if isinstance(obj, str):
            return self.mask(obj, mapping, detections)
        if isinstance(obj, list):
            return [self.mask_json_leaves(v, mapping, detections) for v in obj]
        if isinstance(obj, dict):
            return {k: self.mask_json_leaves(v, mapping, detections) for k, v in obj.items()}
        return obj

    def mask_arguments(self, arguments: Any, mapping, detections) -> Any:
        if not isinstance(arguments, str):
            return self.mask_json_leaves(arguments, mapping, detections)
        try:
            decoded = json.loads(arguments)
        except ValueError:
            return self.mask(arguments, mapping, detections)
        masked = self.mask_json_leaves(decoded, mapping, detections)
        return json.dumps(masked, ensure_ascii=False)

    def mask_messages(self, messages: list[Any], mapping, detections) -> list[Any]:
        clean = []
        for msg in messages:
            if not isinstance(msg, dict):
                clean.append(msg)
                continue
            msg = json.loads(json.dumps(msg))
            content = msg.get("content")
            if isinstance(content, str):
                msg["content"] = self.mask(content, mapping, detections)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        part["text"] = self.mask(part["text"], mapping, detections)
            for call in msg.get("tool_calls") or []:
                fn = call.get("function") if isinstance(call, dict) else None
                if isinstance(fn, dict) and "arguments" in fn:
                    fn["arguments"] = self.mask_arguments(fn["arguments"], mapping, detections)
            clean.append(msg)
        return clean


def _record(kind: str, baseline: str) -> dict[str, Any]:
    return {
        "request_id": "req_" + uuid.uuid4().hex[:20],
        "created_at": datetime.now(UTC).isoformat(),
        "kind": kind,
        "protection_level": None,
        "detections": [],
        "outbound": [],
        "gate": {"decision": "allow", "reasons": []},
        "timings_ms": {},
        "meta": {"baseline": baseline, "cloud_called": False},
    }


def _error(status: int, type_: str, message: str) -> JSONResponse:
    return JSONResponse({"error": {"type": type_, "message": message}}, status_code=status)


def create_app(
    name: str,
    detector: Detector | None,
    *,
    honor_vault_terms: bool = True,
    description: str = "",
    info: dict[str, Any] | None = None,
) -> FastAPI:
    app = FastAPI(title=f"Airlock eval baseline: {name}")
    masker = Masker(detector, honor_vault_terms=honor_vault_terms)
    audit: dict[str, dict[str, Any]] = {}
    lock = threading.Lock()
    app.state.masker = masker
    app.state.audit = audit

    def save(record: dict[str, Any], t0: float, detect_ms: float) -> None:
        total = (time.perf_counter() - t0) * 1000
        record["timings_ms"] = {"detect": round(detect_ms, 2), "total": round(total, 2)}
        with lock:
            audit[record["request_id"]] = record

    @app.get("/healthz")
    async def healthz():
        return {
            "status": "ok",
            "baseline": name,
            "protection_level": f"baseline:{name}",
            "description": description,
            "cloud_calls": False,
            **(info or {}),
        }

    @app.post("/vault/terms")
    async def add_terms(request: Request):
        body = await request.json()
        added = 0
        for term in (body or {}).get("terms") or []:
            if isinstance(term, str) and term.strip() and term not in masker.terms:
                masker.terms.append(term)
                added += 1
        masker.terms.sort(key=len, reverse=True)
        return {"added": added, "total": len(masker.terms), "kind": body.get("kind", "sensitive")}

    @app.delete("/vault/terms")
    async def delete_terms(request: Request):
        body = await request.json()
        drop = set((body or {}).get("terms") or [])
        before = len(masker.terms)
        masker.terms[:] = [t for t in masker.terms if t not in drop]
        return {"removed": before - len(masker.terms), "total": len(masker.terms)}

    @app.post("/vault/reset")
    async def reset():
        removed = len(masker.terms)
        masker.terms.clear()
        return {"reset": True, "terms_removed": removed}

    @app.post("/v1/chat/completions")
    async def chat(request: Request):
        t0 = time.perf_counter()
        try:
            body = await request.json()
        except ValueError:
            return _error(400, "invalid_request_error", "body must be JSON")
        if not isinstance(body, dict) or not isinstance(body.get("messages"), list):
            return _error(400, "invalid_request_error", "messages must be a list")
        record = _record("chat", name)
        mapping: dict[str, str] = {}
        d0 = time.perf_counter()
        messages = masker.mask_messages(body["messages"], mapping, record["detections"])
        detect_ms = (time.perf_counter() - d0) * 1000
        payload = {**body, "model": UPSTREAM_MODEL, "messages": messages}
        record["outbound"].append({"destination": "upstream", "payload": payload})
        save(record, t0, detect_ms)
        response = {
            "id": "chatcmpl-" + record["request_id"],
            "object": "chat.completion",
            "created": int(time.time()),
            "model": f"baseline-{name}",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {
                        "role": "assistant",
                        "content": f"(baseline {name}: stub answer, no cloud call was made)",
                    },
                }
            ],
        }
        return JSONResponse(response, headers={"x-airlock-request-id": record["request_id"]})

    @app.post("/v1/search")
    async def search(request: Request):
        t0 = time.perf_counter()
        try:
            body = await request.json()
        except ValueError:
            return _error(400, "invalid_request_error", "body must be JSON")
        if not isinstance(body, dict) or not isinstance(body.get("query"), str):
            return _error(400, "invalid_request_error", "query must be a string")
        record = _record("search", name)
        mapping: dict[str, str] = {}
        d0 = time.perf_counter()
        query = masker.mask(body["query"], mapping, record["detections"])
        detect_ms = (time.perf_counter() - d0) * 1000
        max_results = max(1, min(int(body.get("max_results") or 5), 20))
        payload = {"query": query, "max_results": max_results, "search_depth": "basic"}
        record["outbound"].append({"destination": "tavily", "payload": payload})
        save(record, t0, detect_ms)
        return JSONResponse(
            {
                "request_id": record["request_id"],
                "outbound_query": query,
                "results": [],
                "answer": f"(baseline {name}: stub answer, no search call was made)",
            },
            headers={"x-airlock-request-id": record["request_id"]},
        )

    @app.get("/audit/{request_id}")
    async def get_audit(request_id: str):
        record = audit.get(request_id)
        if record is None:
            return _error(404, "not_found", "no audit record with that id")
        return record

    return app


def serve(build: Callable[[], FastAPI], default_port: int, description: str) -> None:
    import uvicorn

    ap = argparse.ArgumentParser(description=description)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=default_port)
    args = ap.parse_args()
    uvicorn.run(build(), host=args.host, port=args.port, log_level="warning")
