# /// script
# requires-python = ">=3.11"
# dependencies = ["fastapi>=0.110", "uvicorn>=0.29"]
# ///
"""A deliberately imperfect Airlock mock that implements the HTTP contract with regexes only.

    uv run eval/mock_airlock.py --port 8787 --seed 0

It exists so the harness runs end to end without models or API keys, and so we can show the
harness catches leaks. Nothing is sent anywhere: "outbound" payloads are recorded in the audit
log exactly as a real proxy would send them, and the cloud answer is a canned echo.

Known holes, on purpose:
* names are only caught by a coin-flip "LLM" heuristic (Capitalized Pairs, Korean name + 님/씨)
* phones/cards are only caught in their canonical dashed formats; spaced, split, full-width,
  spelled-out, base64 and percent-encoded forms pass through
* tool-call arguments are never inspected, only message `content`
* health, quasi-identifiers and search intent are not detected at all
* vault terms are replaced case-sensitively; the gate re-checks them case-insensitively
* the detector skips credential URLs, so the gate has something to save
* any 7+ digit number is masked, which over-redacts benign text
Latency numbers in `timings_ms` are simulated, not measured, and mean nothing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import threading
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

REGEX_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("CONTACT", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("CONTACT", re.compile(r"\b01[016789]-\d{3,4}-\d{4}\b")),
    ("CONTACT", re.compile(r"\(\d{3}\) \d{3}-\d{4}")),
    ("ID_NUMBER", re.compile(r"\b\d{6}-[1-4]\d{6}\b")),
    ("ID_NUMBER", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("FINANCIAL", re.compile(r"\b\d{4}-\d{4}-\d{4}-\d{4}\b")),
    ("SECRET", re.compile(r"\b[a-z]{2,6}_(?:live|test|prod)_[A-Za-z0-9]{12,}")),
    ("SECRET", re.compile(r"(?i)password\s*[:=]\s*\S{6,}")),
    ("ID_NUMBER", re.compile(r"\b\d{7,}\b")),  # over-eager on purpose
]
EN_PAIR = re.compile(r"\b[A-Z][a-z]+ [A-Z][a-z]+(?:-[A-Z][a-z]+)?\b")
KO_NAME = re.compile(r"[김이박최정강조윤장임한오서신권황안송류홍][가-힣]{2}(?=\s?(?:님|씨))")
CREDENTIAL_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s@/]+)@")
PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class MockAirlock:
    def __init__(self, seed: int = 0, llm_recall: float = 0.7):
        self.rng = random.Random(seed)
        self.llm_recall = llm_recall
        self.vault: list[str] = []
        self.audit: dict[str, dict[str, Any]] = {}
        self.lock = threading.Lock()

    # -- detection ---------------------------------------------------------------------------

    def detect(self, text: str) -> list[dict[str, Any]]:
        spans: list[dict[str, Any]] = []
        for term in self.vault:
            for m in re.finditer(re.escape(term), text):  # case-sensitive: a deliberate hole
                spans.append({"start": m.start(), "end": m.end(), "type": "ORG", "source": "vault"})
        for type_, pattern in REGEX_RULES:
            for m in pattern.finditer(text):
                spans.append({"start": m.start(), "end": m.end(), "type": type_, "source": "regex"})
        for pattern in (EN_PAIR, KO_NAME):
            for m in pattern.finditer(text):
                if self.rng.random() < self.llm_recall:
                    spans.append(
                        {"start": m.start(), "end": m.end(), "type": "PERSON", "source": "llm"}
                    )
        spans.sort(key=lambda s: (-(s["end"] - s["start"]), s["start"]))
        chosen: list[dict[str, Any]] = []
        for s in spans:
            if all(s["end"] <= c["start"] or s["start"] >= c["end"] for c in chosen):
                chosen.append(s)
        return sorted(chosen, key=lambda s: s["start"])

    def mask_text(
        self, text: str, mapping: dict[str, str], detections: list[dict[str, Any]]
    ) -> str:
        out, pos = [], 0
        counters: dict[str, int] = {}
        for s in self.detect(text):
            original = text[s["start"] : s["end"]]
            if original not in mapping:
                counters[s["type"]] = (
                    sum(1 for k in mapping.values() if k.startswith(f"[[{s['type']}_")) + 1
                )
                mapping[original] = f"[[{s['type']}_{counters[s['type']]}]]"
            detections.append(
                {
                    "text_sha256": sha256(original),
                    "type": s["type"],
                    "action": "mask",
                    "source": s["source"],
                }
            )
            out.append(text[pos : s["start"]])
            out.append(mapping[original])
            pos = s["end"]
        out.append(text[pos:])
        return "".join(out)

    def sanitize_messages(self, messages: list[dict[str, Any]], mapping, detections):
        clean = []
        for msg in messages:
            msg = dict(msg)
            if isinstance(msg.get("content"), str):
                msg["content"] = self.mask_text(msg["content"], mapping, detections)
            clean.append(msg)  # tool_calls arguments pass through untouched (deliberate hole)
        return clean

    # -- gate --------------------------------------------------------------------------------

    def gate(self, payload: Any) -> dict[str, Any]:
        blob = json.dumps(payload, ensure_ascii=False)
        folded = blob.casefold()
        reasons = []
        for term in self.vault:
            if term.casefold() in folded:
                reasons.append(f"declared_term:ORG:{sha256(term)[:12]}")
        for m in CREDENTIAL_URL.finditer(blob):
            reasons.append(f"secret_pattern:credential_url:{sha256(m.group(1))[:12]}")
        if PRIVATE_KEY.search(blob):
            reasons.append("secret_pattern:private_key:redacted")
        return {"decision": "block" if reasons else "allow", "reasons": reasons}

    # -- records -----------------------------------------------------------------------------

    def new_record(self, kind: str, protection_level: str | None) -> dict[str, Any]:
        return {
            "request_id": "req_" + uuid.UUID(int=self.rng.getrandbits(128)).hex[:20],
            "created_at": datetime.now(UTC).isoformat(),
            "kind": kind,
            "protection_level": protection_level,
            "detections": [],
            "outbound": [],
            "gate": {"decision": "block", "reasons": ["not_evaluated"]},
            "timings_ms": {},
        }

    def save(self, record: dict[str, Any], t0: float, remote_ms: float, remote_key: str) -> None:
        local = (time.perf_counter() - t0) * 1000
        record["timings_ms"] = {
            "detect": round(local * 0.8 + self.rng.uniform(40, 120), 2),  # simulated local model
            "gate": round(local * 0.2, 2),
            remote_key: round(remote_ms, 2),
        }
        record["timings_ms"]["total"] = round(sum(record["timings_ms"].values()), 2)
        with self.lock:
            self.audit[record["request_id"]] = record


def rehydrate(text: str, mapping: dict[str, str]) -> str:
    for original, placeholder in mapping.items():
        text = text.replace(placeholder, original)
    return text


def blocked(record: dict[str, Any]) -> JSONResponse:
    return JSONResponse(
        {
            "error": {
                "type": "airlock_blocked",
                "reasons": record["gate"]["reasons"],
                "request_id": record["request_id"],
            }
        },
        status_code=422,
        headers={"x-airlock-request-id": record["request_id"]},
    )


def create_app(seed: int = 0, llm_recall: float = 0.7) -> FastAPI:
    app = FastAPI(title="Airlock mock (eval only)")
    mock = MockAirlock(seed, llm_recall)
    app.state.mock = mock

    @app.get("/healthz")
    async def healthz():
        return {"ok": True, "mock": True, "protection_level": "mock"}

    @app.post("/vault/terms")
    async def vault_terms(body: dict[str, Any]):
        added = 0
        for term in body.get("terms") or []:
            if isinstance(term, str) and term.strip() and term not in mock.vault:
                mock.vault.append(term)
                added += 1
        mock.vault.sort(key=len, reverse=True)
        return {"added": added, "total": len(mock.vault)}

    @app.post("/v1/chat/completions")
    async def chat(request: Request):
        t0 = time.perf_counter()
        body = await request.json()
        record = mock.new_record("chat", request.headers.get("x-airlock-protection-level"))
        mapping: dict[str, str] = {}
        messages = mock.sanitize_messages(body.get("messages") or [], mapping, record["detections"])
        payload = {"model": "nemotron-3-ultra (mock)", "messages": messages}
        record["gate"] = mock.gate(payload)
        if record["gate"]["decision"] == "block":
            mock.save(record, t0, 0.0, "upstream")
            return blocked(record)
        record["outbound"].append(
            {"destination": "upstream", "payload": json.loads(json.dumps(payload))}
        )
        last_user = next(
            (m.get("content") or "" for m in reversed(messages) if m.get("role") == "user"), ""
        )
        answer = f"(mock answer) You asked: {str(last_user)[:160]}"
        mock.save(record, t0, mock.rng.uniform(600, 1800), "upstream")
        response = {
            "id": "chatcmpl-" + record["request_id"],
            "object": "chat.completion",
            "created": int(time.time()),
            "model": "airlock-mock",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": rehydrate(answer, mapping)},
                }
            ],
        }
        return JSONResponse(response, headers={"x-airlock-request-id": record["request_id"]})

    @app.post("/v1/search")
    async def search(request: Request):
        t0 = time.perf_counter()
        body = await request.json()
        record = mock.new_record("search", request.headers.get("x-airlock-protection-level"))
        mapping: dict[str, str] = {}
        query = mock.mask_text(body.get("query") or "", mapping, record["detections"])
        mock.mask_text(body.get("context") or "", mapping, record["detections"])  # local use only
        payload = {
            "query": query,
            "max_results": int(body.get("max_results") or 5),
            "search_depth": "basic",
        }
        record["gate"] = mock.gate(payload)
        if record["gate"]["decision"] == "block":
            mock.save(record, t0, 0.0, "tavily")
            return blocked(record)
        record["outbound"].append({"destination": "tavily", "payload": payload})
        results = [
            {
                "title": f"Result {i + 1} for {query[:40]}",
                "url": f"https://example.com/r/{i + 1}",
                "content": "Synthetic mock search result.",
            }
            for i in range(payload["max_results"])
        ]
        mock.save(record, t0, mock.rng.uniform(300, 900), "tavily")
        return JSONResponse(
            {
                "request_id": record["request_id"],
                "outbound_query": query,
                "results": results,
                "answer": rehydrate(f"(mock answer) Top results for: {query}", mapping),
            },
            headers={"x-airlock-request-id": record["request_id"]},
        )

    @app.get("/audit/{request_id}")
    async def audit(request_id: str):
        record = mock.audit.get(request_id)
        if record is None:
            return JSONResponse({"error": {"type": "not_found"}}, status_code=404)
        return record

    return app


def main() -> None:
    import uvicorn

    ap = argparse.ArgumentParser(description="Imperfect Airlock mock for the eval harness")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument(
        "--llm-recall",
        type=float,
        default=0.7,
        help="probability the simulated LLM catches a name candidate",
    )
    args = ap.parse_args()
    uvicorn.run(
        create_app(args.seed, args.llm_recall), host=args.host, port=args.port, log_level="warning"
    )


if __name__ == "__main__":
    main()
