"""FastAPI app: OpenAI-compatible chat proxy, private search, audit, vault terms, demo UI."""

from __future__ import annotations

import json
import secrets
import time
from collections import OrderedDict
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from importlib import resources
from typing import Any, Literal

import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from airlock import __version__, gate
from airlock.agent_settings import AgentSettings
from airlock.audit import AuditLog, AuditRecord
from airlock.config import ReviewMode, Settings, load_settings
from airlock.detect.llm import LLMDetector, LocalModel, LocalModelError, block_reason
from airlock.detect.spans import Span, normalize
from airlock.hashing import Hasher, hasher_for
from airlock.pipeline import ChatAnalysis, PayloadError, Sanitizer, conversation_id_for
from airlock.rehydrate import (
    REASONING_FIELDS,
    StreamRehydrator,
    rehydrate_arguments,
    rehydrate_response,
)
from airlock.search import PrivateSearch, SearchBlocked, SearchNotConfigured, Tavily, TavilyError
from airlock.upstream import Upstream, UpstreamError
from airlock.vault import Vault, VaultSession

REQUEST_ID_HEADER = "x-airlock-request-id"
CONVERSATION_HEADER = "x-airlock-conversation-id"
# Opt-in: forward the model's reasoning_content to the client (rehydrated). Off by default.
REASONING_HEADER = "x-airlock-include-reasoning"
# "required": stop before sending and return proposed redactions (HTTP 409) for confirmation.
REVIEW_HEADER = "x-airlock-review"


@dataclass
class PendingReview:
    """A request waiting for the user's decision. In memory only; holds the raw body."""

    body: dict[str, Any]
    conversation_id: str
    analysis: ChatAnalysis
    proposals: list[dict[str, Any]]
    include_reasoning: bool
    created: float = field(default_factory=time.monotonic)


class ReviewStore:
    def __init__(self, ttl_s: float, max_items: int = 256):
        self.ttl_s = ttl_s
        self.max_items = max_items
        self._items: OrderedDict[str, PendingReview] = OrderedDict()

    def _expire(self) -> None:
        now = time.monotonic()
        for key in [k for k, v in self._items.items() if now - v.created > self.ttl_s]:
            del self._items[key]

    def put(self, pending: PendingReview) -> str:
        self._expire()
        review_id = "rev_" + secrets.token_hex(12)
        self._items[review_id] = pending
        while len(self._items) > self.max_items:
            self._items.popitem(last=False)
        return review_id

    def get(self, review_id: str) -> PendingReview | None:
        self._expire()
        return self._items.get(review_id)

    def pop(self, review_id: str) -> PendingReview | None:
        self._expire()
        return self._items.pop(review_id, None)

    def clear(self) -> int:
        n = len(self._items)
        self._items.clear()
        return n


@dataclass
class Services:
    settings: Settings
    http: httpx.AsyncClient
    vault: Vault
    audit: AuditLog
    local: LocalModel
    sanitizer: Sanitizer
    upstream: Upstream
    search: PrivateSearch
    hasher: Hasher
    reviews: ReviewStore

    async def aclose(self) -> None:
        await self.http.aclose()
        self.vault.close()
        self.audit.close()


def build_services(
    settings: Settings, transport: httpx.AsyncBaseTransport | None = None
) -> Services:
    http = httpx.AsyncClient(transport=transport, follow_redirects=False)
    vault = Vault(settings.vault_path)
    audit = AuditLog(settings.audit_db)
    local = LocalModel(settings, http)
    detector = LLMDetector(local, settings.protection_level)
    sanitizer = Sanitizer(settings, detector, vault)
    upstream = Upstream(settings, http)
    hasher = hasher_for(settings)
    search = PrivateSearch(settings, local, sanitizer, Tavily(settings, http), hasher)
    reviews = ReviewStore(settings.review_ttl_s)
    return Services(
        settings, http, vault, audit, local, sanitizer, upstream, search, hasher, reviews
    )


class SearchRequest(BaseModel):
    query: str = Field(min_length=1, max_length=2000)
    context: str | None = Field(default=None, max_length=20000)
    max_results: int = Field(default=5, ge=1, le=20)


class TermsDeleteRequest(BaseModel):
    terms: list[str] = Field(min_length=1, max_length=500)
    kind: Literal["sensitive", "canary"] | None = None


class ReviewAddition(BaseModel):
    text: str = Field(min_length=2, max_length=500)
    type: str = Field(default="PERSON", pattern=r"^[A-Z][A-Z_]{1,30}$")


class ReviewDecision(BaseModel):
    approve: list[str] = Field(default_factory=list, max_length=500)
    reject: list[str] = Field(default_factory=list, max_length=500)
    add: list[ReviewAddition] = Field(default_factory=list, max_length=100)


class TermsRequest(BaseModel):
    terms: list[str] = Field(min_length=1, max_length=500)
    # Omitted: inferred per term (ORG, PROJECT, PERSON or TERM; airlock.detect.term_type).
    type: str | None = Field(default=None, pattern=r"^[A-Z][A-Z_]{1,30}$")
    kind: Literal["sensitive", "canary"] = "sensitive"


def _error(status: int, type_: str, message: str, request_id: str | None = None, **extra: Any):
    body: dict[str, Any] = {"error": {"type": type_, "message": message, **extra}}
    if request_id:
        body["error"]["request_id"] = request_id
    headers = {REQUEST_ID_HEADER: request_id} if request_id else None
    return JSONResponse(body, status_code=status, headers=headers)


def _blocked(record: AuditRecord, reasons: list[str]) -> JSONResponse:
    return JSONResponse(
        {"error": {"type": "airlock_blocked", "reasons": reasons, "request_id": record.request_id}},
        status_code=422,
        headers={REQUEST_ID_HEADER: record.request_id},
    )


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


async def relay_stream(
    upstream: httpx.Response,
    session: VaultSession,
    *,
    include_reasoning: bool,
    on_done: Callable[[], None],
) -> AsyncIterator[str]:
    """Relay upstream SSE chunks, rehydrating text deltas without splitting placeholders.

    Text deltas pass through a StreamRehydrator per (choice, field). Tool-call deltas are
    buffered and emitted once, fully rehydrated, with the finishing chunk: their arguments are
    JSON and cannot be rehydrated safely piece by piece.
    """
    text_fields = ("content", "refusal", *(REASONING_FIELDS if include_reasoning else ()))
    rehydrators: dict[tuple[int, str], StreamRehydrator] = {}
    tool_calls: dict[int, dict[int, dict[str, Any]]] = {}
    started: set[int] = set()
    finished: set[int] = set()

    def rehydrator(idx: int, field: str) -> StreamRehydrator:
        return rehydrators.setdefault((idx, field), StreamRehydrator(session))

    def finish_delta(idx: int, delta: dict[str, Any]) -> None:
        for (i, field), r in rehydrators.items():
            if i == idx and (tail := r.flush()):
                delta[field] = (delta.get(field) or "") + tail
        if tool_calls.get(idx):
            calls = []
            for tidx in sorted(tool_calls[idx]):
                call = tool_calls[idx][tidx]
                fn = call.setdefault("function", {})
                fn["arguments"] = rehydrate_arguments(fn.get("arguments", ""), session)
                calls.append({"index": tidx, **call})
            delta["tool_calls"] = calls
            tool_calls[idx] = {}

    try:
        last_chunk: dict[str, Any] = {}
        async for line in upstream.aiter_lines():
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                chunk = json.loads(data)
            except json.JSONDecodeError:
                continue
            if not isinstance(chunk, dict):
                continue
            last_chunk = chunk
            for choice in chunk.get("choices") or []:
                idx = choice.get("index", 0)
                delta = choice.get("delta") or {}
                for field in REASONING_FIELDS:
                    if not include_reasoning:
                        delta.pop(field, None)
                for field in text_fields:
                    if isinstance(delta.get(field), str):
                        piece = delta[field]
                        if field == "content" and idx not in started:
                            piece = piece.lstrip()
                            if piece:
                                started.add(idx)
                        delta[field] = rehydrator(idx, field).feed(piece)
                for tc in delta.pop("tool_calls", None) or []:
                    slot = tool_calls.setdefault(idx, {}).setdefault(tc.get("index", 0), {})
                    for key in ("id", "type"):
                        if tc.get(key):
                            slot[key] = tc[key]
                    fn = tc.get("function") or {}
                    target = slot.setdefault("function", {})
                    if fn.get("name"):
                        target["name"] = target.get("name", "") + fn["name"]
                    if fn.get("arguments"):
                        target["arguments"] = target.get("arguments", "") + fn["arguments"]
                if choice.get("finish_reason") is not None:
                    finish_delta(idx, delta)
                    finished.add(idx)
                choice["delta"] = delta
            yield f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n"

        pending = {i for i, _ in rehydrators} | set(tool_calls)
        for idx in sorted(pending - finished):
            delta: dict[str, Any] = {}
            finish_delta(idx, delta)
            if delta:
                tail = {key: last_chunk.get(key) for key in ("id", "object", "created", "model")}
                tail["choices"] = [{"index": idx, "delta": delta, "finish_reason": None}]
                yield f"data: {json.dumps(tail, ensure_ascii=False)}\n\n"
        yield "data: [DONE]\n\n"
    finally:
        await upstream.aclose()
        on_done()


def create_app(
    settings: Settings | None = None,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    agent_settings: AgentSettings | None = None,
) -> FastAPI:
    settings = settings or load_settings()
    services = build_services(settings, transport)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        await services.aclose()

    app = FastAPI(title="Airlock", version=__version__, lifespan=lifespan)
    app.state.services = services
    if "*" not in settings.allowed_hosts:
        hosts = [
            f"[{h}]" if ":" in h and not h.startswith("[") else h for h in settings.allowed_hosts
        ]
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=[*settings.allowed_hosts, *hosts])

    @app.middleware("http")
    async def require_json(request: Request, call_next):
        # A web page can send "simple" cross-origin POSTs (text/plain) without a CORS preflight.
        # Requiring a JSON content type forces the preflight, which Airlock never approves.
        if request.method == "POST":
            ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
            if not (ctype == "application/json" or ctype.endswith("+json")):
                return _error(415, "invalid_request_error", "Content-Type must be application/json")
        return await call_next(request)

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def index() -> HTMLResponse:
        html = resources.files("airlock.static").joinpath("index.html").read_text("utf-8")
        return HTMLResponse(html)

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {
            "status": "ok",
            "version": __version__,
            "protection_level": str(settings.protection_level),
            "local_model": settings.local_model,
            "local_temperature": settings.local_temperature,
            "upstream_model": settings.upstream_model,
            "upstream_configured": bool(settings.nebius_api_key),
            "search_configured": bool(settings.tavily_api_key),
        }

    def review_reasons(request: Request, analysis: ChatAnalysis, preview_stats) -> list[str]:
        if (request.headers.get(REVIEW_HEADER) or "").strip().lower() == "required":
            return ["requested"]
        mode = settings.review_mode
        if mode is ReviewMode.ALWAYS:
            return ["always"]
        if mode is ReviewMode.UNCERTAIN:
            return services.sanitizer.review_triggers(analysis, preview_stats)
        return []

    async def finish_chat(
        record: AuditRecord,
        body: dict[str, Any],
        analysis: ChatAnalysis,
        session: VaultSession,
        conversation_id: str,
        include_reasoning: bool,
        *,
        rejected: list[str] | None = None,
        added: list[Span] | None = None,
    ):
        record.start("substitute")
        sanitized = services.sanitizer.build_chat(
            body, analysis, session, rejected=rejected or [], added=added or []
        )
        record.stop("substitute")
        record.detections = [d.audit(services.hasher) for d in sanitized.detections]
        record.meta["detector"] = sanitized.stats.as_dict()
        originals = [p.text for p in sanitized.protected]

        record.start("gate")
        decision = gate.check(
            sanitized.payload,
            sanitized.protected,
            hasher=services.hasher,
            extra_reasons=sanitized.extra_reasons,
        )
        record.stop("gate")
        record.gate = decision.as_dict()
        if not decision.allowed:
            services.audit.write(record, originals)
            return _blocked(record, decision.reasons)

        if not services.upstream.configured:
            services.audit.write(record, originals)
            return _error(
                503, "airlock_not_configured", "NEBIUS_API_KEY is not set", record.request_id
            )

        streaming = bool(sanitized.payload.get("stream"))
        record.meta.update(
            {"stream": streaming, "conversation_id_hmac": services.hasher(conversation_id)}
        )
        headers = {REQUEST_ID_HEADER: record.request_id, CONVERSATION_HEADER: conversation_id}

        record.start("upstream")
        try:
            result = await services.upstream.send(
                sanitized.payload,
                lambda sent: record.add_outbound("upstream", sent),
                stream=streaming,
            )
        except UpstreamError as exc:
            record.stop("upstream")
            services.audit.write(record, originals)
            return _error(
                502, "airlock_upstream_error", str(exc), record.request_id, status=exc.status
            )
        record.meta.update({"model_used": result.model_used, "fallback": result.fallback})

        if result.stream is not None:
            services.audit.write(record, originals)  # outbound is final; timings updated later

            def done() -> None:
                record.stop("upstream")
                services.audit.write(record, originals)

            return StreamingResponse(
                relay_stream(
                    result.stream, session, include_reasoning=include_reasoning, on_done=done
                ),
                media_type="text/event-stream",
                headers=headers,
            )

        record.stop("upstream")
        record.start("rehydrate")
        answer = rehydrate_response(result.data or {}, session, include_reasoning=include_reasoning)
        record.stop("rehydrate")
        services.audit.write(record, originals)
        return JSONResponse(answer, headers=headers)

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request):
        record = AuditRecord("chat")
        try:
            body = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _error(400, "invalid_request_error", "body must be JSON", record.request_id)
        if not isinstance(body, dict):
            return _error(400, "invalid_request_error", "body must be an object", record.request_id)

        conversation_id = request.headers.get(CONVERSATION_HEADER) or conversation_id_for(body)
        session = services.vault.session(conversation_id)
        include_reasoning = _truthy(request.headers.get(REASONING_HEADER))

        record.start("detect")
        try:
            analysis = await services.sanitizer.analyze_chat(body, session)
        except PayloadError as exc:
            return _error(400, "invalid_request_error", str(exc), record.request_id)
        except LocalModelError as exc:
            # Fail closed: without a working local detector nothing leaves the machine.
            reasons = [block_reason(exc)]
            record.gate = {"decision": "block", "reasons": reasons}
            services.audit.write(record)
            return _blocked(record, reasons)
        finally:
            record.stop("detect")

        wants_review = settings.review_mode is not ReviewMode.NEVER or (
            request.headers.get(REVIEW_HEADER)
        )
        if wants_review:
            proposals, preview_stats = services.sanitizer.propose(body, analysis, session)
            reasons = review_reasons(request, analysis, preview_stats)
            if reasons:
                return hold_for_review(
                    record, body, analysis, proposals, preview_stats, reasons,
                    conversation_id, include_reasoning,
                )  # fmt: skip
        return await finish_chat(
            record, body, analysis, session, conversation_id, include_reasoning
        )

    def hold_for_review(
        record: AuditRecord,
        body: dict[str, Any],
        analysis: ChatAnalysis,
        proposals: list[dict[str, Any]],
        preview_stats,
        reasons: list[str],
        conversation_id: str,
        include_reasoning: bool,
    ) -> JSONResponse:
        review_id = services.reviews.put(
            PendingReview(body, conversation_id, analysis, proposals, include_reasoning)
        )
        record.gate = {"decision": "review", "reasons": [f"review_required:{r}" for r in reasons]}
        record.meta.update({"detector": preview_stats.as_dict(), "review_id": review_id})
        record.detections = []
        services.audit.write(record, [p["text"] for p in proposals])
        return JSONResponse(
            {
                "error": {
                    "type": "airlock_review_required",
                    "message": "Confirm the proposed redactions: POST /review/{review_id}",
                    "review_id": review_id,
                    "reasons": reasons,
                    "proposed": proposals,
                    "request_id": record.request_id,
                    "expires_in_s": int(settings.review_ttl_s),
                }
            },
            status_code=409,
            headers={REQUEST_ID_HEADER: record.request_id, CONVERSATION_HEADER: conversation_id},
        )

    @app.post("/review/{review_id}")
    async def submit_review(review_id: str, decision: ReviewDecision):
        pending = services.reviews.get(review_id)
        if pending is None:
            return _error(404, "airlock_review_not_found", "unknown or expired review_id")
        ids = {p["span_id"] for p in pending.proposals}
        unknown = sorted((set(decision.approve) | set(decision.reject)) - ids)
        if unknown:
            return _error(400, "invalid_request_error", f"unknown span_id: {', '.join(unknown)}")
        both = set(decision.approve) & set(decision.reject)
        if both:
            return _error(400, "invalid_request_error", "a span_id is both approved and rejected")
        services.reviews.pop(review_id)

        rejected = [p["text"] for p in pending.proposals if p["span_id"] in decision.reject]
        # A user-added span cannot be rejected by the same decision.
        added_norms = {normalize(a.text) for a in decision.add}
        rejected = [r for r in rejected if normalize(r) not in added_norms]
        added = [Span(text=a.text.strip(), type=a.type, source="user") for a in decision.add]

        record = AuditRecord("chat")
        record.meta["review"] = {
            "review_id": review_id,
            "proposed": len(pending.proposals),
            "approved": len(pending.proposals) - len(rejected),
            "rejected": len(rejected),
            "added": len(added),
        }
        session = services.vault.session(pending.conversation_id)
        return await finish_chat(
            record,
            pending.body,
            pending.analysis,
            session,
            pending.conversation_id,
            pending.include_reasoning,
            rejected=rejected,
            added=added,
        )

    @app.post("/v1/search")
    async def private_search(req: SearchRequest):
        record = AuditRecord("search")
        try:
            result = await services.search.run(req.query, req.context, req.max_results, record)
        except SearchBlocked as exc:
            record.gate = {"decision": "block", "reasons": exc.reasons}
            services.audit.write(record, [req.query, req.context or ""])
            return _blocked(record, exc.reasons)
        except SearchNotConfigured as exc:
            services.audit.write(record)
            return _error(503, "airlock_not_configured", str(exc), record.request_id)
        except TavilyError as exc:
            services.audit.write(record)
            return _error(502, "airlock_upstream_error", str(exc), record.request_id)
        services.audit.write(record)
        return JSONResponse(result, headers={REQUEST_ID_HEADER: record.request_id})

    @app.get("/audit")
    async def audit_recent(limit: int = 50) -> dict[str, Any]:
        return {"records": services.audit.recent(max(1, min(limit, 500)))}

    @app.get("/audit/{request_id}")
    async def audit_get(request_id: str):
        data = services.audit.get(request_id)
        if data is None:
            return _error(404, "not_found", "no audit record with that id")
        return data

    @app.post("/vault/terms")
    async def add_terms(req: TermsRequest) -> dict[str, Any]:
        added = services.vault.add_terms(req.terms, req.type, req.kind)
        return {
            "added": added,
            "total": len(services.vault.terms(req.kind)),
            "kind": req.kind,
        }

    @app.delete("/vault/terms")
    async def delete_terms(req: TermsDeleteRequest) -> dict[str, Any]:
        removed = services.vault.remove_terms(req.terms, req.kind)
        return {
            "removed": removed,
            "total": len(services.vault.terms()),
        }

    @app.post("/vault/reset")
    async def reset_vault() -> dict[str, Any]:
        # Clears declared terms, canaries, all conversation mappings and the in-memory detection
        # caches (local detector and health entailment; both hold raw text). Audit records are kept.
        cleared = services.sanitizer.clear_caches()
        services.reviews.clear()
        return {"reset": True, **services.vault.reset(), "detection_cache_cleared": cleared}

    # Agent mode (egress firewall for tool calls and web search): airlock/agent_api.py
    from airlock.agent_api import add_agent_routes
    from airlock.agent_settings import load_agent_settings

    add_agent_routes(app, services, agent_settings or load_agent_settings())

    return app
