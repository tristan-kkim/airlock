"""HTTP routes for agent mode: `POST /v1/agent/run` (JSON or `?stream=1` server-sent events)."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from airlock.agent import AgentRunner, make_docs
from airlock.agent_settings import AgentSettings
from airlock.search_guard import IntentJudge, SearchGuard

if TYPE_CHECKING:
    from airlock.server import Services

REQUEST_ID_HEADER = "x-airlock-request-id"


class AgentDoc(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    text: str = Field(min_length=1, max_length=50000)


class AgentRunRequest(BaseModel):
    question: str = Field(min_length=1, max_length=4000)
    docs: list[AgentDoc] = Field(default_factory=list, max_length=20)
    max_steps: int | None = Field(default=None, ge=1, le=16)


def build_agent_runner(services: Services, agent: AgentSettings) -> AgentRunner:
    judge = IntentJudge(services.settings, agent, services.http)
    guard = SearchGuard(
        services.settings, agent, services.sanitizer, services.local, judge, services.hasher
    )
    return AgentRunner(
        services.settings,
        agent,
        sanitizer=services.sanitizer,
        upstream=services.upstream,
        search_backend=services.search.tavily,
        guard=guard,
        hasher=services.hasher,
        audit=services.audit,
        vault=services.vault,
    )


def sse(event: dict[str, Any]) -> str:
    return f"event: {event['type']}\ndata: {json.dumps(event, ensure_ascii=False)}\n\n"


def public_event(event: dict[str, Any]) -> dict[str, Any]:
    """The `done` event carries the audit record in-process; clients fetch it from /audit/{id}."""
    if event.get("type") == "done":
        return {k: v for k, v in event.items() if k != "audit"}
    return event


def add_agent_routes(app: FastAPI, services: Services, agent: AgentSettings) -> None:
    runner = build_agent_runner(services, agent)
    app.state.agent_runner = runner

    @app.post("/v1/agent/run")
    async def agent_run(req: AgentRunRequest, stream: int = 0):
        if not services.upstream.configured:
            error = {"type": "airlock_not_configured", "message": "NEBIUS_API_KEY is not set"}
            return JSONResponse({"error": error}, status_code=503)
        docs = make_docs([(d.name, d.text) for d in req.docs])
        # guard is always on here: unguarded runs exist only in-process for evaluation.
        events = runner.events(req.question, docs, guard=True, max_steps=req.max_steps)

        if stream:

            async def body() -> AsyncIterator[str]:
                async for event in events:
                    yield sse(public_event(event))

            return StreamingResponse(
                body(),
                media_type="text/event-stream",
                headers={"cache-control": "no-store", "x-accel-buffering": "no"},
            )

        trace: list[dict[str, Any]] = []
        final: dict[str, Any] = {}
        done: dict[str, Any] = {}
        async for event in events:
            if event["type"] == "final":
                final = event
            elif event["type"] == "done":
                done = event
            else:
                trace.append(event)
        return JSONResponse(
            {
                "run_id": done.get("run_id"),
                "request_id": done.get("request_id"),
                "status": final.get("status"),
                "answer": final.get("answer"),
                "steps": final.get("steps"),
                "searches": final.get("searches"),
                "search_rewritten": final.get("search_rewritten"),
                "search_blocked": final.get("search_blocked"),
                "trace": trace,
            },
            headers={REQUEST_ID_HEADER: done.get("request_id") or ""},
        )
