"""Command line: `airlock serve` and `airlock doctor`."""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import dataclass
from typing import Literal

import httpx

from airlock import __version__
from airlock.config import Settings, load_settings
from airlock.detect import gliner
from airlock.detect.llm import LLMDetector, LocalModel, LocalModelError

Status = Literal["ok", "warn", "fail"]


@dataclass
class Check:
    status: Status
    name: str
    detail: str


def key_status(value: str | None) -> str:
    # Never print any part of a secret; presence and length are enough to debug.
    return f"set ({len(value)} chars)" if value else "not set"


async def check_local(settings: Settings, client: httpx.AsyncClient) -> list[Check]:
    local = LocalModel(settings, client)
    try:
        models = await local.ping()
        ids = [m.get("id") for m in models.get("data", []) if isinstance(m, dict)]
    except (httpx.HTTPError, ValueError) as exc:
        return [Check("fail", "local server", f"{settings.local_base_url} ({type(exc).__name__})")]
    checks = [Check("ok", "local server", f"{settings.local_base_url} models={ids}")]
    try:
        result = await LLMDetector(local, settings.protection_level).detect(
            "Please email Jane Doe at <CONTACT_1> about the Q3 invoice."
        )
        checks.append(
            Check("ok", "local detector", f"{len(result.spans)} span(s) on a synthetic probe")
        )
    except LocalModelError as exc:
        checks.append(Check("fail", "local detector", type(exc).__name__))
    return checks


async def check_upstream(settings: Settings, client: httpx.AsyncClient) -> list[Check]:
    checks = [
        Check(
            "ok" if settings.nebius_api_key else "fail",
            "NEBIUS_API_KEY",
            key_status(settings.nebius_api_key),
        )
    ]
    if not settings.nebius_api_key:
        return checks
    try:
        resp = await client.get(
            f"{settings.upstream_base_url}/models",
            headers={"Authorization": f"Bearer {settings.nebius_api_key}"},
            timeout=20,
        )
    except httpx.HTTPError as exc:
        return [*checks, Check("fail", "upstream", f"unreachable ({type(exc).__name__})")]
    if resp.status_code != 200:
        return [*checks, Check("fail", "upstream auth", f"GET /models -> HTTP {resp.status_code}")]
    ids = {m.get("id") for m in resp.json().get("data", []) if isinstance(m, dict)}
    checks.append(Check("ok", "upstream auth", "GET /models -> HTTP 200"))
    for label, model in (
        ("primary model", settings.upstream_model),
        ("fallback model", settings.upstream_fallback_model),
    ):
        if model:
            listed = model in ids
            checks.append(
                Check(
                    "ok" if listed else "warn",
                    label,
                    f"{model} {'listed' if listed else 'not listed'}",
                )
            )
    return checks


async def check_tavily(settings: Settings, client: httpx.AsyncClient) -> list[Check]:
    checks = [
        Check(
            "ok" if settings.tavily_api_key else "warn",
            "TAVILY_API_KEY",
            key_status(settings.tavily_api_key),
        )
    ]
    if not settings.tavily_api_key:
        return checks
    try:
        resp = await client.post(
            f"{settings.tavily_base_url}/search",
            # A generic, non-personal query: this check spends one basic search credit.
            json={"query": "OpenAI-compatible API", "max_results": 1, "search_depth": "basic"},
            headers={"Authorization": f"Bearer {settings.tavily_api_key}"},
            timeout=30,
        )
    except httpx.HTTPError as exc:
        return [*checks, Check("fail", "tavily", f"unreachable ({type(exc).__name__})")]
    status: Status = "ok" if resp.status_code == 200 else "fail"
    return [*checks, Check(status, "tavily auth", f"POST /search -> HTTP {resp.status_code}")]


async def run_doctor(settings: Settings) -> list[Check]:
    async with httpx.AsyncClient() as client:
        return [
            *await check_local(settings, client),
            *[Check(*row) for row in gliner.doctor_checks(settings)],
            *await check_upstream(settings, client),
            *await check_tavily(settings, client),
        ]


def _print_checks(settings: Settings, checks: list[Check]) -> int:
    print(f"Airlock {__version__} doctor (protection level: {settings.protection_level})")
    for c in checks:
        print(f"  [{c.status.upper():^4}] {c.name:<16} {c.detail}")
    failed = any(c.status == "fail" for c in checks)
    print("  some checks failed" if failed else "  all required checks passed")
    return 1 if failed else 0


def _short(text: object, limit: int = 160) -> str:
    flat = " ".join(str(text or "").split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def print_agent_event(event: dict, out=sys.stdout) -> None:
    """Human-readable trace line. Local-only: may show originals (never forwarded)."""
    kind = event.get("type")
    if kind == "run_started":
        print(f"run {event['run_id']} · {len(event['docs'])} local doc(s)", file=out)
    elif kind == "hop" and event.get("destination") == "upstream":
        new = event.get("outbound") or []
        preview = _short(new[-1].get("content") if new else "")
        print(
            f"  [{event['step']}] → Ultra  {event['decision']:<9} {event['kind']:<11} {preview}",
            file=out,
        )
    elif kind == "hop":
        sent = _short(event.get("outbound_query"), 70) or "(nothing)"
        local = _short(event.get("local_query"), 70)
        print(
            f"  [{event['step']}] → Tavily {event['decision']:<9} local: {local}  sent: {sent}",
            file=out,
        )
    elif kind == "tool":
        print(
            f"  [{event['step']}]   local  {event['name']} {_short(event.get('summary', ''))}",
            file=out,
        )
    elif kind == "error":
        print(f"  error: {event.get('message')}", file=out)
    elif kind == "final":
        print(f"\n{event['status']} after {event['steps']} step(s)\n\n{event['answer']}", file=out)
    elif kind == "done":
        print(f"\naudit: GET /audit/{event['request_id']}", file=out)


async def run_agent_cli(
    settings: Settings, question: str, docs_dir: str, max_steps: int | None
) -> int:
    from airlock.agent import load_docs_dir
    from airlock.agent_api import build_agent_runner
    from airlock.agent_settings import load_agent_settings
    from airlock.server import build_services

    services = build_services(settings)
    try:
        runner = build_agent_runner(services, load_agent_settings())
        docs = load_docs_dir(docs_dir) if docs_dir else []
        status = "error"
        async for event in runner.events(question, docs, guard=True, max_steps=max_steps):
            print_agent_event(event)
            if event["type"] == "final":
                status = event["status"]
        return 0 if status == "finished" else 1
    finally:
        await services.aclose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="airlock", description="Local privacy airlock for cloud AI"
    )
    parser.add_argument("--version", action="version", version=f"airlock {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the Airlock proxy")
    serve.add_argument("--host", default=None, help="bind address (default AIRLOCK_HOST)")
    serve.add_argument("--port", type=int, default=None, help="port (default AIRLOCK_PORT)")
    serve.add_argument("--reload", action="store_true", help="auto-reload (development)")

    sub.add_parser("doctor", help="check the local model, upstream key and Tavily key")

    agent = sub.add_parser("agent", help="run the private research agent on local documents")
    agent.add_argument("question", help="what to research")
    agent.add_argument("--docs", default="", help="directory of .md/.txt files (stay local)")
    agent.add_argument("--max-steps", type=int, default=None, help="planning turns (max 16)")

    args = parser.parse_args(argv)
    settings = load_settings()

    if args.command == "serve":
        import uvicorn

        host = args.host or settings.host
        port = args.port or settings.port
        if settings.gliner and (problem := gliner.availability_problem(settings)):
            print(f"error: AIRLOCK_GLINER=on but GLiNER cannot run: {problem}", file=sys.stderr)
            return 1
        if host not in ("127.0.0.1", "localhost", "::1"):
            print(f"warning: binding to {host}; Airlock should listen on loopback", file=sys.stderr)
        uvicorn.run(
            "airlock.server:create_app", factory=True, host=host, port=port, reload=args.reload
        )
        return 0
    if args.command == "doctor":
        return _print_checks(settings, asyncio.run(run_doctor(settings)))
    if args.command == "agent":
        return asyncio.run(run_agent_cli(settings, args.question, args.docs, args.max_steps))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
