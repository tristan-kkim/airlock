"""The demo gateway: an ASGI app in front of per-session Airlock apps.

    request ─▶ security headers ─▶ DemoGateway
                                    ├─ /healthz, /readyz   probes (no Host check)
                                    ├─ /, /demo/*          banner UI, presets, budget page
                                    └─ allowlisted API     caps, limits, budget ─▶ session app

Each visitor session is a complete `airlock.server.create_app` instance with an in-memory vault and
audit log, so the normal chat, search, review, agent and audit routes work unchanged and never
see another visitor's data. Run with `AIRLOCK_DEMO=1 airlock serve` (see deploy/DEMO_RUNBOOK.md).
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import html
import json
import re
import secrets
import time
from collections.abc import Awaitable, Callable
from http.cookies import SimpleCookie
from importlib import resources
from typing import Any
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from airlock import __version__
from airlock.agent_settings import AgentSettings, load_agent_settings
from airlock.config import Settings, load_settings
from airlock.demo.cloud_detector import CloudDetectorModel, cloud_detector_settings
from airlock.demo.config import DemoSettings, load_demo_settings
from airlock.demo.guards import (
    DailyBudget,
    SharedTransport,
    SlidingWindowLimiter,
    client_ip,
    input_chars,
    utc_day,
)
from airlock.demo.presets import (
    PRESETS,
    PRESETS_BY_ID,
    LiveRunFailed,
    as_recorded,
    load_recorded,
    run_live,
)
from airlock.demo.sessions import COOKIE_NAME, SessionSigner, SessionStore
from airlock.server import create_app

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]

# Airlock routes a demo visitor may reach. Everything else (OpenAPI docs included) is 404.
COSTLY_ROUTES = (
    ("POST", re.compile(r"^/v1/chat/completions$")),
    ("POST", re.compile(r"^/v1/search$")),
    ("POST", re.compile(r"^/v1/agent/run$")),
    ("POST", re.compile(r"^/review/[A-Za-z0-9_]{1,64}$")),
)
SESSION_ROUTES = (
    ("GET", re.compile(r"^/audit$")),
    ("GET", re.compile(r"^/audit/[A-Za-z0-9_]{1,64}$")),
    ("POST", re.compile(r"^/vault/terms$")),
    ("DELETE", re.compile(r"^/vault/terms$")),
    ("POST", re.compile(r"^/vault/reset$")),
)
SITE_ROUTES = (
    ("GET", re.compile(r"^/$")),
    ("GET", re.compile(r"^/demo/(status|presets|budget)$")),
    ("POST", re.compile(r"^/demo/presets/[a-z0-9-]{1,64}/run$")),
)

BANNER_TEXT = (
    "Demo mode: detection runs in an isolated server/cloud model. Don't paste real personal data. "
    "Run Airlock locally for real privacy."
)

BASE_SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "strict-transport-security": "max-age=31536000",
    "cache-control": "no-store",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
}


def _json_error(status: int, type_: str, message: str, **extra: Any) -> tuple[int, bytes, dict]:
    body = json.dumps({"error": {"type": type_, "message": message, **extra}}).encode()
    headers = {"content-type": "application/json"}
    if "retry_after_s" in extra:
        headers["retry-after"] = str(extra["retry_after_s"])
    return status, body, headers


async def _send_simple(send: Send, status: int, body: bytes, headers: dict[str, str]) -> None:
    raw = [(k.encode("latin-1"), v.encode("latin-1")) for k, v in headers.items()]
    raw.append((b"content-length", str(len(body)).encode()))
    await send({"type": "http.response.start", "status": status, "headers": raw})
    await send({"type": "http.response.body", "body": body})


def _matches(routes, method: str, path: str) -> bool:
    return any(m == method and rx.match(path) for m, rx in routes)


def csp_for_html(page: str) -> str:
    """A CSP that allows exactly the page's own inline scripts and styles (by hash)."""

    def hashes(tag: str) -> str:
        found = re.findall(rf"<{tag}>(.*?)</{tag}>", page, flags=re.DOTALL)
        return " ".join(
            "'sha256-" + base64.b64encode(hashlib.sha256(s.encode()).digest()).decode() + "'"
            for s in found
        )

    return (
        "default-src 'none'; "
        f"script-src {hashes('script') or chr(39) + 'none' + chr(39)}; "
        f"style-src {hashes('style') or chr(39) + 'none' + chr(39)}; "
        "connect-src 'self'; img-src 'self' data:; form-action 'none'; "
        "base-uri 'none'; frame-ancestors 'none'"
    )


class SecurityHeaders:
    def __init__(self, app: Callable[..., Awaitable[None]]):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                present = {k.decode("latin-1").lower() for k, _ in headers}
                for name, value in BASE_SECURITY_HEADERS.items():
                    if name not in present:
                        headers.append((name.encode(), value.encode()))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


class DemoGateway:
    def __init__(
        self,
        settings: Settings,
        demo: DemoSettings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        agent_settings: AgentSettings | None = None,
        clock: Callable[[], float] = time.monotonic,
        today: Callable[[], str] = utc_day,
    ):
        self.demo = demo
        core = settings.with_overrides(
            vault_path=":memory:",
            audit_db=":memory:",
            # A per-process key: audit hashes are meaningless outside this process, by design.
            audit_hash_key=settings.audit_hash_key or secrets.token_hex(32),
            allowed_hosts=("*",),  # the gateway checks Host; session apps are internal
            gliner=False,
        )
        local_factory = None
        if demo.detector_backend == "cloud":
            core = cloud_detector_settings(core, demo.cloud_detector_model)
            local_factory = CloudDetectorModel.factory(demo.cloud_detector_model)
        self.settings = core
        agent = agent_settings or load_agent_settings()
        self.agent_settings = agent.with_overrides(
            max_steps=max(1, min(agent.max_steps, demo.agent_max_steps))
        )
        self.budget = DailyBudget(demo.daily_requests, demo.daily_cloud_calls, today=today)

        paid_hosts = [
            urlsplit(core.upstream_base_url).hostname,
            urlsplit(core.tavily_base_url).hostname,
        ]
        if demo.detector_backend == "cloud":
            paid_hosts.append(urlsplit(core.local_base_url).hostname)
        self.transport = SharedTransport(
            transport or httpx.AsyncHTTPTransport(),
            [h for h in paid_hosts if h],
            on_paid_call=lambda _host: self.budget.spend_cloud_call(),
            on_out_of_credit=self._out_of_credit,
        )
        self.sessions = SessionStore(
            lambda: create_app(
                self.settings,
                transport=self.transport,
                agent_settings=self.agent_settings,
                local_factory=local_factory,
            ),
            ttl_s=demo.session_ttl_s,
            max_sessions=demo.max_sessions,
            clock=clock,
        )
        self.signer = SessionSigner()
        self.ip_limiter = SlidingWindowLimiter(demo.ip_limit, demo.window_s, clock=clock)
        self.session_limiter = SlidingWindowLimiter(demo.session_limit, demo.window_s, clock=clock)
        self.ip_requests = SlidingWindowLimiter(demo.ip_request_limit, demo.window_s, clock=clock)
        self.recorded = load_recorded()
        self.active = 0
        self.started = time.time()
        self.site = self._build_site()

    # ------------------------------------------------------------------ state
    def _out_of_credit(self) -> None:
        self.budget.forced_exhausted = True

    @property
    def models(self) -> dict[str, str]:
        return {
            "detector": self.settings.local_model,
            "detector_backend": self.demo.detector_backend,
            "upstream": self.settings.upstream_model,
        }

    def admission(self, ip: str, sid: str) -> dict[str, Any] | None:
        """None if a costly request may run now; else an error payload (not yet recorded)."""
        if self.budget.exhausted:
            return {
                "status": 429,
                "type": "demo_budget_reached",
                "reason": "budget_exhausted",
                "message": (
                    "The demo's daily budget is used up. The one-click scenarios still show "
                    "recorded runs, and Airlock runs locally in about five minutes: "
                    + self.demo.quickstart_url
                ),
                "extra": {"page": "/demo/budget"},
            }
        wait = max(self.ip_limiter.check(ip), self.session_limiter.check(sid))
        if wait > 0:
            return {
                "status": 429,
                "type": "demo_rate_limited",
                "reason": "rate_limited",
                "message": (
                    f"Demo limit: {self.demo.session_limit} requests per "
                    f"{self.demo.window_s // 60} minutes. Try again in {int(wait) + 1} s, or "
                    "pick a scenario (recorded runs are always available)."
                ),
                "extra": {"retry_after_s": int(wait) + 1},
            }
        if self.active >= self.demo.max_concurrent:
            return {
                "status": 503,
                "type": "demo_busy",
                "reason": "busy",
                "message": "The demo is busy right now. Try again in a few seconds.",
                "extra": {"retry_after_s": 5},
            }
        return None

    def admit(self, ip: str, sid: str) -> None:
        self.ip_limiter.hit(ip)
        self.session_limiter.hit(sid)
        self.budget.spend_request()

    def status(self, ip: str, sid: str) -> dict[str, Any]:
        return {
            "demo": True,
            "banner": BANNER_TEXT,
            "detector": self.demo.detector_label,
            "models": self.models,
            "budget": self.budget.status(),
            "limits": {
                "requests_per_window": self.demo.session_limit,
                "window_s": self.demo.window_s,
                "max_input_chars": self.demo.max_input_chars,
                "session_ttl_s": self.demo.session_ttl_s,
            },
            "remaining": {
                "ip": self.ip_limiter.remaining(ip),
                "session": self.session_limiter.remaining(sid),
            },
            # The visitor's own address as the server sees it. Behind a proxy with the wrong
            # AIRLOCK_DEMO_TRUSTED_PROXY_HOPS this is the proxy, and the per-IP limit turns global.
            "client_ip": ip,
            "presets_mode": self.demo.presets,
            "quickstart_url": self.demo.quickstart_url,
        }

    # ------------------------------------------------------------------ site
    def index_html(self) -> str:
        page = resources.files("airlock.static").joinpath("index.html").read_text("utf-8")
        demo_css = resources.files("airlock.demo").joinpath("static/demo.css").read_text("utf-8")
        demo_js = resources.files("airlock.demo").joinpath("static/demo.js").read_text("utf-8")
        demo_html = resources.files("airlock.demo").joinpath("static/demo.html").read_text("utf-8")
        demo_html = (
            demo_html.replace("{{BANNER_TEXT}}", html.escape(BANNER_TEXT, quote=False))
            .replace("{{QUICKSTART_URL}}", html.escape(self.demo.quickstart_url))
            .replace("{{DETECTOR}}", html.escape(self.demo.detector_label))
        )
        banner, _, scenarios = demo_html.partition("<!-- scenarios -->")
        for old, new in (
            ("Stored only in the local vault.", "Stored in this demo session's in-memory vault."),
            (
                "Private context (stays on this machine)",
                "Private context (used on the demo server)",
            ),
            (
                "(stay on this machine; the cloud sees them only through Airlock)",
                "(stay on the demo server; Ultra and Tavily see them only through Airlock)",
            ),
            ("<title>Airlock</title>", "<title>Airlock demo</title>"),
        ):
            page = page.replace(old, new)
        page = page.replace("</head>", f"<style>{demo_css}</style>\n</head>", 1)
        page = page.replace("<body>", "<body>\n" + banner, 1)
        page = page.replace("<main>", "<main>\n" + scenarios, 1)
        page = page.replace("</body>", f"<script>{demo_js}</script>\n</body>", 1)
        return page

    def budget_html(self) -> str:
        page = resources.files("airlock.demo").joinpath("static/budget.html").read_text("utf-8")
        return page.replace("{{QUICKSTART_URL}}", html.escape(self.demo.quickstart_url))

    def _build_site(self) -> FastAPI:
        site = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
        gateway = self
        index = self.index_html()
        index_csp = csp_for_html(index)
        budget_page = self.budget_html()
        budget_csp = csp_for_html(budget_page)

        def who(request: Request) -> tuple[str, str]:
            info = request.scope["airlock_demo"]
            return info["ip"], info["sid"]

        @site.get("/")
        async def home() -> HTMLResponse:
            return HTMLResponse(index, headers={"content-security-policy": index_csp})

        @site.get("/demo/budget")
        async def budget() -> HTMLResponse:
            return HTMLResponse(budget_page, headers={"content-security-policy": budget_csp})

        @site.get("/demo/status")
        async def status(request: Request) -> dict[str, Any]:
            return gateway.status(*who(request))

        @site.get("/demo/presets")
        async def presets() -> dict[str, Any]:
            return {
                "presets": [
                    {**p.public(), "has_recorded": p.id in gateway.recorded} for p in PRESETS
                ]
            }

        @site.post("/demo/presets/{preset_id}/run")
        async def run_preset(preset_id: str, request: Request):
            preset = PRESETS_BY_ID.get(preset_id)
            if preset is None:
                return JSONResponse(
                    {"error": {"type": "not_found", "message": "unknown preset"}}, status_code=404
                )
            ip, sid = who(request)
            recorded = gateway.recorded.get(preset_id)
            refusal = (
                {
                    "reason": "recorded_mode",
                    "status": 503,
                    "type": "demo_recorded_only",
                    "message": "Live runs are switched off; no recording for this scenario.",
                    "extra": {},
                }
                if gateway.demo.presets == "recorded"
                else gateway.admission(ip, sid)
            )
            if refusal is not None:
                if recorded:
                    return as_recorded(recorded, refusal["reason"])
                return JSONResponse(
                    {
                        "error": {
                            "type": refusal["type"],
                            "message": refusal["message"],
                            **refusal["extra"],
                        }
                    },
                    status_code=refusal["status"],
                )
            gateway.admit(ip, sid)
            session = await gateway.sessions.get(sid)
            session.inflight += 1
            gateway.active += 1
            try:
                return await run_live(session.app, preset, gateway.models)
            except (LiveRunFailed, httpx.HTTPError) as exc:
                if recorded:
                    return as_recorded(recorded, "live_error")
                return JSONResponse(
                    {"error": {"type": "demo_live_error", "message": str(exc)}}, status_code=502
                )
            finally:
                session.inflight -= 1
                gateway.active -= 1

        return site

    # ------------------------------------------------------------------ ASGI
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
            return
        if scope["type"] != "http":
            return
        method, path = scope["method"], scope["path"]

        if path == "/healthz" and method == "GET":
            await self._json(send, 200, self.health())
            return
        if path == "/readyz" and method == "GET":
            ready, body = self.readiness()
            await self._json(send, 200 if ready else 503, body)
            return

        ip = client_ip(scope, self.demo.trusted_proxy_hops)
        if self.ip_requests.check(ip) > 0:
            await _send_simple(send, *_json_error(429, "demo_rate_limited", "Too many requests."))
            return
        self.ip_requests.hit(ip)

        sid, new_cookie = self._session_id(scope)
        send = self._with_cookie(send, sid, scope) if new_cookie else send
        scope["airlock_demo"] = {"ip": ip, "sid": sid}

        costly = _matches(COSTLY_ROUTES, method, path)
        site = _matches(SITE_ROUTES, method, path)
        if not (costly or site or _matches(SESSION_ROUTES, method, path)):
            await _send_simple(send, *_json_error(404, "not_found", "Not found in demo mode."))
            return

        body = b""
        if method in ("POST", "DELETE", "PUT", "PATCH"):
            ctype = _header(scope, b"content-type").split(";")[0].strip().lower()
            if method == "POST" and not (ctype == "application/json" or ctype.endswith("+json")):
                await _send_simple(
                    send,
                    *_json_error(415, "invalid_request_error", "Content-Type must be JSON"),
                )
                return
            body_or_error = await self._read_body(scope, receive)
            if isinstance(body_or_error, tuple):
                await _send_simple(send, *body_or_error)
                return
            body = body_or_error
            if body and not site:
                checked = self._check_and_clamp(path, body)
                if isinstance(checked, tuple):
                    await _send_simple(send, *checked)
                    return
                body = checked

        if site:
            await self.site(scope, _replay(body, receive), send)
            return

        if costly:
            refusal = self.admission(ip, sid)
            if refusal is not None:
                await _send_simple(
                    send,
                    *_json_error(
                        refusal["status"], refusal["type"], refusal["message"], **refusal["extra"]
                    ),
                )
                return
            self.admit(ip, sid)

        session = await self.sessions.get(sid)
        session.inflight += 1
        self.active += 1 if costly else 0
        try:
            if body:
                scope = {**scope, "headers": _with_length(scope["headers"], len(body))}
            await session.app(scope, _replay(body, receive), send)
        finally:
            session.inflight -= 1
            self.active -= 1 if costly else 0

    # ------------------------------------------------------------------ helpers
    def health(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "version": __version__,
            "demo": True,
            "protection_level": str(self.settings.protection_level),
            "local_model": self.demo.detector_label,
            "upstream_model": self.settings.upstream_model,
            "upstream_configured": bool(self.settings.nebius_api_key),
            "search_configured": bool(self.settings.tavily_api_key),
        }

    def readiness(self) -> tuple[bool, dict[str, Any]]:
        live = bool(self.settings.nebius_api_key)
        recorded = sum(1 for p in PRESETS if p.id in self.recorded)
        # Ready when visitors get something useful: live runs, or every scenario recorded.
        ready = live or recorded == len(PRESETS)
        return ready, {
            "status": "ready" if ready else "not_ready",
            "live_configured": live,
            "search_configured": bool(self.settings.tavily_api_key),
            "detector_backend": self.demo.detector_backend,
            "recorded_presets": f"{recorded}/{len(PRESETS)}",
            "budget_exhausted": self.budget.exhausted,
            "sessions": len(self.sessions),
            "uptime_s": int(time.time() - self.started),
        }

    def _session_id(self, scope: Scope) -> tuple[str, bool]:
        cookie = SimpleCookie()
        with contextlib.suppress(Exception):  # a malformed cookie header just means no session
            cookie.load(_header(scope, b"cookie"))
        morsel = cookie.get(COOKIE_NAME)
        sid = self.signer.verify(morsel.value if morsel else None)
        return (sid, False) if sid else (self.signer.mint(), True)

    def _with_cookie(self, send: Send, sid: str, scope: Scope) -> Send:
        secure = scope.get("scheme") == "https" or (
            self.demo.trusted_proxy_hops > 0 and _header(scope, b"x-forwarded-proto") == "https"
        )
        value = (
            f"{COOKIE_NAME}={sid}; Path=/; HttpOnly; SameSite=Lax; "
            f"Max-Age={self.demo.session_ttl_s}" + ("; Secure" if secure else "")
        )

        async def wrapped(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers = [*message.get("headers", []), (b"set-cookie", value.encode())]
                message = {**message, "headers": headers}
            await send(message)

        return wrapped

    async def _read_body(self, scope: Scope, receive: Receive) -> bytes | tuple[int, bytes, dict]:
        cap = self.demo.max_body_bytes
        too_big = _json_error(
            413, "demo_input_too_large", f"Request body is larger than {cap} bytes."
        )
        declared = _header(scope, b"content-length")
        if declared.isdigit() and int(declared) > cap:
            return too_big
        chunks, size = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return _json_error(400, "invalid_request_error", "client disconnected")
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > cap:
                return too_big
            chunks.append(chunk)
            if not message.get("more_body"):
                return b"".join(chunks)

    def _check_and_clamp(self, path: str, body: bytes) -> bytes | tuple[int, bytes, dict]:
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return body  # the Airlock app answers with its own 400
        chars = input_chars(data)
        if chars > self.demo.max_input_chars:
            return _json_error(
                413,
                "demo_input_too_large",
                f"Demo inputs are limited to {self.demo.max_input_chars} characters "
                f"(this request has {chars}). Run Airlock locally for longer inputs.",
            )
        if not isinstance(data, dict):
            return body
        if path == "/v1/chat/completions":
            cap = self.demo.max_tokens
            data["max_tokens"] = min(_as_int(data.get("max_tokens"), cap), cap)
            if "max_completion_tokens" in data:
                given = _as_int(data["max_completion_tokens"], cap)
                data["max_completion_tokens"] = min(given, cap)
            if "n" in data:
                data["n"] = 1
        elif path == "/v1/agent/run":
            cap = self.agent_settings.max_steps
            data["max_steps"] = min(_as_int(data.get("max_steps"), cap), cap)
        return json.dumps(data, ensure_ascii=False).encode("utf-8")

    async def _json(self, send: Send, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode()
        await _send_simple(send, status, body, {"content-type": "application/json"})

    async def _lifespan(self, receive: Receive, send: Send) -> None:
        janitor: asyncio.Task | None = None
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                janitor = asyncio.create_task(self._janitor())
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                if janitor:
                    janitor.cancel()
                await self.aclose()
                await send({"type": "lifespan.shutdown.complete"})
                return

    async def _janitor(self) -> None:
        while True:
            await asyncio.sleep(60)
            await self.sessions.expire()

    async def aclose(self) -> None:
        await self.sessions.close_all()
        await self.transport.close_inner()


def _as_int(value: Any, default: int) -> int:
    ok = isinstance(value, int) and not isinstance(value, bool) and value > 0
    return value if ok else default


def _header(scope: Scope, name: bytes) -> str:
    for key, value in scope.get("headers") or []:
        if key == name:
            return value.decode("latin-1")
    return ""


def _with_length(headers: list[tuple[bytes, bytes]], length: int) -> list[tuple[bytes, bytes]]:
    return [(k, v) for k, v in headers if k != b"content-length"] + [
        (b"content-length", str(length).encode())
    ]


def _replay(body: bytes, receive: Receive) -> Receive:
    sent = False

    async def replay() -> dict[str, Any]:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await receive()

    return replay


def build_demo_asgi(gateway: DemoGateway, allowed_hosts: tuple[str, ...]):
    """Security headers on every response; Host allowlist on everything except the probes.

    Platform health checks often use an internal address as Host, so /healthz and /readyz skip the
    allowlist. They expose no session data.
    """
    checked: Any = gateway
    if "*" not in allowed_hosts:
        checked = TrustedHostMiddleware(gateway, allowed_hosts=list(allowed_hosts))

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        probe = scope["type"] == "http" and scope["path"] in ("/healthz", "/readyz")
        await (gateway if probe or scope["type"] == "lifespan" else checked)(scope, receive, send)

    wrapped = SecurityHeaders(app)
    wrapped.gateway = gateway  # type: ignore[attr-defined]
    return wrapped


def create_demo_app(
    settings: Settings | None = None,
    demo: DemoSettings | None = None,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    agent_settings: AgentSettings | None = None,
    clock: Callable[[], float] = time.monotonic,
    today: Callable[[], str] = utc_day,
):
    """uvicorn factory: `uvicorn --factory airlock.demo.app:create_demo_app`."""
    settings = settings or load_settings()
    demo = demo or load_demo_settings()
    if not demo.enabled:
        raise RuntimeError("create_demo_app requires AIRLOCK_DEMO=1")
    gateway = DemoGateway(
        settings, demo, transport=transport, agent_settings=agent_settings, clock=clock, today=today
    )
    return build_demo_asgi(gateway, settings.allowed_hosts)
