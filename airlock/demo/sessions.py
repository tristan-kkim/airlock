"""Per-visitor demo sessions: each one is a full Airlock app with an in-memory vault and audit.

A session never sees another session's declared terms, placeholder mappings, detection caches,
pending reviews or audit records, because it has its own `Services`. Nothing is written to disk.
Idle sessions are dropped after a TTL; the oldest idle session is dropped past `max_sessions`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import FastAPI

COOKIE_NAME = "airlock_demo_sid"


class SessionSigner:
    """Session ids are random tokens signed with a per-process key.

    The server only accepts ids it minted, so a visitor cannot choose (or fix) another's id, and a
    restart invalidates every id along with the in-memory state behind it.
    """

    def __init__(self, key: bytes | None = None):
        self._key = key or secrets.token_bytes(32)

    def _sig(self, token: str) -> str:
        mac = hmac.new(self._key, token.encode("ascii"), hashlib.sha256).digest()[:16]
        return base64.urlsafe_b64encode(mac).decode("ascii").rstrip("=")

    def mint(self) -> str:
        token = secrets.token_urlsafe(18)
        return f"{token}.{self._sig(token)}"

    def verify(self, value: str | None) -> str | None:
        if not value or value.count(".") != 1 or len(value) > 128:
            return None
        token, sig = value.split(".")
        try:
            token.encode("ascii")
        except UnicodeEncodeError:
            return None
        return value if hmac.compare_digest(sig, self._sig(token)) else None


@dataclass
class DemoSession:
    sid: str
    app: FastAPI
    created: float = field(default_factory=time.monotonic)
    last_seen: float = field(default_factory=time.monotonic)
    inflight: int = 0

    async def aclose(self) -> None:
        await self.app.state.services.aclose()


class SessionStore:
    def __init__(
        self,
        build: Callable[[], FastAPI],
        ttl_s: float,
        max_sessions: int,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.build = build
        self.ttl_s = ttl_s
        self.max_sessions = max_sessions
        self.clock = clock
        self._sessions: OrderedDict[str, DemoSession] = OrderedDict()

    def __len__(self) -> int:
        return len(self._sessions)

    def peek(self, sid: str) -> DemoSession | None:
        return self._sessions.get(sid)

    async def get(self, sid: str) -> DemoSession:
        await self.expire()
        session = self._sessions.get(sid)
        if session is None:
            session = DemoSession(sid, self.build(), created=self.clock(), last_seen=self.clock())
            self._sessions[sid] = session
            await self._evict_over_capacity(keep=sid)
        session.last_seen = self.clock()
        self._sessions.move_to_end(sid)
        return session

    async def expire(self) -> int:
        now = self.clock()
        stale = [
            s for s in self._sessions.values() if s.inflight == 0 and now - s.last_seen > self.ttl_s
        ]
        for s in stale:
            await self._drop(s)
        return len(stale)

    async def _evict_over_capacity(self, keep: str) -> None:
        for s in list(self._sessions.values()):
            if len(self._sessions) <= self.max_sessions:
                break
            if s.inflight == 0 and s.sid != keep:
                await self._drop(s)

    async def _drop(self, session: DemoSession) -> None:
        self._sessions.pop(session.sid, None)
        await session.aclose()

    async def close_all(self) -> None:
        for s in list(self._sessions.values()):
            await self._drop(s)
