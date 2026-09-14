"""Abuse and cost guards for the public demo: rate limits, daily budget, input caps."""

from __future__ import annotations

import time
from collections import OrderedDict, deque
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any

import httpx


class SlidingWindowLimiter:
    """At most `limit` hits per key in any `window_s` seconds. Memory is bounded by `max_keys`."""

    def __init__(
        self,
        limit: int,
        window_s: float,
        *,
        max_keys: int = 20_000,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.limit = limit
        self.window_s = window_s
        self.max_keys = max_keys
        self.clock = clock
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()

    def _window(self, key: str, now: float) -> deque[float]:
        hits = self._hits.get(key)
        if hits is None:
            hits = self._hits[key] = deque()
            while len(self._hits) > self.max_keys:
                self._hits.popitem(last=False)
        else:
            self._hits.move_to_end(key)
        while hits and now - hits[0] >= self.window_s:
            hits.popleft()
        return hits

    def check(self, key: str) -> float:
        """0 if a hit is allowed now, else seconds until the next slot frees up. Does not record."""
        now = self.clock()
        hits = self._window(key, now)
        if len(hits) < self.limit:
            return 0.0
        return max(0.0, self.window_s - (now - hits[0]))

    def hit(self, key: str) -> None:
        now = self.clock()
        self._window(key, now).append(now)

    def remaining(self, key: str) -> int:
        return max(0, self.limit - len(self._window(key, self.clock())))


def utc_day(now: datetime | None = None) -> str:
    return (now or datetime.now(UTC)).strftime("%Y-%m-%d")


class DailyBudget:
    """Global per-UTC-day counters. A limit of 0 disables that counter.

    `requests` counts admitted costly requests; `cloud_calls` counts every HTTP call that left the
    demo server for Token Factory or Tavily (see SharedTransport). Either one reaching its limit
    exhausts the budget until the next UTC day. In memory: a restart resets it, which is acceptable
    for a demo whose real ceiling is the Token Factory balance.
    """

    def __init__(
        self,
        daily_requests: int,
        daily_cloud_calls: int,
        *,
        today: Callable[[], str] = utc_day,
    ):
        self.daily_requests = daily_requests
        self.daily_cloud_calls = daily_cloud_calls
        self.today = today
        self._day = today()
        self.requests = 0
        self.cloud_calls = 0
        self.forced_exhausted = False  # set when Token Factory reports 402 (out of credit)

    def _roll(self) -> None:
        day = self.today()
        if day != self._day:
            self._day, self.requests, self.cloud_calls = day, 0, 0
            self.forced_exhausted = False

    @property
    def exhausted(self) -> bool:
        self._roll()
        return (
            self.forced_exhausted
            or (0 < self.daily_requests <= self.requests)
            or (0 < self.daily_cloud_calls <= self.cloud_calls)
        )

    def spend_request(self) -> None:
        self._roll()
        self.requests += 1

    def spend_cloud_call(self) -> None:
        self._roll()
        self.cloud_calls += 1

    def status(self) -> dict[str, Any]:
        self._roll()
        return {
            "day_utc": self._day,
            "exhausted": self.exhausted,
            "requests": self.requests,
            "daily_requests": self.daily_requests,
            "cloud_calls": self.cloud_calls,
            "daily_cloud_calls": self.daily_cloud_calls,
            "out_of_credit": self.forced_exhausted,
        }


class SharedTransport(httpx.AsyncBaseTransport):
    """One connection pool for every session's client; counts calls to paid hosts.

    Session clients are closed when a session expires. Closing must not tear down the shared pool,
    so `aclose` is a no-op here and the gateway closes the inner transport at shutdown.
    """

    def __init__(
        self,
        inner: httpx.AsyncBaseTransport,
        paid_hosts: Iterable[str],
        on_paid_call: Callable[[str], None],
        on_out_of_credit: Callable[[], None] | None = None,
    ):
        self.inner = inner
        self.paid_hosts = {h.lower() for h in paid_hosts if h}
        self.on_paid_call = on_paid_call
        self.on_out_of_credit = on_out_of_credit

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = (request.url.host or "").lower()
        paid = host in self.paid_hosts
        if paid:
            self.on_paid_call(host)
        response = await self.inner.handle_async_request(request)
        if paid and response.status_code == 402 and self.on_out_of_credit:
            self.on_out_of_credit()
        return response

    async def aclose(self) -> None:  # shared: closed by the owner, not by session clients
        return None

    async def close_inner(self) -> None:
        await self.inner.aclose()


def input_chars(value: Any) -> int:
    """Characters of user-controlled text in a JSON body: every string value, recursively."""
    if isinstance(value, str):
        return len(value)
    if isinstance(value, dict):
        return sum(input_chars(v) for v in value.values())
    if isinstance(value, list):
        return sum(input_chars(v) for v in value)
    return 0


def client_ip(scope: dict[str, Any], trusted_proxy_hops: int, header: str = "") -> str:
    """Client address. Behind N trusted proxies, the N-th X-Forwarded-For entry from the right.

    Entries left of that are client-controlled and never trusted. With 0 hops the socket peer is
    used and X-Forwarded-For is ignored. `header` names a header the platform proxy sets itself
    (Fly.io: Fly-Client-IP); only configure it when the proxy overwrites a client-sent value.
    """
    peer = (scope.get("client") or ("unknown", 0))[0]
    if header:
        wanted = header.lower().encode("latin-1")
        for name, value in scope.get("headers") or []:
            if name == wanted and value.strip():
                return value.decode("latin-1").strip()
    if trusted_proxy_hops <= 0:
        return peer
    forwarded: list[str] = []
    for name, value in scope.get("headers") or []:
        if name == b"x-forwarded-for":
            forwarded += [p.strip() for p in value.decode("latin-1").split(",") if p.strip()]
    # Fewer entries than trusted proxies: the header did not come through them, so ignore it.
    return forwarded[-trusted_proxy_hops] if len(forwarded) >= trusted_proxy_hops else peer
