"""Egress policy: every hop that leaves the machine is an event, gated and audited the same way.

An agent run talks to several remote parties: the cloud model (every planning turn, carrying the
conversation, the tool results and the model's own earlier tool-call arguments), the search API
(one query per search) and, in general, any HTTP tool. Each of those is an `EgressEvent`:

    destination: upstream | tavily | http_tool
    kind:        prompt | search_query | tool_args | tool_result
    payload:     the exact JSON object that would be sent

The kind-specific sanitizer runs first (chat sanitization for upstream turns, the search-intent
guard for queries). `EgressPolicy.check` then runs the deterministic gate on the exact payload and
`EgressPolicy.record` appends one hop to the run's audit record: what left (verbatim, because it
passed the gate), or the reasons it did not. A hop never stores an original: blocked candidates
are recorded as keyed hashes only.

Unguarded runs (evaluation only, see `airlock.agent`) skip sanitization and the gate but are
recorded exactly the same way, so both modes can be attacked from their audit records.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Literal

from airlock import gate
from airlock.audit import AuditRecord

Destination = Literal["upstream", "tavily", "http_tool"]
EgressKind = Literal["prompt", "search_query", "tool_args", "tool_result"]
HopDecision = Literal["allow", "rewritten", "block"]


@dataclass
class EgressEvent:
    destination: Destination
    kind: EgressKind
    payload: Any
    step: int = 0


@dataclass
class Hop:
    """One recorded hop. `payload` is None unless something was actually sent."""

    index: int
    step: int
    destination: Destination
    kind: EgressKind
    decision: HopDecision
    reasons: list[str] = field(default_factory=list)
    payload: Any = None
    meta: dict[str, Any] = field(default_factory=dict)
    ms: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "hop": self.index,
            "step": self.step,
            "destination": self.destination,
            "kind": self.kind,
            "decision": self.decision,
            "reasons": list(self.reasons),
            "ms": round(self.ms, 1),
            "meta": self.meta,
        }
        if self.payload is not None:
            data["payload"] = self.payload
        return data


class EgressPolicy:
    """Gate + hop audit for one agent run."""

    def __init__(self, record: AuditRecord, hasher: Callable[[str], str], *, guard: bool = True):
        self.record = record
        self.hasher = hasher
        self.guard = guard
        self._started: dict[int, float] = {}

    def check(
        self,
        event: EgressEvent,
        protected: Iterable[gate.Protected],
        extra_reasons: Iterable[str] = (),
    ) -> gate.GateDecision:
        """The deterministic gate on the exact payload. Unguarded runs always pass."""
        if not self.guard:
            return gate.GateDecision("allow", [])
        return gate.check(event.payload, protected, hasher=self.hasher, extra_reasons=extra_reasons)

    def record_hop(
        self,
        event: EgressEvent,
        decision: HopDecision,
        *,
        reasons: Iterable[str] = (),
        sent: Any = None,
        meta: dict[str, Any] | None = None,
        started: float | None = None,
    ) -> Hop:
        hop = Hop(
            index=len(self.record.hops) + 1,
            step=event.step,
            destination=event.destination,
            kind=event.kind,
            decision=decision,
            reasons=list(reasons),
            payload=sent,
            meta={"guard": self.guard, **(meta or {})},
            ms=(time.perf_counter() - started) * 1000 if started is not None else 0.0,
        )
        self.record.hops.append(hop.as_dict())
        return hop

    def sent(self, destination: Destination, payload: Any) -> None:
        """Called with each exact payload right before it leaves (fallback attempts included)."""
        self.record.add_outbound(destination, payload)

    def update_hop(self, hop: Hop, **changes: Any) -> None:
        for key, value in changes.items():
            setattr(hop, key, value)
        self.record.hops[hop.index - 1] = hop.as_dict()
