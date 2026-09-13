"""Audit log: one record per request, containing exactly what left the machine.

Sensitive originals are never stored: detections carry only a SHA-256 of the original text, and
gate reasons carry a truncated hash. Outbound payloads are stored verbatim because they already
passed the gate (or, for blocked requests, were never sent and are not recorded).
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from airlock.detect.spans import normalize, term_pattern


def new_request_id() -> str:
    return "req_" + uuid.uuid4().hex


class AuditRecord:
    def __init__(self, kind: Literal["chat", "search"], request_id: str | None = None):
        self.request_id = request_id or new_request_id()
        self.created_at = datetime.now(UTC).isoformat()
        self.kind = kind
        self.detections: list[dict[str, str]] = []
        self.outbound: list[dict[str, Any]] = []
        self.gate: dict[str, Any] = {"decision": "block", "reasons": ["not_evaluated"]}
        self.timings_ms: dict[str, float] = {}
        self.meta: dict[str, Any] = {}
        self._t0 = time.perf_counter()
        self._marks: dict[str, float] = {}

    def start(self, name: str) -> None:
        self._marks[name] = time.perf_counter()

    def stop(self, name: str) -> None:
        began = self._marks.pop(name, None)
        if began is not None:
            elapsed = (time.perf_counter() - began) * 1000
            self.timings_ms[name] = round(self.timings_ms.get(name, 0.0) + elapsed, 2)

    def add_outbound(self, destination: Literal["upstream", "tavily"], payload: Any) -> None:
        self.outbound.append({"destination": destination, "payload": payload})

    def to_dict(self) -> dict[str, Any]:
        timings = dict(self.timings_ms)
        timings["total"] = round((time.perf_counter() - self._t0) * 1000, 2)
        return {
            "request_id": self.request_id,
            "created_at": self.created_at,
            "kind": self.kind,
            "detections": self.detections,
            "outbound": self.outbound,
            "gate": self.gate,
            "timings_ms": timings,
            "meta": self.meta,
        }


def scrub(record: dict[str, Any], originals: list[str]) -> dict[str, Any]:
    """Defense in depth: redact any original that slipped into gate reasons or detection labels.

    Outbound payloads are left verbatim (they are the evidence and already passed the gate).
    """
    targets = {"gate": record.get("gate"), "detections": record.get("detections")}
    blob = json.dumps(targets, ensure_ascii=False)
    for original in sorted({o for o in originals if len(o.strip()) >= 2}, key=len, reverse=True):
        encoded = json.dumps(original.strip(), ensure_ascii=False)[1:-1]
        if normalize(original) in normalize(blob):
            blob = term_pattern(encoded).sub("[REDACTED]", blob)
    return {**record, **json.loads(blob)}


class AuditLog:
    def __init__(self, path: str):
        if path != ":memory:":
            Path(path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS audit (request_id TEXT PRIMARY KEY, created_at TEXT, "
            "kind TEXT, decision TEXT, record TEXT NOT NULL)"
        )
        self._lock = threading.Lock()

    def write(self, record: AuditRecord, originals: list[str] | None = None) -> dict[str, Any]:
        data = scrub(record.to_dict(), originals or [])
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO audit VALUES (?, ?, ?, ?, ?)",
                (
                    data["request_id"],
                    data["created_at"],
                    data["kind"],
                    data["gate"]["decision"],
                    json.dumps(data, ensure_ascii=False),
                ),
            )
        return data

    def get(self, request_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT record FROM audit WHERE request_id = ?", (request_id,)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT request_id, created_at, kind, decision FROM audit "
                "ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {"request_id": r[0], "created_at": r[1], "kind": r[2], "decision": r[3]} for r in rows
        ]

    def close(self) -> None:
        with self._lock:
            self._conn.close()
