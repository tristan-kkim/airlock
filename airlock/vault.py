"""The vault: original <-> placeholder mappings and user-declared terms. Local only.

The vault file contains the sensitive originals in plain text. It lives on this machine
(`AIRLOCK_VAULT_PATH`, default `./.airlock/`) and is never sent anywhere. Use `:memory:` to keep
mappings only for the life of the process.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from airlock.detect.spans import normalize

TermKind = Literal["sensitive", "canary"]


def render_placeholder(key: str) -> str:
    return f"[[{key}]]"


@dataclass(frozen=True)
class Term:
    text: str
    type: str
    kind: TermKind


@dataclass(frozen=True)
class Mapping:
    original: str
    type: str
    action: Literal["mask", "generalize"]
    value: str  # placeholder key (e.g. PERSON_1) for mask, replacement text for generalize

    @property
    def outbound(self) -> str:
        return render_placeholder(self.value) if self.action == "mask" else self.value


_SCHEMA = """
CREATE TABLE IF NOT EXISTS mappings (
    conversation_id TEXT NOT NULL,
    norm_original   TEXT NOT NULL,
    original        TEXT NOT NULL,
    type            TEXT NOT NULL,
    action          TEXT NOT NULL,
    value           TEXT NOT NULL,
    created_at      REAL NOT NULL,
    PRIMARY KEY (conversation_id, norm_original)
);
CREATE INDEX IF NOT EXISTS mappings_value ON mappings (conversation_id, value);
CREATE TABLE IF NOT EXISTS terms (
    norm_text  TEXT NOT NULL,
    kind       TEXT NOT NULL,
    text       TEXT NOT NULL,
    type       TEXT NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY (norm_text, kind)
);
"""


class Vault:
    def __init__(self, path: str):
        if path != ":memory:":
            Path(path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._lock = threading.RLock()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---- user-declared terms -------------------------------------------------
    def add_terms(
        self, terms: list[str], type_: str = "PERSON", kind: TermKind = "sensitive"
    ) -> int:
        added = 0
        with self._lock, self._conn:
            for raw in terms:
                text = raw.strip()
                if len(text) < 2:
                    continue
                cur = self._conn.execute(
                    "INSERT OR IGNORE INTO terms VALUES (?, ?, ?, ?, ?)",
                    (normalize(text), kind, text, type_, time.time()),
                )
                added += cur.rowcount
        return added

    def terms(self, kind: TermKind | None = None) -> list[Term]:
        with self._lock:
            if kind is None:
                rows = self._conn.execute("SELECT text, type, kind FROM terms").fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT text, type, kind FROM terms WHERE kind = ?", (kind,)
                ).fetchall()
        return [Term(text=r[0], type=r[1], kind=r[2]) for r in rows]

    def remove_terms(self, terms: list[str], kind: TermKind | None = None) -> int:
        removed = 0
        with self._lock, self._conn:
            for text in terms:
                if kind is None:
                    cur = self._conn.execute(
                        "DELETE FROM terms WHERE norm_text = ?", (normalize(text),)
                    )
                else:
                    cur = self._conn.execute(
                        "DELETE FROM terms WHERE norm_text = ? AND kind = ?",
                        (normalize(text), kind),
                    )
                removed += cur.rowcount
        return removed

    def reset(self) -> dict[str, int]:
        """Forget every declared term, canary and conversation mapping."""
        with self._lock, self._conn:
            terms = self._conn.execute("DELETE FROM terms").rowcount
            mappings = self._conn.execute("DELETE FROM mappings").rowcount
        return {"terms_removed": terms, "mappings_removed": mappings}

    # ---- conversation mappings ----------------------------------------------
    def session(self, conversation_id: str) -> VaultSession:
        return VaultSession(self, conversation_id)

    def _load(self, conversation_id: str) -> list[Mapping]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT original, type, action, value FROM mappings WHERE conversation_id = ? "
                "ORDER BY created_at",
                (conversation_id,),
            ).fetchall()
        return [Mapping(r[0], r[1], r[2], r[3]) for r in rows]

    def _get_or_create(
        self, conversation_id: str, original: str, type_: str, action: str, generalized: str | None
    ) -> Mapping:
        norm = normalize(original)
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT original, type, action, value FROM mappings "
                "WHERE conversation_id = ? AND norm_original = ?",
                (conversation_id, norm),
            ).fetchone()
            if row:
                return Mapping(row[0], row[1], row[2], row[3])
            if action == "mask":
                prefix = f"{type_}_"
                existing = self._conn.execute(
                    "SELECT value FROM mappings WHERE conversation_id = ? AND action = 'mask' "
                    "AND value LIKE ?",
                    (conversation_id, prefix + "%"),
                ).fetchall()
                nums = [int(v[0][len(prefix) :]) for v in existing if v[0][len(prefix) :].isdigit()]
                value = f"{prefix}{max(nums, default=0) + 1}"
            else:
                value = generalized or ""
            self._conn.execute(
                "INSERT INTO mappings VALUES (?, ?, ?, ?, ?, ?, ?)",
                (conversation_id, norm, original, type_, action, value, time.time()),
            )
            return Mapping(original, type_, action, value)  # type: ignore[arg-type]


class VaultSession:
    """Mappings for one conversation. The same original always gets the same placeholder."""

    def __init__(self, vault: Vault, conversation_id: str):
        self.vault = vault
        self.conversation_id = conversation_id
        self._by_norm: dict[str, Mapping] = {}
        self._by_key: dict[str, Mapping] = {}
        for m in vault._load(conversation_id):
            self._remember(m)

    def _remember(self, m: Mapping) -> None:
        self._by_norm[normalize(m.original)] = m
        if m.action == "mask":
            self._by_key[m.value] = m

    def get(self, original: str) -> Mapping | None:
        return self._by_norm.get(normalize(original))

    def mask(self, original: str, type_: str) -> Mapping:
        existing = self.get(original)
        if existing is not None:
            return existing
        m = self.vault._get_or_create(self.conversation_id, original, type_, "mask", None)
        self._remember(m)
        return m

    def generalize(self, original: str, type_: str, replacement: str) -> Mapping:
        existing = self.get(original)
        if existing is not None:
            return existing
        m = self.vault._get_or_create(
            self.conversation_id, original, type_, "generalize", replacement
        )
        self._remember(m)
        return m

    def original_for(self, key: str) -> str | None:
        m = self._by_key.get(key)
        return m.original if m else None

    def mappings(self) -> list[Mapping]:
        return list(self._by_norm.values())
