"""Keyed hashing for audit records.

Audit records identify sensitive values by HMAC-SHA256 under a local key, never by a plain hash:
an unsalted SHA-256 of a phone number can be reversed by enumerating every phone number. The key
comes from `AIRLOCK_AUDIT_HASH_KEY`, or is generated once and stored (mode 600) at
`AIRLOCK_AUDIT_HASH_KEY_FILE` (default `./.airlock/audit_hash.key`). It is never served over HTTP.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path

from airlock.config import Settings


class Hasher:
    def __init__(self, key: bytes):
        if not key:
            raise ValueError("audit hash key must not be empty")
        self._key = key

    def __call__(self, text: str) -> str:
        return hmac.new(self._key, text.encode("utf-8"), hashlib.sha256).hexdigest()

    def __repr__(self) -> str:  # never reveal the key in logs or tracebacks
        return "Hasher(<hidden>)"


def load_key(settings: Settings) -> bytes:
    if settings.audit_hash_key:
        return settings.audit_hash_key.encode("utf-8")
    path = Path(settings.audit_hash_key_file).expanduser()
    if not path.is_file():
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass  # created concurrently; read it below
        else:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(secrets.token_hex(32) + "\n")
    key = path.read_text(encoding="utf-8").strip()
    if not key:
        raise ValueError(f"audit hash key file {path} is empty")
    return key.encode("utf-8")


def hasher_for(settings: Settings) -> Hasher:
    return Hasher(load_key(settings))
