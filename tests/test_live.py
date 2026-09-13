"""Opt-in checks against the real services, using `.env`. Run with `uv run pytest -m live`.

Skipped by default so `pytest -q` stays offline. Secrets are never printed: the doctor checks
only report presence, length and HTTP status.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest

from airlock.cli import check_local, check_tavily, check_upstream
from airlock.config import load_settings

pytestmark = pytest.mark.live

ENV_FILE = Path(__file__).resolve().parents[1] / ".env"


@pytest.fixture(scope="module")
def settings():
    return load_settings(ENV_FILE)


def _run(coro_fn, settings):
    async def go():
        async with httpx.AsyncClient() as client:
            return await coro_fn(settings, client)

    return asyncio.run(go())


def test_live_upstream(settings) -> None:
    if not settings.nebius_api_key:
        pytest.skip("NEBIUS_API_KEY not set")
    checks = _run(check_upstream, settings)
    assert all(c.status != "fail" for c in checks), [(c.name, c.detail) for c in checks]


def test_live_tavily(settings) -> None:
    if not settings.tavily_api_key:
        pytest.skip("TAVILY_API_KEY not set")
    checks = _run(check_tavily, settings)
    assert all(c.status != "fail" for c in checks), [(c.name, c.detail) for c in checks]


def test_live_local_model(settings) -> None:
    checks = _run(check_local, settings)
    if checks[0].status == "fail":
        pytest.skip(f"local model server not running at {settings.local_base_url}")
    assert all(c.status != "fail" for c in checks), [(c.name, c.detail) for c in checks]
