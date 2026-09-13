"""Private web search: rewrite the query locally, gate it, call Tavily, re-rank locally."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

import httpx

from airlock import gate
from airlock.audit import AuditRecord
from airlock.config import Settings
from airlock.detect.llm import LocalModel, LocalModelError, block_reason, load_prompt
from airlock.detect.spans import contains_placeholder, normalize
from airlock.pipeline import Detection, Sanitizer, dedupe_detections
from airlock.vault import Vault

REWRITE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"query": {"type": "string"}},
    "required": ["query"],
    "additionalProperties": False,
}
RERANK_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"order": {"type": "array", "items": {"type": "integer"}}},
    "required": ["order"],
    "additionalProperties": False,
}


class SearchBlocked(Exception):
    def __init__(self, reasons: list[str]):
        super().__init__(", ".join(reasons))
        self.reasons = reasons


class SearchNotConfigured(Exception):
    pass


class TavilyError(Exception):
    pass


class Tavily:
    def __init__(self, settings: Settings, client: httpx.AsyncClient):
        self.settings = settings
        self.client = client

    async def search(self, body: bytes) -> dict[str, Any]:
        if not self.settings.tavily_api_key:
            raise SearchNotConfigured("TAVILY_API_KEY is not set")
        try:
            resp = await self.client.post(
                f"{self.settings.tavily_base_url}/search",
                content=body,
                headers={
                    # Key goes in the header so the audited JSON body holds no credential.
                    "Authorization": f"Bearer {self.settings.tavily_api_key}",
                    "Content-Type": "application/json",
                },
                timeout=30,
            )
        except httpx.HTTPError as exc:
            raise TavilyError(f"tavily unreachable: {type(exc).__name__}") from exc
        if resp.status_code >= 400:
            raise TavilyError(f"tavily returned HTTP {resp.status_code}")
        return resp.json()


_WORD = re.compile(r"[\w가-힣]{2,}", re.UNICODE)


def lexical_order(results: list[dict[str, Any]], query: str, context: str | None) -> list[int]:
    wanted = {w.casefold() for w in _WORD.findall(f"{query} {context or ''}")}

    def score(i: int) -> tuple[int, int]:
        r = results[i]
        words = {
            w.casefold() for w in _WORD.findall(f"{r.get('title', '')} {r.get('content', '')}")
        }
        return (-len(wanted & words), i)

    return sorted(range(len(results)), key=score)


class PrivateSearch:
    def __init__(
        self,
        settings: Settings,
        local: LocalModel,
        sanitizer: Sanitizer,
        tavily: Tavily,
        hasher: Callable[[str], str],
    ):
        self.hasher = hasher
        self.settings = settings
        self.local = local
        self.sanitizer = sanitizer
        self.tavily = tavily
        # Search mappings are never rehydrated, so they live in a throwaway in-memory vault.
        self._scratch = Vault(":memory:")
        self._rewrite_prompt = load_prompt("search_rewrite.md")
        self._rerank_prompt = load_prompt("search_rerank.md")

    async def run(
        self, query: str, context: str | None, max_results: int, record: AuditRecord
    ) -> dict[str, Any]:
        session = self._scratch.session(record.request_id)

        # 1. Detect what is private in the query and context (fail closed on model errors).
        record.start("detect")
        protected: list[gate.Protected] = []
        detections: list[Detection] = []
        try:
            for text in (query, context or ""):
                if not text.strip():
                    continue
                result = await self.sanitizer.sanitize_text(text, session)
                protected += result.protected
                detections += result.detections
        except LocalModelError as exc:
            raise SearchBlocked([block_reason(exc)]) from exc
        finally:
            record.stop("detect")
        detections = dedupe_detections(detections)
        record.detections = [d.audit(self.hasher) for d in detections]
        # Generalized spans (a condition, an age range) are the *topic* of a search and may
        # appear in the rewritten query. Masked values (names, contacts, IDs, secrets) may not.
        generalized = {normalize(d.text) for d in detections if d.action == "generalize"}
        protected = [p for p in protected if normalize(p.text) not in generalized]

        # 2. Rewrite locally.
        record.start("rewrite")
        try:
            user = json.dumps({"query": query, "private_context": context}, ensure_ascii=False)
            data = await self.local.chat_json(
                self._rewrite_prompt, user, REWRITE_SCHEMA, "airlock_search_query", max_tokens=200
            )
            rewritten = str(data.get("query", "") if isinstance(data, dict) else "").strip()
        except LocalModelError as exc:
            raise SearchBlocked([block_reason(exc, "local_rewriter")]) from exc
        finally:
            record.stop("rewrite")
        rewritten = re.sub(r"\s+", " ", rewritten).strip().strip('"')[:400]

        # 3. Deterministic gate on the exact Tavily payload.
        payload = {
            "query": rewritten,
            "max_results": max_results,
            "search_depth": "basic",
            "include_answer": True,
        }
        record.start("gate")
        extra = []
        if not rewritten:
            extra.append("rewrite_empty")
        if contains_placeholder(rewritten):
            extra.append("rewrite_contains_placeholder")
        decision = gate.check(
            payload,
            protected + self.sanitizer.standing_protected(),
            hasher=self.hasher,
            extra_reasons=extra,
        )
        record.stop("gate")
        record.gate = decision.as_dict()
        if not decision.allowed:
            raise SearchBlocked(decision.reasons)

        # 4. Search.
        if not self.settings.tavily_api_key:
            raise SearchNotConfigured("TAVILY_API_KEY is not set")
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        record.add_outbound("tavily", json.loads(body))
        record.start("tavily")
        try:
            resp = await self.tavily.search(body)
        finally:
            record.stop("tavily")
        raw_results = [r for r in (resp.get("results") or []) if isinstance(r, dict)]

        # 5. Re-rank locally against the private context.
        record.start("rerank")
        order = await self._rerank(query, context, raw_results)
        record.stop("rerank")
        results = []
        for rank, idx in enumerate(order, start=1):
            r = raw_results[idx]
            results.append(
                {
                    "title": r.get("title"),
                    "url": r.get("url"),
                    "content": r.get("content"),
                    "score": r.get("score"),
                    "local_rank": rank,
                }
            )
        return {
            "request_id": record.request_id,
            "outbound_query": rewritten,
            "results": results,
            "answer": resp.get("answer") or None,
        }

    async def _rerank(
        self, query: str, context: str | None, results: list[dict[str, Any]]
    ) -> list[int]:
        if len(results) <= 1:
            return list(range(len(results)))
        listing = [
            {"index": i, "title": r.get("title"), "snippet": str(r.get("content") or "")[:300]}
            for i, r in enumerate(results)
        ]
        user = json.dumps(
            {"question": query, "private_context": context, "results": listing}, ensure_ascii=False
        )
        try:
            data = await self.local.chat_json(
                self._rerank_prompt, user, RERANK_SCHEMA, "airlock_rerank", max_tokens=200
            )
            order = [int(i) for i in data.get("order", []) if 0 <= int(i) < len(results)]
        except (LocalModelError, AttributeError, TypeError, ValueError):
            return lexical_order(results, query, context)
        order = list(dict.fromkeys(order))
        order += [i for i in range(len(results)) if i not in order]
        return order
