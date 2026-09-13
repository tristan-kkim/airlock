"""Private research agent: Nemotron 3 Ultra plans with tools, Airlock gates every hop that leaves.

    POST /v1/agent/run            {"question": "...", "docs": [{"name": "...", "text": "..."}]}
    POST /v1/agent/run?stream=1   same, as server-sent events (one event per step and hop)
    airlock agent "question" --docs ./private_docs

Tools:

* `list_local_docs()` and `read_local_doc(doc_id)` run on this machine. A document enters the
  conversation as a tool result, and like everything else in the conversation it reaches the cloud
  model only through the sanitizer and the gate.
* `web_search(query)` goes to Tavily through the search-intent guard (`airlock.search_guard`).
* `finish(answer)` ends the run. The answer is rehydrated locally.

Every planning turn is an egress hop to `upstream` (`kind` prompt for the first turn, tool_result
after that), and every search is a hop to `tavily` (`kind` search_query). All hops land in one
audit record (`kind: agent`, `hops: [...]`).

The local history holds the originals. Each turn, the whole history is sanitized again with the
run's vault session, so a value keeps the same placeholder for the whole run and the model's tool
calls (which use placeholders) are restored locally before a tool runs.

`guard=False` exists only to measure what an unprotected agent leaks (eval/agent). It sends raw
documents and raw queries, still records every hop, and refuses to run unless
`AIRLOCK_ALLOW_UNGUARDED=1`. The HTTP endpoint and the CLI never expose it.
"""

from __future__ import annotations

import copy
import json
import re
import secrets
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from airlock import gate
from airlock.agent_settings import AgentSettings
from airlock.audit import AuditLog, AuditRecord
from airlock.config import Settings
from airlock.detect.llm import LocalModelError, block_reason, load_prompt
from airlock.egress import EgressEvent, EgressPolicy
from airlock.hashing import Hasher
from airlock.pipeline import Detection, PayloadError, Sanitizer, dedupe_detections
from airlock.rehydrate import rehydrate_arguments, rehydrate_text
from airlock.search_guard import SearchGuard
from airlock.upstream import Upstream, UpstreamError
from airlock.vault import Vault, VaultSession

TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "list_local_docs",
            "description": "List the user's private documents on this computer (id and title).",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_local_doc",
            "description": "Read one of the user's local documents by id.",
            "parameters": {
                "type": "object",
                "properties": {
                    "doc_id": {"type": "string", "description": "id from list_local_docs"}
                },
                "required": ["doc_id"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Search the public web. Returns titles, URLs and snippets.",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "finish",
            "description": "Give the final answer to the user and end the task.",
            "parameters": {
                "type": "object",
                "properties": {"answer": {"type": "string"}},
                "required": ["answer"],
                "additionalProperties": False,
            },
        },
    },
]
FINISH_ONLY = [t for t in TOOLS if t["function"]["name"] == "finish"]
STEP_LIMIT_NOTE = "Step limit reached. Call finish now with the best answer you can give."
SEARCH_BLOCKED_NOTE = (
    "web_search was withheld by the user's privacy firewall: the query would reveal private "
    "details. Continue without it, or search for a more general topic."
)
DOC_CHARS = 12000
RESULT_CHARS = 500


class UnguardedNotAllowed(RuntimeError):
    pass


class SearchBackend(Protocol):
    async def search(self, body: bytes) -> dict[str, Any]: ...


@dataclass
class LocalDoc:
    doc_id: str
    name: str
    text: str

    @property
    def title(self) -> str:
        for line in self.text.splitlines():
            stripped = line.strip().lstrip("#").strip()
            if stripped:
                return stripped[:120]
        return self.name


def make_docs(items: list[tuple[str, str]]) -> list[LocalDoc]:
    """Documents get neutral ids (doc-1, ...): file names often carry the private situation."""
    return [LocalDoc(f"doc-{i}", name, text) for i, (name, text) in enumerate(items, start=1)]


def load_docs_dir(path: str | Path, max_docs: int = 50) -> list[LocalDoc]:
    root = Path(path)
    files = sorted(p for p in root.iterdir() if p.is_file() and p.suffix.lower() in {".md", ".txt"})
    return make_docs([(p.name, p.read_text(encoding="utf-8")) for p in files[:max_docs]])


@dataclass
class AgentResult:
    run_id: str
    status: str  # finished | max_steps | blocked | error
    answer: str
    steps: int
    events: list[dict[str, Any]] = field(default_factory=list)
    audit: dict[str, Any] | None = None


def _json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False)


class AgentRunner:
    def __init__(
        self,
        settings: Settings,
        agent: AgentSettings,
        *,
        sanitizer: Sanitizer,
        upstream: Upstream,
        search_backend: SearchBackend,
        guard: SearchGuard,
        hasher: Hasher | Callable[[str], str],
        audit: AuditLog | None = None,
        vault: Vault | None = None,
    ):
        self.settings = settings
        self.agent = agent
        self.sanitizer = sanitizer
        self.upstream = upstream
        self.search_backend = search_backend
        self.guard = guard
        self.hasher = hasher
        self.audit = audit
        self.vault = vault or sanitizer.vault
        self.system_prompt = load_prompt("agent_system.md")

    # ------------------------------------------------------------------ helpers
    def _context(self, question: str, docs: list[LocalDoc], read: set[str]) -> str:
        """Private context for the local search rewriter (never leaves the machine)."""
        parts = [f"User question: {question}"]
        for doc in docs:
            if doc.doc_id in read:
                parts.append(f"Document {doc.title}:\n{doc.text[:900]}")
        return "\n\n".join(parts)

    def _body(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
        body: dict[str, Any] = {
            "messages": messages,
            "tools": tools,
            "tool_choice": "auto",
            "max_tokens": self.agent.max_tokens,
            "temperature": 0.2,
        }
        if self.agent.reasoning_effort:
            body["reasoning_effort"] = self.agent.reasoning_effort
        return body

    async def _search(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        resp = await self.search_backend.search(body)
        results = []
        for r in (resp.get("results") or [])[: self.agent.search_max_results]:
            if isinstance(r, dict):
                results.append(
                    {
                        "title": r.get("title"),
                        "url": r.get("url"),
                        "content": str(r.get("content") or "")[:RESULT_CHARS],
                    }
                )
        return results

    # ------------------------------------------------------------------ run
    async def events(
        self,
        question: str,
        docs: list[LocalDoc],
        *,
        guard: bool = True,
        max_steps: int | None = None,
        run_id: str | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        """Run the agent and yield trace events. The last event is always `done`.

        Events are a local-only view: `local` fields hold originals and must never be forwarded.
        The audit record holds only what left the machine, plus keyed hashes.
        """
        if not guard and not self.agent.allow_unguarded:
            raise UnguardedNotAllowed(
                "unguarded agent runs are for evaluation only: set AIRLOCK_ALLOW_UNGUARDED=1"
            )
        run_id = run_id or "run_" + secrets.token_hex(12)
        max_steps = max(1, min(max_steps or self.agent.max_steps, self.agent.max_steps))
        record = AuditRecord("agent")
        policy = EgressPolicy(record, self.hasher, guard=guard)
        session: VaultSession = self.vault.session(f"agent:{run_id}")
        by_id = {d.doc_id: d for d in docs}
        read: set[str] = set()
        detections: list[Detection] = []
        counts = {"searches": 0, "search_rewritten": 0, "search_allowed": 0, "search_blocked": 0}
        record.meta.update(
            {
                "run_id_hmac": self.hasher(run_id),
                "guard": guard,
                "max_steps": max_steps,
                "docs": len(docs),
                "search_judge": self.agent.search_judge if guard else None,
            }
        )
        status, answer, steps = "error", "", 0
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": question},
        ]
        prev_outbound = 0
        prev_local = 0
        t_run = time.perf_counter()

        yield {
            "type": "run_started",
            "run_id": run_id,
            "request_id": record.request_id,
            "guard": guard,
            "max_steps": max_steps,
            "docs": [{"id": d.doc_id, "title": d.title} for d in docs],
            "question": question,
        }

        try:
            for step in range(1, max_steps + 1):
                steps = step
                last = step == max_steps
                if last:
                    messages.append({"role": "user", "content": STEP_LIMIT_NOTE})
                body = self._body(messages, FINISH_ONLY if last else TOOLS)
                kind = "prompt" if step == 1 else "tool_result"
                started = time.perf_counter()

                # -- sanitize + gate the planning turn ---------------------------------------
                if guard:
                    try:
                        payload, protected, extra, found = await self._sanitize_turn(body, session)
                    except LocalModelError as exc:
                        reasons = [block_reason(exc)]
                        event = EgressEvent("upstream", kind, None, step)
                        policy.record_hop(event, "block", reasons=reasons, started=started)
                        status = "blocked"
                        yield self._hop_event(
                            record, step, kind, "block", reasons, [], messages, prev_local
                        )
                        break
                    detections += found
                else:
                    payload = {"model": self.settings.upstream_model, **copy.deepcopy(body)}
                    protected, extra = [], []

                event = EgressEvent("upstream", kind, payload, step)
                decision = policy.check(event, protected, extra)
                if not decision.allowed:
                    policy.record_hop(event, "block", reasons=decision.reasons, started=started)
                    status = "blocked"
                    yield self._hop_event(
                        record, step, kind, "block", decision.reasons, [], messages, prev_local
                    )
                    break

                try:
                    result = await self.upstream.send(
                        payload, lambda sent: policy.sent("upstream", sent)
                    )
                except UpstreamError as exc:
                    policy.record_hop(
                        event, "allow", sent=payload, meta={"error": str(exc)}, started=started
                    )
                    status = "error"
                    yield {"type": "error", "step": step, "message": f"upstream error: {exc}"}
                    break
                hop = policy.record_hop(
                    event,
                    "allow",
                    sent=payload,
                    meta={"model_used": result.model_used, "fallback": result.fallback},
                    started=started,
                )
                outbound_msgs = payload.get("messages") or []
                yield {
                    "type": "hop",
                    "hop": hop.index,
                    "step": step,
                    "destination": "upstream",
                    "kind": kind,
                    "decision": "allow",
                    "reasons": [],
                    "outbound": outbound_msgs[prev_outbound:],
                    "local": messages[prev_local:],
                    "model_used": result.model_used,
                    "ms": round(hop.ms, 1),
                }
                prev_outbound, prev_local = len(outbound_msgs), len(messages)

                # -- the model's reply (inbound): rehydrate locally ----------------------------
                choice = ((result.data or {}).get("choices") or [{}])[0]
                message = choice.get("message") or {}
                content = message.get("content")
                if guard and isinstance(content, str):
                    content = rehydrate_text(content, session)
                calls = []
                for call in message.get("tool_calls") or []:
                    fn = call.get("function") if isinstance(call, dict) else None
                    if not isinstance(fn, dict):
                        continue
                    raw_args = fn.get("arguments") or "{}"
                    local_args = rehydrate_arguments(raw_args, session) if guard else raw_args
                    calls.append(
                        {
                            "id": call.get("id") or f"call_{step}_{len(calls)}",
                            "name": fn.get("name") or "",
                            "model_arguments": raw_args,
                            "arguments": local_args,
                        }
                    )
                messages.append(
                    {
                        "role": "assistant",
                        "content": content
                        if isinstance(content, str) and content.strip()
                        else None,
                        **(
                            {
                                "tool_calls": [
                                    {
                                        "id": c["id"],
                                        "type": "function",
                                        "function": {
                                            "name": c["name"],
                                            "arguments": c["arguments"],
                                        },
                                    }
                                    for c in calls
                                ]
                            }
                            if calls
                            else {}
                        ),
                    }
                )
                if not calls:
                    answer = (content or "").strip()
                    status = "finished" if answer else "error"
                    break

                finished = False
                for call in calls:
                    try:
                        args = json.loads(call["arguments"] or "{}")
                    except json.JSONDecodeError:
                        args = {}
                    if not isinstance(args, dict):
                        args = {}
                    name = call["name"]
                    if name == "finish":
                        answer = str(
                            args.get("answer") or salvage_answer(call["arguments"]) or content or ""
                        ).strip()
                        messages.append(
                            {"role": "tool", "tool_call_id": call["id"], "content": "done"}
                        )
                        finished = True
                        yield {"type": "tool", "step": step, "name": "finish", "executed": "local"}
                        break
                    if name == "list_local_docs":
                        output = _json([{"doc_id": d.doc_id, "title": d.title} for d in docs])
                        yield {
                            "type": "tool",
                            "step": step,
                            "name": name,
                            "executed": "local",
                            "summary": f"{len(docs)} document(s)",
                        }
                    elif name == "read_local_doc":
                        doc = by_id.get(str(args.get("doc_id") or "").strip())
                        if doc is None:
                            output = "error: unknown doc_id"
                        else:
                            read.add(doc.doc_id)
                            output = doc.text[:DOC_CHARS]
                        yield {
                            "type": "tool",
                            "step": step,
                            "name": name,
                            "executed": "local",
                            "doc_id": doc.doc_id if doc else None,
                            "summary": doc.title if doc else "unknown doc_id",
                            "chars": len(output),
                        }
                    elif name == "web_search":
                        output, search_event = await self._web_search(
                            str(args.get("query") or ""),
                            call["model_arguments"],
                            question,
                            docs,
                            read,
                            session,
                            policy,
                            step,
                            guard,
                            counts,
                        )
                        yield search_event
                    else:
                        output = f"error: unknown tool {name!r}"
                    messages.append({"role": "tool", "tool_call_id": call["id"], "content": output})
                if finished:
                    status = "finished"
                    break
            else:
                status = "max_steps"
        except PayloadError as exc:
            status = "error"
            yield {"type": "error", "message": f"invalid request: {exc}"}
        except Exception as exc:  # noqa: BLE001 - the trace must always end with done
            status = "error"
            yield {"type": "error", "message": f"{type(exc).__name__}"}

        if status == "max_steps" and not answer:
            last_msg = messages[-1] if messages else {}
            answer = (
                str(last_msg.get("content") or "") if last_msg.get("role") == "assistant" else ""
            )
        record.detections = [d.audit(self.hasher) for d in dedupe_detections(detections)]
        record.meta.update({"status": status, "steps": steps, **counts})
        record.gate = {
            "decision": "block" if status == "blocked" else "allow",
            "reasons": [
                r
                for h in record.hops
                for r in h.get("reasons", [])
                if h["decision"] == "block" and h["destination"] == "upstream"
            ],
        }
        record.timings_ms["run"] = round((time.perf_counter() - t_run) * 1000, 1)
        originals = [m.original for m in session.mappings()] + [question]
        audit_data = self.audit.write(record, originals) if self.audit else record.to_dict()
        yield {
            "type": "final",
            "status": status,
            "answer": answer,
            "steps": steps,
            **counts,
        }
        yield {
            "type": "done",
            "run_id": run_id,
            "request_id": record.request_id,
            "audit": audit_data,
        }

    async def _sanitize_turn(
        self, body: dict[str, Any], session: VaultSession
    ) -> tuple[dict[str, Any], list[Any], list[str], list[Detection]]:
        """Sanitize the whole history; converge once if a value was detected in only some slots.

        Detection runs per text slot, and a new mapping reaches other slots only on the next
        sanitization. A turn with several new tool results can therefore hold a value that was
        masked in one document but missed in another, which the gate would block. One more pass
        applies this turn's mappings to every slot (the detector cache makes it cheap). The gate
        still decides on the final payload.
        """
        sanitized = await self.sanitizer.sanitize_chat(body, session)
        first = gate.check(
            sanitized.payload,
            sanitized.protected,
            hasher=self.hasher,
            extra_reasons=sanitized.extra_reasons,
        )
        if not first.allowed and all(r.startswith("vault_original:") for r in first.reasons):
            sanitized = await self.sanitizer.sanitize_chat(body, session)
        return (
            sanitized.payload,
            sanitized.protected,
            sanitized.extra_reasons,
            sanitized.detections,
        )

    def _hop_event(
        self,
        record: AuditRecord,
        step: int,
        kind: str,
        decision: str,
        reasons: list[str],
        outbound: list[Any],
        messages: list[dict[str, Any]],
        prev_local: int,
    ) -> dict[str, Any]:
        return {
            "type": "hop",
            "hop": len(record.hops),
            "step": step,
            "destination": "upstream",
            "kind": kind,
            "decision": decision,
            "reasons": reasons,
            "outbound": outbound,
            "local": messages[prev_local:],
        }

    async def _web_search(
        self,
        local_query: str,
        model_arguments: str,
        question: str,
        docs: list[LocalDoc],
        read: set[str],
        session: VaultSession,
        policy: EgressPolicy,
        step: int,
        guard: bool,
        counts: dict[str, int],
    ) -> tuple[str, dict[str, Any]]:
        counts["searches"] += 1
        started = time.perf_counter()
        try:
            model_query = str(json.loads(model_arguments).get("query") or "")
        except (json.JSONDecodeError, AttributeError):
            model_query = ""
        base = {
            "type": "hop",
            "step": step,
            "destination": "tavily",
            "kind": "search_query",
            "local_query": local_query,
            "model_query": model_query,
        }
        meta: dict[str, Any] = {"original_query_hmac": self.hasher(local_query)}

        if not guard:
            payload = self.guard.payload_for(clean(local_query))
            event = EgressEvent("tavily", "search_query", payload, step)
            decision_name = "allow"
            result_meta: dict[str, Any] = {"outbound_query": payload["query"]}
            guard_extra: dict[str, Any] = {}
        else:
            context = self._context(question, docs, read)
            g = await self.guard.run(local_query, context, session)
            meta.update(
                {
                    "attempts": [a.audit(self.hasher) for a in g.attempts],
                    "judge": g.judge,
                    "judge_mode": self.agent.search_judge,
                    "timings_ms": g.timings_ms,
                }
            )
            guard_extra = {
                "judge": g.judge,
                "attempts": [
                    {"candidate": a.candidate, "gate_reasons": a.gate_reasons, "judge": a.judge}
                    for a in g.attempts
                ],
            }
            if not g.sent:
                counts["search_blocked"] += 1
                event = EgressEvent("tavily", "search_query", None, step)
                hop = policy.record_hop(
                    event,
                    "block",
                    reasons=g.reasons,
                    meta={**meta, "outbound_query": None},
                    started=started,
                )
                return SEARCH_BLOCKED_NOTE, {
                    **base,
                    "hop": hop.index,
                    "decision": "block",
                    "reasons": g.reasons,
                    "outbound_query": None,
                    "results": 0,
                    "ms": round(hop.ms, 1),
                    **guard_extra,
                }
            payload = g.payload or {}
            event = EgressEvent("tavily", "search_query", payload, step)
            decision_name = "rewritten" if g.decision == "rewritten" else "allow"
            counts["search_rewritten" if decision_name == "rewritten" else "search_allowed"] += 1
            result_meta = {"outbound_query": g.outbound_query}

        if not guard:
            counts["search_allowed"] += 1
        policy.sent("tavily", payload)
        hop = policy.record_hop(
            event, decision_name, sent=payload, meta={**meta, **result_meta}, started=started
        )
        try:
            results = await self._search(payload)
            output = _json(results)
        except Exception as exc:  # noqa: BLE001 - a failed search never ends the run
            results = []
            output = f"web_search failed: {type(exc).__name__}"
        policy.update_hop(hop, ms=(time.perf_counter() - started) * 1000)
        return output, {
            **base,
            "hop": hop.index,
            "decision": decision_name,
            "reasons": [],
            "outbound_query": result_meta["outbound_query"],
            "results": len(results),
            "result_titles": [r.get("title") for r in results],
            "ms": round(hop.ms, 1),
            **guard_extra,
        }

    async def run(self, question: str, docs: list[LocalDoc], **kwargs: Any) -> AgentResult:
        events: list[dict[str, Any]] = []
        async for ev in self.events(question, docs, **kwargs):
            events.append(ev)
        final = next(e for e in events if e["type"] == "final")
        done = events[-1]
        return AgentResult(
            run_id=done["run_id"],
            status=final["status"],
            answer=final["answer"],
            steps=final["steps"],
            events=events,
            audit=done.get("audit"),
        )


_ANSWER_START = re.compile(r'"answer"\s*:\s*"')


def salvage_answer(arguments: str) -> str:
    """The answer from finish() arguments whose JSON was cut off (for example at max_tokens)."""
    m = _ANSWER_START.search(arguments or "")
    if not m:
        return ""
    body = arguments[m.end() :]
    body = re.sub(r'(?<!\\)"\s*\}?\s*$', "", body)
    for end in range(len(body), max(len(body) - 8, -1), -1):
        try:
            return json.loads('"' + body[:end] + '"')
        except json.JSONDecodeError:
            continue
    return body.replace("\\n", "\n")


def clean(query: str) -> str:
    return re.sub(r"\s+", " ", query or "").strip()[:400]
