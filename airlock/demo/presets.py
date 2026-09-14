"""Fictional one-click demo scenarios, their live runner, and recorded fallbacks.

Every name, number, company, clinic and document below is invented for this demo. Each preset
produces the same three views as the main UI: what you typed, what the cloud saw, and the answer.
When the demo budget is spent (or a live run fails), the preset serves a recorded run captured
from a real run of the same preset, clearly labeled as such (`scripts/demo/record_presets.py`).
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from importlib import resources
from typing import Any, Literal

import httpx

Mode = Literal["chat", "search", "agent"]
TEXT_LIMIT = 4000
DETECTOR_FAILURE_PREFIXES = ("local_detector_unavailable", "local_detector_malformed")


@dataclass(frozen=True)
class Preset:
    id: str
    title: str
    lang: Literal["en", "ko"]
    mode: Mode
    blurb: str
    message: str = ""  # chat
    query: str = ""  # search
    context: str = ""  # search: private context, used only on the demo server
    question: str = ""  # agent
    docs: tuple[tuple[str, str], ...] = field(default_factory=tuple)  # agent: (name, text)

    def public(self) -> dict[str, Any]:
        data = asdict(self)
        data["docs"] = [{"name": n, "text": t} for n, t in self.docs]
        return data


PRESETS: tuple[Preset, ...] = (
    Preset(
        id="chat-medical-en",
        title="Medical leave note",
        lang="en",
        mode="chat",
        blurb="Name, email, phone and a diagnosis in a request to draft a note.",
        message=(
            "Hi, I'm Jane Park (jane.park@example.com, 010-5555-0142). I'm 34 and was just "
            "diagnosed with type 1 diabetes at Hanbit Clinic. Draft a short note to my manager, "
            "Tom Reyes, asking for flexible hours for the next two months."
        ),
    ),
    Preset(
        id="chat-rent-ko",
        title="월세 송금 문자",
        lang="ko",
        mode="chat",
        blurb="주민등록번호와 계좌번호가 섞인 한국어 요청.",
        message=(
            "김민수(주민번호 900101-1234567)에게 신한은행 110-234-567890 계좌로 이번 달 월세 "
            "85만원을 보내야 해. 집주인 이영희 님께 보낼 정중한 문자를 써줘."
        ),
    ),
    Preset(
        id="chat-secrets-en",
        title="Secrets in a bug report",
        lang="en",
        mode="chat",
        blurb="A database password and an API key pasted into a debugging question.",
        message=(
            "Why does my app crash on startup? My config has "
            "DATABASE_URL=postgres://admin:hunter22@db.internal:5432/prod and "
            "OPENAI_API_KEY=sk-proj-Zx8Qw3Er5Ty7Ui9Op1As2Df4Gh6Jk. The log says "
            "'connection refused'."
        ),
    ),
    Preset(
        id="search-layoff-en",
        title="Private web search: layoff",
        lang="en",
        mode="search",
        blurb="The search query is rewritten so Tavily never sees who is asking or why.",
        query="Can my employer cut my role without severance?",
        context=(
            "I'm Minji Lee, a senior analyst at Seoul Mirae Bank, employee ID 20231187. HR told me "
            "on Friday that my role is being cut at the end of the month."
        ),
    ),
    Preset(
        id="agent-resignation-ko",
        title="리서치 에이전트: 희망퇴직 통보",
        lang="ko",
        mode="agent",
        blurb="비공개 문서 두 건을 가진 에이전트가 Ultra로 계획하고 Tavily로 검색한다.",
        question=(
            "회사에서 받은 문서야. 여기에 서명해야 하는지, 위로금 조건이 괜찮은지, "
            "실업급여는 받을 수 있는지 알려줘."
        ),
        docs=(
            (
                "퇴직_합의서.md",
                "# 퇴직 합의서\n\n본인 박성훈(사번 DN-19044)은 동해누리정밀(주)와 아래와 같이 "
                "합의한다.\n\n1. 본인은 자발적 의사로 2026년 10월 31일자로 퇴직한다.\n"
                "2. 회사는 법정 퇴직금 외에 위로금 3개월분을 지급한다.\n"
                "3. 본인은 본 합의 이후 회사에 대하여 퇴직과 관련한 어떠한 민·형사상 이의도 "
                "제기하지 않는다.\n4. 본 합의 내용은 제3자에게 누설하지 않는다.\n",
            ),
            (
                "희망퇴직_안내.md",
                "# 희망퇴직 대상자 개별 통보\n\n수신: 품질보증팀 박성훈 팀장 (사번 DN-19044)\n"
                "발신: 동해누리정밀(주) 인사총무팀\n\n당사는 조직 개편에 따라 품질보증팀을 "
                "생산기술팀으로 통합하기로 결정하였습니다. 이에 귀하를 희망퇴직 대상자로 "
                "선정하였음을 알려드립니다.\n\n## 조건\n\n1. 퇴직일: 2026년 10월 31일\n"
                "2. 법정 퇴직금 외 위로금 3개월분 통상임금 지급 (약 1,650만원)\n"
                "3. 잔여 연차수당 정산\n\n## 기한\n\n동봉한 「퇴직 합의서」에 2026년 9월 25일까지 "
                "서명하여 제출해 주시기 바랍니다.\n",
            ),
        ),
    ),
)

PRESETS_BY_ID = {p.id: p for p in PRESETS}


# ---------------------------------------------------------------- recorded runs
def load_recorded() -> dict[str, dict[str, Any]]:
    """Recorded runs shipped with the package (airlock/demo/recorded/<preset_id>.json)."""
    out: dict[str, dict[str, Any]] = {}
    folder = resources.files("airlock.demo").joinpath("recorded")
    if not folder.is_dir():
        return out
    for item in folder.iterdir():
        if item.name.endswith(".json"):
            data = json.loads(item.read_text("utf-8"))
            if data.get("preset_id") in PRESETS_BY_ID:
                out[data["preset_id"]] = data
    return out


def as_recorded(result: dict[str, Any], reason: str) -> dict[str, Any]:
    return {**result, "source": "recorded", "fallback_reason": reason}


# ---------------------------------------------------------------- normalization
def _clip(text: Any, limit: int = TEXT_LIMIT) -> str:
    s = text if isinstance(text, str) else json.dumps(text, ensure_ascii=False)
    return s if len(s) <= limit else s[:limit] + f"\n… ({len(s) - limit} more characters)"


def _message_text(m: dict[str, Any]) -> str:
    body = m.get("content") if isinstance(m.get("content"), str) else ""
    calls = [
        f"{(c.get('function') or {}).get('name')}({(c.get('function') or {}).get('arguments', '')})"
        for c in m.get("tool_calls") or []
    ]
    return "\n".join(x for x in [body, *calls] if x)


def _detections(audit: dict[str, Any] | None) -> list[dict[str, str]]:
    # Types and actions only: the keyed hashes mean nothing outside this session.
    return [
        {"type": d.get("type", ""), "action": d.get("action", ""), "source": d.get("source", "")}
        for d in (audit or {}).get("detections") or []
    ]


def _base(preset: Preset, models: dict[str, str]) -> dict[str, Any]:
    return {
        "preset_id": preset.id,
        "title": preset.title,
        "mode": preset.mode,
        "lang": preset.lang,
        "source": "live",
        "fallback_reason": None,
        "recorded_at": None,
        "models": models,
    }


def chat_result(
    preset: Preset, status: int, data: dict[str, Any], audit: dict[str, Any] | None, models
) -> dict[str, Any]:
    out = _base(preset, models)
    outbound = (audit or {}).get("outbound") or []
    sent = outbound[-1]["payload"].get("messages", []) if outbound else []
    out.update(
        typed=[{"label": "user", "text": preset.message}],
        cloud_saw=[
            {"destination": "upstream", "label": m.get("role", ""), "text": _clip(_message_text(m))}
            for m in sent
        ],
        answer=(data.get("choices") or [{}])[0].get("message", {}).get("content")
        if status == 200
        else None,
        error=None if status == 200 else (data.get("error") or {"type": f"http_{status}"}),
        gate=(audit or {}).get("gate") or {},
        detections=_detections(audit),
        timings_ms=(audit or {}).get("timings_ms") or {},
        model_used=((audit or {}).get("meta") or {}).get("model_used"),
    )
    return out


def search_result(
    preset: Preset, status: int, data: dict[str, Any], audit: dict[str, Any] | None, models
) -> dict[str, Any]:
    out = _base(preset, models)
    outbound = (audit or {}).get("outbound") or []
    out.update(
        typed=[
            {"label": "query", "text": preset.query},
            {"label": "private context", "text": preset.context},
        ],
        cloud_saw=[
            {
                "destination": "tavily",
                "label": "search query",
                "text": o["payload"].get("query", ""),
            }
            for o in outbound
            if o.get("destination") == "tavily"
        ],
        answer=None,
        results=[
            {
                "rank": r.get("local_rank"),
                "title": r.get("title"),
                "url": r.get("url"),
                "snippet": _clip(r.get("content") or "", 280),
            }
            for r in (data.get("results") or [])
        ]
        if status == 200
        else [],
        error=None if status == 200 else (data.get("error") or {"type": f"http_{status}"}),
        gate=(audit or {}).get("gate") or {},
        detections=_detections(audit),
        timings_ms=(audit or {}).get("timings_ms") or {},
    )
    return out


def agent_result(
    preset: Preset, status: int, data: dict[str, Any], audit: dict[str, Any] | None, models
) -> dict[str, Any]:
    out = _base(preset, models)
    cloud: list[dict[str, Any]] = []
    for ev in data.get("trace") or []:
        if ev.get("type") != "hop":
            continue
        if ev.get("destination") == "upstream":
            msgs = [m for m in ev.get("outbound") or [] if m.get("role") != "system"]
            text = "\n\n".join(f"[{m.get('role')}] {_message_text(m)}" for m in msgs)
            cloud.append(
                {
                    "destination": "upstream",
                    "label": f"step {ev.get('step')} → Nemotron 3 Ultra ({ev.get('decision')})",
                    "text": _clip(text or "(nothing new)", 2400),
                }
            )
        elif ev.get("destination") == "tavily":
            cloud.append(
                {
                    "destination": "tavily",
                    "label": f"step {ev.get('step')} → Tavily ({ev.get('decision')})",
                    "text": ev.get("outbound_query") or "(nothing: search blocked)",
                }
            )
    out.update(
        typed=[{"label": "question", "text": preset.question}]
        + [{"label": f"local document: {n}", "text": t} for n, t in preset.docs],
        cloud_saw=cloud,
        answer=data.get("answer") if status == 200 else None,
        error=None if status == 200 else (data.get("error") or {"type": f"http_{status}"}),
        gate=(audit or {}).get("gate") or {},
        detections=_detections(audit),
        timings_ms=(audit or {}).get("timings_ms") or {},
        stats={
            k: data.get(k)
            for k in ("status", "steps", "searches", "search_rewritten", "search_blocked")
        },
    )
    return out


# ---------------------------------------------------------------- live runner
class LiveRunFailed(Exception):
    """The live run could not produce a meaningful result (5xx, not configured, bad JSON)."""


async def run_live(app: Any, preset: Preset, models: dict[str, str]) -> dict[str, Any]:
    """Run a preset against one session's Airlock app, in process, with the normal routes."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://demo.internal", timeout=300
    ) as client:
        if preset.mode == "chat":
            resp = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "airlock",
                    "messages": [{"role": "user", "content": preset.message}],
                },
                headers={"x-airlock-conversation-id": f"preset-{uuid.uuid4().hex}"},
            )
            build = chat_result
        elif preset.mode == "search":
            resp = await client.post(
                "/v1/search",
                json={"query": preset.query, "context": preset.context, "max_results": 5},
            )
            build = search_result
        else:
            resp = await client.post(
                "/v1/agent/run",
                json={
                    "question": preset.question,
                    "docs": [{"name": n, "text": t} for n, t in preset.docs],
                },
            )
            build = agent_result
        try:
            data = resp.json()
        except ValueError as exc:
            raise LiveRunFailed(f"non-JSON response (HTTP {resp.status_code})") from exc
        # 422 is a real outcome (the gate blocked the request); other errors are failures.
        if resp.status_code >= 500 or resp.status_code not in (200, 422):
            raise LiveRunFailed(f"HTTP {resp.status_code}")
        request_id = (
            resp.headers.get("x-airlock-request-id")
            or data.get("request_id")
            or (data.get("error") or {}).get("request_id")
        )
        audit = None
        if request_id:
            audit_resp = await client.get(f"/audit/{request_id}")
            if audit_resp.status_code == 200:
                audit = audit_resp.json()
        result = build(preset, resp.status_code, data, audit, models)
        result["request_id"] = request_id
        # A detector failure fails closed, which is correct but says nothing about the scenario:
        # the caller serves the recorded run instead, labeled as a fallback.
        reasons = [
            *((data.get("error") or {}).get("reasons") or []),
            *((audit or {}).get("gate") or {}).get("reasons", []),
            *(r for ev in data.get("trace") or [] for r in ev.get("reasons") or []),
        ]
        failed = [str(r) for r in reasons if str(r).startswith(DETECTOR_FAILURE_PREFIXES)]
        if failed:
            raise LiveRunFailed(f"detector failed: {failed[0]}")
        return result
