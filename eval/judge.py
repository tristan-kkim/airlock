"""OPTIONAL answer-utility scoring for `run.py --judge`. Kept separate on purpose.

What it does, per judged chat case that Airlock answered:
1. Baseline: sends the RAW case messages (with the synthetic sensitive values) directly to an
   OpenAI-compatible endpoint. This bypasses Airlock by design. The data is fictional, but this is
   still the one place in the eval that deliberately sends unprotected prompts to a cloud model.
2. Judge: asks a model to score both answers 1-5 for how well they serve the user's request.
   Answer order is randomized per case (seeded) to limit position bias.

Environment:
    AIRLOCK_JUDGE_BASE_URL   e.g. https://api.tokenfactory.nebius.com/v1
    AIRLOCK_JUDGE_MODEL      judge model id
    NEBIUS_API_KEY           bearer token for that endpoint
    AIRLOCK_BASELINE_MODEL   optional; model for the raw-prompt baseline (default: judge model)

Search cases are not judged (a fair baseline would need a direct Tavily call). Blocked cases have
no Airlock answer and are counted separately, not scored as zero.
"""

from __future__ import annotations

import json
import os
import random
import re
import statistics
from pathlib import Path
from typing import Any

import httpx

JUDGE_PROMPT = """You are grading two assistant answers to the same user request.
Score each from 1 (useless) to 5 (fully serves the request) for helpfulness and correctness only.
Placeholder tokens like [[PERSON_1]] or generalized wording are acceptable if the answer still
serves the request. Reference notes describe what a good answer covers.

USER REQUEST:
{request}

REFERENCE NOTES:
{notes}

ANSWER A:
{a}

ANSWER B:
{b}

Reply with JSON only: {{"score_a": <1-5>, "score_b": <1-5>, "rationale": "<one sentence>"}}"""


def _env() -> tuple[str, str, str, str]:
    base = os.environ.get("AIRLOCK_JUDGE_BASE_URL")
    model = os.environ.get("AIRLOCK_JUDGE_MODEL")
    key = os.environ.get("NEBIUS_API_KEY")
    missing = [
        n
        for n, v in (
            ("AIRLOCK_JUDGE_BASE_URL", base),
            ("AIRLOCK_JUDGE_MODEL", model),
            ("NEBIUS_API_KEY", key),
        )
        if not v
    ]
    if missing:
        raise SystemExit(f"--judge needs {', '.join(missing)}")
    return base.rstrip("/"), model, key, os.environ.get("AIRLOCK_BASELINE_MODEL") or model


async def _complete(client: httpx.AsyncClient, model: str, messages: list[dict[str, Any]]) -> str:
    resp = await client.post(
        "/chat/completions", json={"model": model, "messages": messages, "temperature": 0}
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"] or ""


def _render_request(messages: list[dict[str, Any]]) -> str:
    return "\n".join(
        f"[{m.get('role')}] {m.get('content') or json.dumps(m.get('tool_calls'))}" for m in messages
    )


async def run(cases: list[dict[str, Any]], raw_passes: list[list[dict[str, Any]]], out: Path):
    base, judge_model, key, baseline_model = _env()
    print("NOTE: --judge sends raw synthetic prompts directly to", base, "(bypassing Airlock).")
    by_id = {c["id"]: c for c in cases}
    rows: list[dict[str, Any]] = []
    headers = {"Authorization": f"Bearer {key}"}
    async with httpx.AsyncClient(base_url=base, headers=headers, timeout=180) as client:
        baseline_cache: dict[str, str] = {}
        for pass_no, records in enumerate(raw_passes, start=1):
            for rec in records:
                case = by_id[rec["case_id"]]
                if case["task"] != "chat":
                    continue
                row: dict[str, Any] = {
                    "case_id": case["id"],
                    "category": case["category"],
                    "lang": case["lang"],
                    "pass": pass_no,
                    "status": rec["status"],
                }
                if rec["status"] != "ok" or not rec.get("answer"):
                    rows.append(row)
                    continue
                try:
                    if case["id"] not in baseline_cache:
                        baseline_cache[case["id"]] = await _complete(
                            client, baseline_model, case["messages"]
                        )
                    baseline = baseline_cache[case["id"]]
                    flip = random.Random(f"judge:{case['id']}:{pass_no}").random() < 0.5
                    a, b = (rec["answer"], baseline) if flip else (baseline, rec["answer"])
                    prompt = JUDGE_PROMPT.format(
                        request=_render_request(case["messages"]),
                        notes=case.get("reference_answer_notes", ""),
                        a=a,
                        b=b,
                    )
                    verdict = await _complete(
                        client, judge_model, [{"role": "user", "content": prompt}]
                    )
                    m = re.search(r"\{.*\}", verdict, re.DOTALL)
                    parsed = json.loads(m.group()) if m else {}
                    sa, sb = float(parsed["score_a"]), float(parsed["score_b"])
                    row.update(
                        {
                            "airlock_score": sa if flip else sb,
                            "baseline_score": sb if flip else sa,
                            "rationale": parsed.get("rationale"),
                            "airlock_was": "A" if flip else "B",
                        }
                    )
                except (httpx.HTTPError, KeyError, ValueError, TypeError) as exc:
                    row["judge_error"] = f"{type(exc).__name__}: {exc}"
                rows.append(row)
    with out.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    return rows


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    judged = [r for r in rows if "airlock_score" in r]
    if not judged:
        return {"judged": 0, "passes_judged": len({r["pass"] for r in rows})}
    air = [r["airlock_score"] for r in judged]
    base = [r["baseline_score"] for r in judged]
    by_cat: dict[str, dict[str, float]] = {}
    for cat in sorted({r["category"] for r in judged}):
        sub = [r for r in judged if r["category"] == cat]
        by_cat[cat] = {
            "n": len(sub),
            "airlock": statistics.fmean(r["airlock_score"] for r in sub),
            "baseline": statistics.fmean(r["baseline_score"] for r in sub),
        }
    return {
        "judged": len(judged),
        "passes_judged": len({r["pass"] for r in rows}),
        "blocked_or_unanswered": sum(1 for r in rows if r["status"] != "ok"),
        "judge_errors": sum(1 for r in rows if "judge_error" in r),
        "airlock_score_mean": statistics.fmean(air),
        "baseline_score_mean": statistics.fmean(base),
        "utility_retention": statistics.fmean(air) / statistics.fmean(base)
        if statistics.fmean(base)
        else None,
        "similar_or_better_rate": sum(1 for a, b in zip(air, base, strict=True) if a >= b)
        / len(judged),
        "by_category": by_cat,
    }
