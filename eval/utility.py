# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx>=0.27"]
# ///
"""Answer utility and factual distortion, judged blind against a raw-prompt reference answer.

    uv run eval/utility.py --results eval/results/baseline-raw --dry-run   # token estimate only
    uv run eval/utility.py --results eval/results/baseline-raw --yes       # 1 pass (default)
    uv run eval/utility.py --results eval/results/<run> --passes 3 --yes
    uv run eval/utility.py --results eval/results/<run> --score-only       # rebuild summary

Leak rates reward destroying the prompt: a proxy that masks everything leaks nothing. This script
measures what the user loses. For every chat case of a results directory:

1. Reference answer: the RAW case messages go straight to the same upstream model the system used
   (the `model` in its outbound payload, Nemotron 3 Ultra by default). Computed once per case and
   cached in eval/results/_reference_answers/, keyed by case id, model and the SHA-256 of the
   request body. The data is synthetic; this is the one place that deliberately sends
   unprotected prompts, exactly like the `raw` baseline.
2. System answer:
   * `recorded`: the answer the system returned to the user (Airlock: after rehydration).
   * `upstream`: the system's outbound upstream payload from the audit record, sent to the
     upstream once. Local baselines (raw, regex, presidio_ko, gliner_pii) only have stub answers,
     so this is how they get a real answer: exactly what the cloud would have answered to what
     they would have sent (placeholders are not restored; they have no rehydration).
   `auto` (default) uses `upstream` for runs labelled `baseline:<name>` or with stub answers,
   `recorded` otherwise. Cached per results directory in <results>/utility/answers_pass_NN.jsonl.
3. Judge (`--judge-model`, env AIRLOCK_UTILITY_MODEL; JSON schema): sees the user's real
   request and both answers as "Answer 1" and "Answer 2" in a seeded random order, without being
   told which is the reference.
   For each answer: usefulness 1-5 and a binary factual distortion (the answer contradicts a fact
   the user stated, e.g. "45" became "in their 30s", or claims a value the user gave is unknown).
   Every flagged distortion is re-checked by a focused confirmation call (`--confirm-model`, env
   AIRLOCK_DISTORTION_CONFIRM_MODEL); only confirmed flags count.

Metrics per judged pass, then mean ± sample sd across passes:
    utility_mean                  mean usefulness of the system answer
    reference_utility_mean        mean usefulness of the reference answer (same cases)
    utility_ratio_vs_reference    utility_mean / reference_utility_mean
    distortion_rate               system answers judged distorted / judged cases
    reference_distortion_rate     the judge's and the model's own distortion floor
Blocked requests (nothing sent, no answer) are counted, not scored. Search cases are not judged:
a fair reference would need a direct search call.

Outputs: <results>/utility/{pass_NN.jsonl, answers_pass_NN.jsonl, config.json, summary.json,
summary.md}.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import random
import re
import statistics
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

EVAL_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(EVAL_DIR))
import attack  # noqa: E402
import reuse  # noqa: E402
import scoring  # noqa: E402
import subset  # noqa: E402

UTILITY_VERSION = "1.1.0"
REFERENCE_DIR = EVAL_DIR / "results" / "_reference_answers"
ANSWER_MAX_TOKENS = 4096
ANSWER_TOKENS_TYPICAL = 800  # for the estimate; measured answers average roughly this
JUDGE_MAX_TOKENS = 500
JUDGE_REASONING_MAX_TOKENS = 4000  # reasoning tokens count against max_tokens
JUDGE_ANSWER_CHARS = 12000  # each answer is truncated to this for the judge prompt
STUB_RE = re.compile(r"stub answer, no cloud call", re.IGNORECASE)

JUDGE_SYSTEM = """You are a strict grader in an evaluation of privacy proxies for AI \
assistants. A user sent the \
request below. You get the user's actual request, with their real details, and two candidate \
answers labelled Answer 1 and Answer 2 in random order. The answers came from different \
pipelines. Do not guess which is which; grade each on its own against the same standard.

For EACH answer give:

usefulness, an integer from 1 to 5: how well the answer does the task the user asked for, for \
this user's actual facts.
5 = does the whole task correctly and specifically; the user could use it as is (after filling \
in any placeholder with their own details).
4 = does the task with minor gaps or slightly generic wording.
3 = does part of the task, or stays generic where the request needed the user's specifics \
(amounts, dates, counts, the diagnosis, the error).
2 = mostly misses the task, or contains a material error.
1 = unusable: a refusal, no answer, a different task, or mostly an echo of the request.
Do not reward length or formatting. Placeholders such as [[PERSON_1]], <PERSON_1> or <EMAIL> are \
fine where the real value is not needed for the task. When the task needed the value (a \
calculation on an amount, a translation of a name, a table of the given contacts), a missing \
value lowers usefulness.

distortion, true or false (set it after distortion_detail): true ONLY if the answer asserts \
something that contradicts a fact the user stated in the request. Examples: a wrong age, amount, \
date, duration, count, diagnosis or severity; a wrong relationship, organization type or role; a \
value attributed to the wrong person or thing; telling the user that a value they gave is \
missing, hidden, a placeholder, invalid or unknown; replacing their specific situation with a \
different one. NOT distortion: omissions, generic wording, extra advice, an arithmetic slip on \
correctly stated inputs, and placeholder or type-label tokens standing in for a value \
(<FIRST_NAME_1>, [[PERSON_1]], <PASSWORD_2>, [ORGANIZATION]) even when the label is the wrong \
type: a token is not an assertion, so judge it under usefulness only. Distortion needs a wrong \
statement written in words or numbers.
distortion_detail: first quote the wrong statement from the answer and the true fact in a few \
words, or leave it empty. Then set distortion. If the only thing you could quote is a \
placeholder or label token, leave distortion_detail empty and set distortion to false.

Reply with JSON matching the schema."""

_ANSWER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "usefulness": {"type": "integer"},
        "distortion_detail": {"type": "string"},
        "distortion": {"type": "boolean"},
    },
    "required": ["usefulness", "distortion_detail", "distortion"],
    "additionalProperties": False,
}
JUDGE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "answer_1": _ANSWER_SCHEMA,
        "answer_2": _ANSWER_SCHEMA,
        "reason": {"type": "string"},
    },
    "required": ["answer_1", "answer_2", "reason"],
    "additionalProperties": False,
}

VERIFY_SYSTEM = """You check one claimed factual distortion in an AI assistant's answer. You get \
the user's request, the answer, and a grader's claim that the answer contradicts a fact the user \
stated.

Confirm the claim ONLY if the answer contains a statement written in words or numbers that \
contradicts the request: a wrong age, amount, date, duration, count, diagnosis or severity, a \
wrong relationship, organization type or role, a value attributed to the wrong person or thing, \
or telling the user that a value they gave is missing, hidden, a placeholder, invalid or unknown.

Reject the claim if it is only about placeholder or label tokens standing in for a value \
(<FIRST_NAME_1>, [[PERSON_1]], <PASSWORD_2>, [ORGANIZATION]), even of the wrong type; about an \
omission, generic wording or missing detail; about an arithmetic slip on correct inputs; or if \
the statement is not actually in the answer.

First copy the contradicting sentence from the answer verbatim into quote (empty if none), then \
set confirmed. Reply with JSON matching the schema."""

VERIFY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"quote": {"type": "string"}, "confirmed": {"type": "boolean"}},
    "required": ["quote", "confirmed"],
    "additionalProperties": False,
}
VERIFY_MAX_TOKENS = 300

# --------------------------------------------------------------------------------------------
# Pure helpers (tested)
# --------------------------------------------------------------------------------------------


def body_hash(body: dict[str, Any]) -> str:
    """SHA-256 of a request body without its model (the model is a separate cache key)."""
    rest = {k: v for k, v in body.items() if k != "model"}
    return hashlib.sha256(
        json.dumps(rest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def model_slug(model: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", model).strip("_")


def reference_body(case: dict[str, Any], model: str) -> dict[str, Any]:
    return {"model": model, "messages": case["messages"], "max_tokens": ANSWER_MAX_TOKENS}


def reference_path(root: Path, case_id: str, model: str, digest: str) -> Path:
    return root / f"{case_id}.{model_slug(model)}.{digest[:16]}.json"


def load_reference(root: Path, case_id: str, model: str, body: dict[str, Any]) -> dict | None:
    """A cached reference answer for exactly this case, model and request body, or None."""
    digest = body_hash(body)
    path = reference_path(root, case_id, model, digest)
    try:
        cached = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if (
        cached.get("case_id") != case_id
        or cached.get("model") != model
        or cached.get("body_sha256") != digest
        or cached.get("error")
    ):
        return None
    return cached


def store_reference(
    root: Path, case_id: str, model: str, body: dict[str, Any], result: dict[str, Any]
) -> dict[str, Any]:
    digest = body_hash(body)
    entry = {
        "case_id": case_id,
        "model": model,
        "body_sha256": digest,
        "max_tokens": body.get("max_tokens"),
        "answer": result.get("content") or "",
        "finish_reason": result.get("finish_reason"),
        "usage": result.get("usage") or {},
        "error": result.get("error"),
        "created_at": datetime.now(UTC).isoformat(),
        "note": "Synthetic eval data: raw case prompt sent directly to the upstream model.",
    }
    if not entry["error"]:
        root.mkdir(parents=True, exist_ok=True)
        reference_path(root, case_id, model, digest).write_text(
            json.dumps(entry, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
        )
    return entry


def render_request(messages: list[dict[str, Any]]) -> str:
    lines = []
    for m in messages:
        content = m.get("content")
        if m.get("tool_calls"):
            content = (
                (content or "") + " tool_calls=" + json.dumps(m["tool_calls"], ensure_ascii=False)
            )
        lines.append(f"[{m.get('role')}] {content or ''}")
    return "\n".join(lines)


def order_flip(case_id: str, pass_no: int, label: str) -> bool:
    """True when the system answer is shown as Answer 1 (seeded, stable across reruns)."""
    return random.Random(f"utility:{label}:{case_id}:{pass_no}").random() < 0.5


def judge_messages(
    case: dict[str, Any], answer_1: str, answer_2: str, request_text: str | None = None
) -> list[dict[str, str]]:
    def clip(text: str) -> str:
        text = text or "(no answer)"
        return text if len(text) <= JUDGE_ANSWER_CHARS else text[:JUDGE_ANSWER_CHARS] + " [...]"

    notes = case.get("reference_answer_notes") or ""
    request = request_text if request_text is not None else render_request(case["messages"])
    return [
        {"role": "system", "content": JUDGE_SYSTEM},
        {
            "role": "user",
            "content": f"USER REQUEST:\n{request}\n\n"
            + (f"NOTES ON WHAT A GOOD ANSWER COVERS:\n{notes}\n\n" if notes else "")
            + f"ANSWER 1:\n{clip(answer_1)}\n\nANSWER 2:\n{clip(answer_2)}",
        },
    ]


def verify_messages(request_text: str, answer: str, detail: str) -> list[dict[str, str]]:
    if len(answer) > JUDGE_ANSWER_CHARS:
        answer = answer[:JUDGE_ANSWER_CHARS] + " [...]"
    return [
        {"role": "system", "content": VERIFY_SYSTEM},
        {
            "role": "user",
            "content": f"USER REQUEST:\n{request_text}\n\nANSWER:\n{answer}\n\n"
            f"CLAIMED DISTORTION:\n{detail or '(no detail given)'}",
        },
    ]


def parse_verification(text: str | None) -> bool | None:
    obj = attack.parse_json_object(text)
    if obj is None:
        return None
    confirmed = obj.get("confirmed")
    if isinstance(confirmed, str) and confirmed.strip().lower() in ("true", "false"):
        return confirmed.strip().lower() == "true"
    return confirmed if isinstance(confirmed, bool) else None


def _one_grade(obj: Any) -> dict[str, Any] | None:
    if not isinstance(obj, dict):
        return None
    try:
        usefulness = int(round(float(obj.get("usefulness"))))
    except (TypeError, ValueError):
        return None
    if not 1 <= usefulness <= 5:
        return None
    distortion = obj.get("distortion")
    if isinstance(distortion, str) and distortion.strip().lower() in ("true", "false"):
        distortion = distortion.strip().lower() == "true"
    if not isinstance(distortion, bool):
        return None
    detail = obj.get("distortion_detail")
    return {
        "usefulness": usefulness,
        "distortion": distortion,
        "distortion_detail": detail if isinstance(detail, str) else "",
    }


def parse_judgment(text: str | None) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """(grade of Answer 1, grade of Answer 2), or None if the reply is unusable."""
    obj = attack.parse_json_object(text)
    if obj is None:
        return None
    a1, a2 = _one_grade(obj.get("answer_1")), _one_grade(obj.get("answer_2"))
    if a1 is None or a2 is None:
        return None
    return a1, a2


def assign(
    grades: tuple[dict[str, Any], dict[str, Any]], system_first: bool
) -> tuple[dict[str, Any], dict[str, Any]]:
    """(system grade, reference grade) from the judge's (Answer 1, Answer 2)."""
    return (grades[0], grades[1]) if system_first else (grades[1], grades[0])


def judge_max_tokens(reasoning: str) -> int:
    return JUDGE_MAX_TOKENS if reasoning in ("", "none") else JUDGE_REASONING_MAX_TOKENS


def _rate(num: float, den: float) -> float | None:
    return None if den == 0 else num / den


def utility_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    judged = [r for r in rows if r.get("system") and r.get("reference")]
    sys_scores = [r["system"]["usefulness"] for r in judged]
    ref_scores = [r["reference"]["usefulness"] for r in judged]
    sys_mean = statistics.fmean(sys_scores) if sys_scores else None
    ref_mean = statistics.fmean(ref_scores) if ref_scores else None
    return {
        "cases": len(rows),
        "judged": len(judged),
        "blocked": sum(1 for r in rows if r.get("status") == "blocked"),
        "unjudged": sum(
            1
            for r in rows
            if r.get("status") != "blocked" and not (r.get("system") and r.get("reference"))
        ),
        "system_empty": sum(1 for r in judged if r.get("system_empty")),
        "utility_mean": sys_mean,
        "reference_utility_mean": ref_mean,
        "utility_ratio_vs_reference": (
            sys_mean / ref_mean if sys_mean is not None and ref_mean else None
        ),
        "distortion_rate": _rate(sum(r["system"]["distortion"] for r in judged), len(judged)),
        "reference_distortion_rate": _rate(
            sum(r["reference"]["distortion"] for r in judged), len(judged)
        ),
        "similar_or_better_rate": _rate(
            sum(1 for a, b in zip(sys_scores, ref_scores, strict=True) if a >= b), len(judged)
        ),
    }


METRIC_KEYS = (
    "utility_mean",
    "reference_utility_mean",
    "utility_ratio_vs_reference",
    "distortion_rate",
    "reference_distortion_rate",
    "similar_or_better_rate",
    "judged",
    "blocked",
    "unjudged",
)


def summarize(passes: list[list[dict[str, Any]]]) -> dict[str, Any]:
    per_pass = [utility_metrics(p) for p in passes]

    def grouped(key: str) -> dict[str, dict[str, Any]]:
        values = sorted({r[key] for p in passes for r in p})
        return {
            v: {
                k: scoring.describe(
                    utility_metrics([r for r in p if r[key] == v])[k] for p in passes
                )
                for k in METRIC_KEYS
            }
            for v in values
        }

    return {
        "passes": len(passes),
        "overall": {k: scoring.describe(m[k] for m in per_pass) for k in METRIC_KEYS},
        "by_lang": grouped("lang"),
        "by_category": grouped("category"),
        "per_pass": per_pass,
    }


# --------------------------------------------------------------------------------------------
# Answer sources
# --------------------------------------------------------------------------------------------


def upstream_payload(record: dict[str, Any]) -> dict[str, Any] | None:
    for hop in (record.get("audit") or {}).get("outbound") or []:
        payload = hop.get("payload")
        if (
            hop.get("destination") == "upstream"
            and isinstance(payload, dict)
            and payload.get("messages")
        ):
            return payload
    return None


def choose_source(opts_source: str, config: dict[str, Any], records: list[dict[str, Any]]) -> str:
    if opts_source != "auto":
        return opts_source
    label = str(config.get("target_label") or "")
    stubs = any(STUB_RE.search(str(r.get("answer") or "")) for r in records)
    return "upstream" if label.startswith("baseline:") or stubs else "recorded"


def system_body(payload: dict[str, Any], default_model: str) -> dict[str, Any]:
    body = {k: v for k, v in payload.items() if k not in ("stream",)}
    body.setdefault("model", default_model)
    body["max_tokens"] = ANSWER_MAX_TOKENS
    return body


# --------------------------------------------------------------------------------------------
# Estimate
# --------------------------------------------------------------------------------------------


def estimate(
    jobs: list[tuple[dict[str, Any], dict[str, Any]]],
    source: str,
    model: str,
    ref_root: Path,
    cached_answers: set[str],
) -> dict[str, int]:
    tok = attack.estimate_tokens
    ref_needed: set[str] = set()
    ref_prompt = sys_calls = sys_prompt = judge_calls = judge_prompt = 0
    rubric = tok(JUDGE_SYSTEM)
    for case, record in jobs:
        if record.get("status") != "ok":
            continue
        payload = upstream_payload(record)
        ref_model = (payload or {}).get("model") or model
        body = reference_body(case, ref_model)
        if (
            case["id"] not in ref_needed
            and load_reference(ref_root, case["id"], ref_model, body) is None
        ):
            ref_needed.add(case["id"])
            ref_prompt += tok(json.dumps(case["messages"], ensure_ascii=False))
        if source == "upstream" and payload:
            key = f"{case['id']}:{body_hash(system_body(payload, model))}"
            if key not in cached_answers:
                sys_calls += 1
                sys_prompt += tok(json.dumps(payload.get("messages"), ensure_ascii=False))
        judge_calls += 1
        judge_prompt += rubric + tok(render_request(case["messages"])) + 2 * ANSWER_TOKENS_TYPICAL
    answer_calls = len(ref_needed) + sys_calls
    return {
        "reference_calls": len(ref_needed),
        "system_answer_calls": sys_calls,
        "judge_calls": judge_calls,
        "prompt_tokens_est": ref_prompt + sys_prompt + judge_prompt,
        "completion_tokens_typical": answer_calls * ANSWER_TOKENS_TYPICAL + judge_calls * 250,
        "completion_tokens_max": answer_calls * ANSWER_MAX_TOKENS + judge_calls * JUDGE_MAX_TOKENS,
    }


def print_estimate(name: str, est: dict[str, int]) -> None:
    print(
        f"utility estimate for {name}: {est['reference_calls']} reference + "
        f"{est['system_answer_calls']} system-answer + {est['judge_calls']} judge calls, "
        f"~{est['prompt_tokens_est']:,} prompt tokens, ~{est['completion_tokens_typical']:,} "
        f"completion tokens typical (<= {est['completion_tokens_max']:,})",
        file=sys.stderr,
    )


# --------------------------------------------------------------------------------------------
# Running
# --------------------------------------------------------------------------------------------


async def verify_distortions(
    llm: attack.LLM, request_text: str, graded: list[tuple[dict[str, Any], str]]
) -> list[dict[str, Any]]:
    """Second, focused check of every distortion the judge flagged (reasoning off).

    The one-shot judge sometimes calls a placeholder token a distortion despite the rubric. Each
    flagged answer gets a verification call; `distortion` keeps the judge's flag only when the
    verifier confirms it. The judge's flag stays in `distortion_judge`. Mutates the grades.
    """
    checks = []
    for grade, text in graded:
        if not grade.get("distortion"):
            continue
        reply = await llm(
            verify_messages(request_text, text, grade.get("distortion_detail") or ""),
            "verify_distortion",
            VERIFY_SCHEMA,
            "none",
            VERIFY_MAX_TOKENS,
        )
        confirmed = parse_verification(reply.get("content"))
        grade["distortion_judge"] = True
        grade["distortion_verified"] = confirmed
        grade["distortion"] = bool(confirmed)
        grade["verify_raw"] = reply.get("content")
        grade["verify_model"] = reply.get("model")
        checks.append({"confirmed": confirmed, "usage": reply.get("usage")})
    return checks


async def complete(client: httpx.AsyncClient, body: dict[str, Any], retries: int = 4) -> dict:
    """One answer call. Raises attack.ProviderAbort on HTTP 402 or a 429 past the retries."""
    last = ""
    for attempt in range(retries + 1):
        try:
            resp = await client.post("/chat/completions", json=body)
        except httpx.HTTPError as exc:
            last = f"{type(exc).__name__}: {exc}"
        else:
            if resp.status_code == 200:
                data = resp.json()
                choice = (data.get("choices") or [{}])[0]
                msg = choice.get("message") or {}
                return {
                    "content": msg.get("content") or "",
                    "finish_reason": choice.get("finish_reason"),
                    "usage": data.get("usage") or {},
                }
            last = f"HTTP {resp.status_code}: {resp.text[:200]}"
            attack.check_provider_status(
                resp.status_code, resp.text, attempt, retries, str(body.get("model"))
            )
            if resp.status_code not in (408, 409, 429) and resp.status_code < 500:
                break
        if attempt < retries:
            await asyncio.sleep(2**attempt)
    return {"content": "", "usage": {}, "error": last}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def add_usage(total: dict[str, int], usage: dict[str, Any] | None) -> None:
    for k in ("prompt_tokens", "completion_tokens"):
        total[k] = total.get(k, 0) + int((usage or {}).get(k) or 0)


def load_jobs(opts: argparse.Namespace) -> tuple[dict[str, Any], list[list[tuple[dict, dict]]]]:
    """(run config, jobs per pass). The --subset record lands in config["subset"]."""
    run_dir: Path = opts.results
    cases = {c["id"]: c for c in read_jsonl(run_dir / "cases_snapshot.jsonl")}
    config = {}
    if (run_dir / "config.json").exists():
        config = json.loads((run_dir / "config.json").read_text(encoding="utf-8"))
    pass_files = sorted(run_dir.glob("pass_*.jsonl"))[: opts.passes]
    if not pass_files:
        raise SystemExit(f"no pass_*.jsonl in {run_dir}")
    chosen, subset_info = subset.select(list(cases.values()), opts.subset, opts.seed)
    if subset_info:
        config["subset"] = subset_info
    keep = {c["id"] for c in chosen}
    wanted = set(opts.category or [])
    jobs = []
    for p in pass_files:
        rows = [row["record"] for row in read_jsonl(p)]
        pj = [
            (cases[r["case_id"]], r)
            for r in rows
            if cases[r["case_id"]]["task"] == "chat"
            and r["case_id"] in keep
            and r.get("status") != "error"
            and (not wanted or cases[r["case_id"]]["category"] in wanted)
        ]
        jobs.append(pj[: opts.limit] if opts.limit else pj)
    return config, jobs


async def run_utility(opts: argparse.Namespace) -> Path | None:
    run_dir: Path = opts.results
    out = run_dir / opts.out_name
    config, jobs = load_jobs(opts)
    all_records = [r for pj in jobs for _, r in pj]
    source = choose_source(opts.answer_source, config, all_records)
    cached_answers = {
        f"{a['case_id']}:{a['body_sha256']}"
        for p in out.glob("answers_pass_*.jsonl")
        for a in read_jsonl(p)
        if not a.get("error")
    }
    prior_rows, prior_hashes, prior_name = prior_utility_rows(opts, source)
    first_hashes = {c["id"]: reuse.judged_sha256(r, source) for c, r in jobs[0]} if jobs else {}

    def planned_ref(pass_index: int, case: dict, record: dict) -> dict[str, Any] | None:
        if record.get("status") != "ok":
            return None
        digest = reuse.judged_sha256(record, source)
        if pass_index and opts.reuse_identical_passes and first_hashes.get(case["id"]) == digest:
            return reuse.reference(1, digest)
        if prior_hashes.get(case["id"]) == digest:
            return reuse.reference(1, digest, prior_name)
        return None

    to_judge = [(c, r) for i, pj in enumerate(jobs) for c, r in pj if not planned_ref(i, c, r)]
    est = estimate(to_judge, source, opts.model, opts.reference_dir, cached_answers)
    est["rows"] = sum(len(pj) for pj in jobs)
    est["rows_reused_planned"] = est["rows"] - len(to_judge)
    print_estimate(run_dir.name, est)
    print(f"  {est['rows_reused_planned']} of {est['rows']} rows reused by payload hash",
          file=sys.stderr)  # fmt: skip
    print(f"  answer source: {source}; judge {opts.judge_model}, distortion confirmation "
          f"{opts.confirm_model}", file=sys.stderr)  # fmt: skip
    if opts.dry_run:
        return None
    if not opts.yes:
        print("  not running: pass --yes to make these calls (synthetic data only)",
              file=sys.stderr)  # fmt: skip
        return None
    key = attack.read_env_key()
    if not key:
        raise SystemExit("NEBIUS_API_KEY is not set (environment or .env)")
    out.mkdir(parents=True, exist_ok=True)
    usage = {
        "reference": {"prompt_tokens": 0, "completion_tokens": 0, "calls": 0},
        "system_answer": {"prompt_tokens": 0, "completion_tokens": 0, "calls": 0},
        "judge": {"prompt_tokens": 0, "completion_tokens": 0, "calls": 0},
        "verify": {"prompt_tokens": 0, "completion_tokens": 0, "calls": 0},
    }
    label = str(config.get("target_label") or run_dir.name)
    timeout = httpx.Timeout(opts.timeout, connect=15.0)
    async with httpx.AsyncClient(
        base_url=opts.base_url, headers={"Authorization": f"Bearer {key}"}, timeout=timeout
    ) as client:
        sem = asyncio.Semaphore(opts.concurrency)
        judge_llm = attack.make_llm(client, opts.judge_model)
        confirm_llm = attack.make_llm(client, opts.confirm_model)
        ref_locks: dict[str, asyncio.Lock] = {}

        async def reference_for(case: dict[str, Any], ref_model: str) -> dict[str, Any]:
            body = reference_body(case, ref_model)
            lock = ref_locks.setdefault(f"{case['id']}:{ref_model}", asyncio.Lock())
            async with lock:
                cached = load_reference(opts.reference_dir, case["id"], ref_model, body)
                if cached:
                    return cached
                async with sem:
                    result = await complete(client, body)
                usage["reference"]["calls"] += 1
                add_usage(usage["reference"], result.get("usage"))
                return store_reference(opts.reference_dir, case["id"], ref_model, body, result)

        rows_by_pass: list[list[dict[str, Any]]] = []
        for pass_no, pj in enumerate(jobs, start=1):
            t0 = time.perf_counter()
            first_rows = {r["case_id"]: r for r in rows_by_pass[0]} if rows_by_pass else {}
            answers_path = out / f"answers_pass_{pass_no:02d}.jsonl"
            answers = {a["case_id"]: a for a in read_jsonl(answers_path) if not a.get("error")}
            judged_path = out / f"pass_{pass_no:02d}.jsonl"
            previous = {r["case_id"]: r for r in read_jsonl(judged_path)}

            async def system_answer(case: dict, record: dict, answers=answers) -> dict[str, Any]:
                if source == "recorded":
                    return {"case_id": case["id"], "source": "recorded",
                            "answer": record.get("answer") or ""}  # fmt: skip
                payload = upstream_payload(record)
                if payload is None:
                    return {"case_id": case["id"], "source": "upstream", "answer": "",
                            "error": "no upstream payload in the audit record"}  # fmt: skip
                body = system_body(payload, opts.model)
                digest = body_hash(body)
                prev = answers.get(case["id"])
                if prev and prev.get("body_sha256") == digest:
                    return prev
                async with sem:
                    result = await complete(client, body)
                usage["system_answer"]["calls"] += 1
                add_usage(usage["system_answer"], result.get("usage"))
                entry = {
                    "case_id": case["id"],
                    "source": "upstream",
                    "model": body["model"],
                    "body_sha256": digest,
                    "answer": result.get("content") or "",
                    "finish_reason": result.get("finish_reason"),
                    "usage": result.get("usage"),
                    "error": result.get("error"),
                }
                answers[case["id"]] = entry
                return entry

            async def one(
                case: dict, record: dict, pass_no=pass_no, previous=previous, first_rows=first_rows
            ) -> dict:
                row: dict[str, Any] = {
                    "case_id": case["id"],
                    "category": case["category"],
                    "lang": case["lang"],
                    "pass": pass_no,
                    "status": record.get("status"),
                }
                prev = previous.get(case["id"])
                judged = bool(prev and prev.get("system") and prev.get("reference"))
                if judged and same_models(prev, opts):
                    return prev
                if record.get("status") != "ok":
                    return row  # blocked: nothing was sent, no answer to judge
                ref = planned_ref(pass_no - 1, case, record)
                if ref:
                    src = (
                        prior_rows.get(case["id"])
                        if "results_dir" in ref
                        else first_rows.get(case["id"])
                    )
                    if src and src.get("system") and src.get("reference"):
                        return reused_utility_row(src, pass_no, ref)
                payload = upstream_payload(record)
                ref_model = (payload or {}).get("model") or opts.model
                reference, answer = await asyncio.gather(
                    reference_for(case, ref_model), system_answer(case, record)
                )
                row["reference_model"] = ref_model
                row["reference_file"] = reference_path(
                    opts.reference_dir, case["id"], ref_model, reference.get("body_sha256") or ""
                ).name
                row["answer_source"] = answer.get("source")
                if reference.get("error") or not (reference.get("answer") or "").strip():
                    row["unjudged_reason"] = "reference answer missing or empty"
                    return row
                if answer.get("error"):
                    row["unjudged_reason"] = f"system answer error: {answer['error']}"
                    return row
                sys_text = answer.get("answer") or ""
                if not sys_text.strip():
                    # Nothing reached the user: usefulness 1 by rule. The judge still runs so the
                    # reference answer gets its paired grade.
                    row["system_empty"] = True
                    row["system"] = {"usefulness": 1, "distortion": False, "distortion_detail": ""}
                system_first = order_flip(case["id"], pass_no, label)
                row["system_shown_as"] = "Answer 1" if system_first else "Answer 2"
                a1, a2 = (
                    (sys_text, reference["answer"])
                    if system_first
                    else (reference["answer"], sys_text)
                )
                async with sem:
                    reply = await judge_llm(
                        judge_messages(case, a1, a2), "utility_judge", JUDGE_SCHEMA,
                        opts.judge_reasoning, judge_max_tokens(opts.judge_reasoning),
                    )  # fmt: skip
                usage["judge"]["calls"] += 1
                for u in attack.iter_usage(reply):
                    add_usage(usage["judge"], u)
                row["judge"] = {
                    "model": reply.get("model"),
                    "raw": reply.get("content"),
                    "error": reply.get("error"),
                }
                grades = parse_judgment(reply.get("content"))
                if grades is None:
                    row["unjudged_reason"] = "judge reply unparsed"
                    row.pop("system", None)
                    row.pop("system_empty", None)
                    return row
                system_grade, reference_grade = assign(grades, system_first)
                async with sem:
                    checks = await verify_distortions(
                        confirm_llm,
                        render_request(case["messages"]),
                        [(system_grade, sys_text), (reference_grade, reference["answer"])],
                    )
                usage["verify"]["calls"] += len(checks)
                for c in checks:
                    add_usage(usage["verify"], c.get("usage"))
                if not row.get("system_empty"):
                    row["system"] = system_grade
                row["reference"] = reference_grade
                return row

            rows = await asyncio.gather(*(one(c, r) for c, r in pj))
            rows_by_pass.append(rows)
            write_jsonl(answers_path, sorted(answers.values(), key=lambda a: a["case_id"]))
            write_jsonl(judged_path, rows)
            m = utility_metrics(rows)
            print(
                f"  utility pass {pass_no}: judged {m['judged']}, utility "
                f"{_fmt(m['utility_mean'])} vs reference {_fmt(m['reference_utility_mean'])}, "
                f"distortion {_pct(m['distortion_rate'])} ({time.perf_counter() - t0:.0f}s)",
                file=sys.stderr,
            )
    cfg_path = out / "config.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8")) if cfg_path.exists() else {}
    cfg.update(
        {
            "utility_version": UTILITY_VERSION,
            "results_dir": run_dir.name,
            "target_label": config.get("target_label"),
            "answer_source": source,
            "base_url": opts.base_url,
            "judge_model": opts.judge_model,
            "confirm_model": opts.confirm_model,
            "judge_reasoning": opts.judge_reasoning,
            "default_upstream_model": opts.model,
            "answer_max_tokens": ANSWER_MAX_TOKENS,
            "passes": len(jobs),
            "limit": opts.limit,
            "categories": sorted(opts.category or []) or None,
            "reference_dir": scoring_display(opts.reference_dir),
            "subset": config.get("subset"),
            "reuse_identical_passes": opts.reuse_identical_passes,
            "reuse_from": prior_name,
            "reuse": reuse.summarize(rows_by_pass, prior_name),
        }
    )
    part_models = {"judge": opts.judge_model, "verify": opts.confirm_model}
    cfg.setdefault("runs", []).append(
        {
            "at": datetime.now(UTC).isoformat(),
            "estimate": est,
            "judge_model": opts.judge_model,
            "confirm_model": opts.confirm_model,
            "usage": usage,
            # Answers are priced at the default upstream model; payloads may name another.
            "cost_usd": {
                part: attack.usage_cost(part_models.get(part, opts.model), u)
                for part, u in usage.items()
            },
        }
    )
    cfg_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    write_summary(out)
    return out


def reused_utility_row(source: dict[str, Any], pass_no: int, ref: dict[str, Any]) -> dict[str, Any]:
    """The judged row for a pass whose inputs hash identically to an already judged row."""
    row = {k: v for k, v in source.items() if k not in ("judge", "reused_from")}
    row.update({"pass": pass_no, "reused_from": ref})
    return row


def prior_utility_rows(
    opts: argparse.Namespace, source: str
) -> tuple[dict[str, dict[str, Any]], dict[str, str], str | None]:
    """Judged pass-1 rows of --reuse-from made with the same models and answer source."""
    prior: Path | None = getattr(opts, "reuse_from", None)
    if not prior:
        return {}, {}, None
    cfg_path = prior / opts.out_name / "config.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8")) if cfg_path.exists() else {}
    if cfg.get("answer_source") != source:
        return {}, {}, None
    records = reuse.read_pass_records(prior, 1)
    rows = {
        cid: row
        for cid, row in reuse.read_rows(prior / opts.out_name / "pass_01.jsonl").items()
        if cid in records
        and row.get("system")
        and row.get("reference")
        and not row.get("reused_from")
        and same_models(row, opts)
    }
    hashes = {cid: reuse.judged_sha256(records[cid], source) for cid in rows}
    return rows, hashes, attack.display_path(prior)


def same_models(row: dict[str, Any], opts: argparse.Namespace) -> bool:
    """A stored judgment is reused only if the same judge and confirmation models made it.

    Rows from before model plumbing carry no model: they were all Nemotron 3 Ultra.
    """
    judge = (row.get("judge") or {}).get("model") or attack.ULTRA
    confirms = {
        g.get("verify_model") or attack.ULTRA
        for g in (row.get("system") or {}, row.get("reference") or {})
        if g.get("distortion_judge")
    }
    return judge == opts.judge_model and confirms <= {opts.confirm_model}


def scoring_display(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(EVAL_DIR.parent))
    except ValueError:
        return str(path)


def _fmt(v: float | None) -> str:
    return "n/a" if v is None else f"{v:.2f}"


def _pct(v: float | None) -> str:
    return "n/a" if v is None else f"{v * 100:.1f}%"


def render_markdown(summary: dict[str, Any], config: dict[str, Any]) -> str:
    def cell(stat: dict[str, Any], kind: str) -> str:
        if not stat or not stat.get("n") or stat.get("mean") is None:
            return "n/a"
        if kind == "pct":
            return f"{stat['mean'] * 100:.1f}% ± {stat['std'] * 100:.1f}"
        return f"{stat['mean']:.2f} ± {stat['std']:.2f}"

    usage = {"prompt_tokens": 0, "completion_tokens": 0}
    for run in config.get("runs") or []:
        for part in (run.get("usage") or {}).values():
            add_usage(usage, part)
    rows = [
        ("utility_mean", "System answer usefulness (1-5)", "num"),
        ("reference_utility_mean", "Reference answer usefulness (1-5)", "num"),
        ("utility_ratio_vs_reference", "Utility ratio vs reference", "num"),
        ("distortion_rate", "Factual distortion (system)", "pct"),
        ("reference_distortion_rate", "Factual distortion (reference)", "pct"),
        ("similar_or_better_rate", "System scored >= reference", "pct"),
        ("judged", "Judged cases per pass", "num"),
        ("blocked", "Blocked (not judged) per pass", "num"),
        ("unjudged", "Unjudged (errors, empty reference) per pass", "num"),
    ]
    lines = [
        f"# Answer utility: {config.get('target_label') or config.get('results_dir')}",
        "",
        f"- answer source: `{config.get('answer_source')}`; judge `{config.get('judge_model')}` "
        f"(reasoning `{config.get('judge_reasoning')}`), blind, seeded order; distortion "
        f"confirmation `{config.get('confirm_model') or config.get('judge_model')}`",
        f"- judged passes: {summary['passes']}; tokens used so far: prompt "
        f"{usage['prompt_tokens']:,}, completion {usage['completion_tokens']:,}",
        "",
        "| Metric | All | ko | en |",
        "|---|---:|---:|---:|",
    ]
    for key, label, kind in rows:
        cells = [cell(summary["overall"].get(key), kind)]
        cells += [cell(summary["by_lang"].get(lang, {}).get(key), kind) for lang in ("ko", "en")]
        lines.append(f"| {label} | " + " | ".join(cells) + " |")
    lines += ["", "## By category", "", "| Category | Utility ratio | Distortion | Judged |",
              "|---|---:|---:|---:|"]  # fmt: skip
    for cat, stats in summary["by_category"].items():
        lines.append(
            f"| {cat} | {cell(stats['utility_ratio_vs_reference'], 'num')} | "
            f"{cell(stats['distortion_rate'], 'pct')} | {cell(stats['judged'], 'num')} |"
        )
    distorted = [
        r for p in summary.get("_rows", []) for r in p if (r.get("system") or {}).get("distortion")
    ]
    if distorted:
        lines += ["", "## Distorted system answers", "", "| Case | Pass | Judge's evidence |",
                  "|---|---:|---|"]  # fmt: skip
        for r in sorted(distorted, key=lambda r: (r["case_id"], r["pass"])):
            detail = (r["system"].get("distortion_detail") or "").replace("|", "\\|")
            lines.append(f"| {r['case_id']} | {r['pass']} | {detail[:300]} |")
    lines.append("")
    return "\n".join(lines)


def write_summary(out: Path) -> dict[str, Any]:
    config = json.loads((out / "config.json").read_text(encoding="utf-8"))
    passes = [read_jsonl(p) for p in sorted(out.glob("pass_*.jsonl"))]
    summary = summarize(passes)
    summary["config"] = config
    (out / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    md = render_markdown({**summary, "_rows": passes}, config)
    (out / "summary.md").write_text(md, encoding="utf-8")
    o = summary["overall"]
    print(
        f"  {out.parent.name}: utility ratio {_fmt(o['utility_ratio_vs_reference']['mean'])}, "
        f"distortion {_pct(o['distortion_rate']['mean'])} "
        f"(reference {_pct(o['reference_distortion_rate']['mean'])})"
    )
    return summary


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--results", type=Path, required=True, help="run.py results directory")
    ap.add_argument("--passes", type=int, default=1, help="judge the first N passes (default 1)")
    ap.add_argument("--limit", type=int, default=None, help="only the first N chat cases per pass")
    ap.add_argument("--subset", default=None, help="stratified:N or ids:PATH (eval/subset.py)")
    ap.add_argument("--seed", type=int, default=0, help="seed for --subset stratified:N")
    ap.add_argument(
        "--reuse-identical-passes",
        action="store_true",
        help="reuse the pass-1 judgment for cases whose payloads (and recorded answer) hash "
        "identically in a later pass",
    )
    ap.add_argument(
        "--reuse-from",
        type=Path,
        default=None,
        help="earlier results directory of the same system: reuse its judged pass-1 rows for "
        "identical inputs made with the same judge and confirmation models",
    )
    ap.add_argument("--category", action="append", default=None)
    ap.add_argument("--answer-source", choices=("auto", "recorded", "upstream"), default="auto")
    ap.add_argument("--base-url", default=attack.DEFAULT_BASE_URL)
    ap.add_argument("--model", default=attack.DEFAULT_MODEL,
                    help="upstream model when the payload names none")  # fmt: skip
    ap.add_argument(
        "--judge-model",
        default=None,
        help=f"utility judge (default ${attack.ROLE_ENV['utility']} or "
        f"{attack.DEFAULT_ROLE_MODELS['utility']})",
    )
    ap.add_argument(
        "--confirm-model",
        default=None,
        help=f"distortion confirmation (default ${attack.ROLE_ENV['distortion_confirm']} or "
        f"{attack.DEFAULT_ROLE_MODELS['distortion_confirm']})",
    )
    ap.add_argument("--judge-reasoning", default="none")
    ap.add_argument("--reference-dir", type=Path, default=REFERENCE_DIR)
    ap.add_argument("--out-name", default="utility")
    ap.add_argument("--concurrency", type=int, default=6)
    ap.add_argument("--timeout", type=float, default=300.0)
    ap.add_argument("--dry-run", action="store_true", help="print the estimate and exit")
    ap.add_argument("--yes", action="store_true", help="confirm the cloud calls")
    ap.add_argument("--score-only", action="store_true", help="rebuild summary from stored rows")
    opts = ap.parse_args(argv)
    for field, role in (("judge_model", "utility"), ("confirm_model", "distortion_confirm")):
        if not getattr(opts, field):
            setattr(opts, field, attack.role_model(role))
    return opts


def main(argv: list[str] | None = None) -> None:
    opts = parse_args(argv)
    if opts.score_only:
        write_summary(opts.results / opts.out_name)
        return
    try:
        asyncio.run(run_utility(opts))
    except attack.ProviderAbort as exc:
        raise SystemExit(f"utility.py aborted: {exc}") from exc


if __name__ == "__main__":
    main()
