# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx>=0.27"]
# ///
"""Airlock leak-measurement harness.

    uv run eval/run.py --base-url http://127.0.0.1:8787 --passes 10
    uv run eval/run.py --rescore eval/results/<run>/        # recompute summary from raw files

For every case and pass: register the case's vault terms, send the request through Airlock, fetch
the audit record, and scan every outbound payload for the case's must_not_leak strings and
canaries (plus normalized and decoded variants). Rates are computed per pass and reported as mean,
standard deviation and range across passes, with a per-case table of how many passes leaked.

Output directory:
    config.json            arguments, dataset hash, server /healthz snapshot
    cases_snapshot.jsonl   the exact cases used (so --rescore needs nothing else)
    pass_01.jsonl ...      one line per case: raw request outcome + audit record + score
    summary.json           all metrics
    summary.md             human-readable report
    utility/               only with --judge: eval/utility.py output (sends raw synthetic prompts
                           to the cloud for the reference answers; see README)
"""

from __future__ import annotations

import argparse
import asyncio
import glob
import hashlib
import json
import os
import random
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

EVAL_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(EVAL_DIR))
import scoring  # noqa: E402

DEFAULT_CASES = str(EVAL_DIR / "cases" / "*.jsonl")


def load_audit_hash_key() -> bytes | None:
    """Airlock's audit HMAC key: AIRLOCK_AUDIT_HASH_KEY, else the key file it generates."""
    if os.environ.get("AIRLOCK_AUDIT_HASH_KEY"):
        return os.environ["AIRLOCK_AUDIT_HASH_KEY"].encode("utf-8")
    path = Path(
        os.environ.get("AIRLOCK_AUDIT_HASH_KEY_FILE") or EVAL_DIR.parent / ".airlock/audit_hash.key"
    )
    if path.is_file():
        return path.read_text(encoding="utf-8").strip().encode("utf-8") or None
    return None


# --------------------------------------------------------------------------------------------
# Dataset
# --------------------------------------------------------------------------------------------


def load_cases(pattern: str) -> tuple[list[dict[str, Any]], str]:
    paths = sorted(glob.glob(pattern))
    if not paths:
        raise SystemExit(f"no case files match {pattern!r}")
    digest = hashlib.sha256()
    cases = []
    for p in paths:
        data = Path(p).read_bytes()
        digest.update(Path(p).name.encode() + b"\0" + data)
        cases.extend(json.loads(line) for line in data.decode("utf-8").splitlines() if line.strip())
    return cases, digest.hexdigest()


def display_path(path: str | Path) -> str:
    """Repo-relative path for reports, so published results don't embed a local home directory."""
    try:
        return str(Path(path).resolve().relative_to(EVAL_DIR.parent))
    except ValueError:
        return str(path)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


# --------------------------------------------------------------------------------------------
# One case
# --------------------------------------------------------------------------------------------


async def execute_case(
    client: httpx.AsyncClient, case: dict[str, Any], opts: argparse.Namespace, pass_no: int = 1
) -> dict[str, Any]:
    """Send one case through Airlock and collect everything needed to score it."""
    record: dict[str, Any] = {"case_id": case["id"], "status": "error"}
    try:
        if case.get("vault_terms"):
            r = await client.post("/vault/terms", json={"terms": case["vault_terms"]})
            record["vault_status"] = r.status_code
            if r.status_code >= 400:
                record["error"] = f"vault/terms returned {r.status_code}: {r.text[:300]}"
                return record
        if opts.register_canaries and case.get("canaries"):
            await client.post("/vault/terms", json={"terms": case["canaries"], "kind": "canary"})

        t0 = time.perf_counter()
        if case["task"] == "chat":
            body = {"model": opts.model, "messages": case["messages"]}
            headers = {}
            if getattr(opts, "conversation_scope", "pass") == "pass":
                # Airlock keys its vault session on the first user message by default, which would
                # let pass 2 reuse what pass 1 learned. A fresh id per (run, pass, case) keeps
                # passes independent.
                run_id = getattr(opts, "run_id", "run")
                headers["x-airlock-conversation-id"] = f"eval-{run_id}-p{pass_no}-{case['id']}"
            resp = await client.post("/v1/chat/completions", json=body, headers=headers)
        else:
            body = {
                "query": case["query"],
                "context": case.get("context") or "",
                "max_results": opts.max_results,
            }
            resp = await client.post("/v1/search", json=body)
        record["client_ms"] = round((time.perf_counter() - t0) * 1000, 2)

        request_id, data = classify_response(resp, case, record)
        if record.get("review") and getattr(opts, "auto_approve_review", False):
            approval = await approve_review(client, record)
            if approval is None:
                return record
            resp = approval
            request_id, data = classify_response(resp, case, record)
        if record["status"] == "error":
            record["error"] = f"HTTP {resp.status_code}: {resp.text[:300]}"
            record["request_id"] = request_id or ((data or {}).get("error") or {}).get("request_id")
            return record

        record["request_id"] = request_id
        if not request_id:
            record["status"] = "error"
            record["error"] = "response carried no request id; cannot fetch audit record"
            return record
        audit = None
        for attempt in range(opts.audit_retries + 1):
            ar = await client.get(f"/audit/{request_id}")
            if ar.status_code == 200:
                audit = ar.json()
                break
            await asyncio.sleep(0.2 * (attempt + 1))
        if audit is None and record["status"] == "blocked" and record.get("review"):
            # Held for review and the server kept no audit record: nothing was sent.
            audit = {"request_id": request_id, "outbound": [], "detections": [], "gate": {}}
        if audit is None:
            record["status"] = "error"
            record["error"] = f"audit record {request_id} not found"
            return record
        record["audit"] = audit
        return record
    except httpx.HTTPError as exc:
        record["status"] = "error"
        record["error"] = f"{type(exc).__name__}: {exc}"
        return record


def classify_response(
    resp: httpx.Response, case: dict[str, Any], record: dict[str, Any]
) -> tuple[str | None, Any]:
    """Set record status from one Airlock response: ok, blocked, held for review, or error."""
    try:
        data = resp.json()
    except ValueError:
        data = None
    record["http_status"] = resp.status_code
    request_id = resp.headers.get("x-airlock-request-id")
    err = (data.get("error") or {}) if isinstance(data, dict) else {}
    if resp.status_code == 200 and isinstance(data, dict):
        record["status"] = "ok"
        request_id = request_id or data.get("request_id")
        if case["task"] == "chat":
            choices = data.get("choices") or [{}]
            record["answer"] = (choices[0].get("message") or {}).get("content")
        else:
            record["answer"] = data.get("answer")
            record["outbound_query"] = data.get("outbound_query")
    elif resp.status_code == 422 and err.get("type") == "airlock_blocked":
        record["status"] = "blocked"
        request_id = request_id or err.get("request_id")
        record["block_reasons"] = err.get("reasons") or []
    elif resp.status_code == 409 and err.get("type") == "airlock_review_required":
        # Held for human review: nothing was sent. Counted as a block unless
        # --auto-approve-review approves the proposed redactions (see approve_review).
        record["status"] = "blocked"
        request_id = request_id or err.get("request_id")
        record["block_reasons"] = [f"review_required:{r}" for r in err.get("reasons") or []] or [
            "review_required"
        ]
        record["review"] = {
            "review_id": err.get("review_id"),
            "held_request_id": request_id,
            "span_ids": [p.get("span_id") for p in err.get("proposed") or [] if p.get("span_id")],
        }
    else:
        record["status"] = "error"
    return request_id, data


async def approve_review(
    client: httpx.AsyncClient, record: dict[str, Any]
) -> httpx.Response | None:
    """Approve every proposed redaction: POST /review/{review_id} {"approve": [span_id, ...]}.

    Airlock then finishes the request and answers like /v1/chat/completions (200 or 422) under a
    new request id, whose audit record is what gets scored.
    """
    review = record["review"]
    if not review.get("review_id"):
        record["status"] = "error"
        record["error"] = "409 airlock_review_required without a review_id"
        return None
    body = {"approve": review["span_ids"], "reject": [], "add": []}
    resp = await client.post(f"/review/{review['review_id']}", json=body)
    review["approval_status"] = resp.status_code
    if resp.status_code not in (200, 422):
        record["status"] = "error"
        record["error"] = f"review approval returned {resp.status_code}: {resp.text[:300]}"
        return None
    return resp


async def run_pass(
    client: httpx.AsyncClient, cases: list[dict[str, Any]], pass_no: int, opts: argparse.Namespace
) -> list[dict[str, Any]]:
    order = list(range(len(cases)))
    if opts.shuffle:
        random.Random(f"{opts.seed}:{pass_no}").shuffle(order)
    sem = asyncio.Semaphore(opts.concurrency)
    results: list[dict[str, Any] | None] = [None] * len(cases)
    done = 0

    async def one(i: int) -> None:
        nonlocal done
        async with sem:
            record = await execute_case(client, cases[i], opts, pass_no)
        record["pass"] = pass_no
        results[i] = record
        done += 1
        if not opts.quiet and (done % 25 == 0 or done == len(cases)):
            print(f"  pass {pass_no}: {done}/{len(cases)}", file=sys.stderr)

    if opts.concurrency == 1:
        for i in order:
            await one(i)
    else:
        await asyncio.gather(*(one(i) for i in order))
    return [r for r in results if r is not None]


# --------------------------------------------------------------------------------------------
# Scoring and output
# --------------------------------------------------------------------------------------------


def score_and_summarize(
    cases: list[dict[str, Any]], raw_passes: list[list[dict[str, Any]]], config: dict[str, Any]
) -> tuple[list[list[dict[str, Any]]], dict[str, Any]]:
    by_id = {c["id"]: c for c in cases}
    scored_passes = [[scoring.score_case(by_id[r["case_id"]], r) for r in p] for p in raw_passes]
    return scored_passes, scoring.summarize(cases, scored_passes, config)


def write_outputs(out: Path, raw_passes, scored_passes, summary) -> None:
    for i, (raw, scored) in enumerate(zip(raw_passes, scored_passes, strict=True), start=1):
        write_jsonl(
            out / f"pass_{i:02d}.jsonl",
            [{"record": r, "score": s} for r, s in zip(raw, scored, strict=True)],
        )
    (out / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (out / "summary.md").write_text(scoring.render_markdown(summary), encoding="utf-8")


def rescore(run_dir: Path) -> None:
    cases = read_jsonl(run_dir / "cases_snapshot.jsonl")
    config = json.loads((run_dir / "config.json").read_text(encoding="utf-8"))
    pass_files = sorted(run_dir.glob("pass_*.jsonl"))
    raw_passes = [[row["record"] for row in read_jsonl(p)] for p in pass_files]
    scored_passes, summary = score_and_summarize(cases, raw_passes, config)
    utility_summary = run_dir / "utility" / "summary.json"
    if utility_summary.exists():
        summary["utility"] = json.loads(utility_summary.read_text(encoding="utf-8"))["overall"]
    write_outputs(run_dir, raw_passes, scored_passes, summary)
    print(f"rescored {len(pass_files)} pass(es) in {run_dir}")
    print_headline(summary)


def print_headline(summary: dict[str, Any]) -> None:
    o = summary["overall"]

    def pct(key: str) -> str:
        s = o.get(key) or {}
        if not s.get("n"):
            return "n/a"
        lo, hi = s["min"] * 100, s["max"] * 100
        return f"{s['mean'] * 100:.1f}% ± {s['std'] * 100:.1f} (range {lo:.1f} to {hi:.1f})"

    print(f"passes: {summary['passes']}  cases: {summary['dataset']['cases']}")
    for key in (
        "leak_rate",
        "canary_leak_rate",
        "quasi_reid_rate",
        "gate_save_rate",
        "block_rate",
        "over_block_benign",
        "over_redaction_rate",
    ):
        print(f"  {key:24s} {pct(key)}")
    print(
        f"  persistent leaks: {len(summary['persistent_leaks'])}  "
        f"flaky leaks: {len(summary['flaky_leaks'])}"
    )


# --------------------------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--base-url", default="http://127.0.0.1:8787")
    ap.add_argument("--passes", type=int, default=10)
    ap.add_argument("--cases", default=DEFAULT_CASES, help="glob of case JSONL files")
    ap.add_argument("--out", type=Path, default=None, help="default: eval/results/<UTC timestamp>/")
    ap.add_argument(
        "--protection-level",
        default=None,
        help="expected server protection level (strict|balanced|minimal). Airlock reads "
        "it from AIRLOCK_PROTECTION_LEVEL at startup; the harness records it, checks "
        "it against /healthz and also sends it as an x-airlock-protection-level header",
    )
    ap.add_argument("--model", default="airlock", help="model field sent in chat requests")
    ap.add_argument("--max-results", type=int, default=5)
    ap.add_argument("--concurrency", type=int, default=1)
    ap.add_argument("--timeout", type=float, default=180.0)
    ap.add_argument("--audit-retries", type=int, default=3)
    ap.add_argument("--seed", type=int, default=0, help="seed for per-pass case order shuffling")
    ap.add_argument("--no-shuffle", dest="shuffle", action="store_false")
    ap.add_argument("--limit", type=int, default=None, help="only the first N cases (smoke tests)")
    ap.add_argument(
        "--category", action="append", default=None, help="restrict to category (repeatable)"
    )
    ap.add_argument(
        "--register-canaries",
        action="store_true",
        help="also declare canaries to the vault (kind=canary). Off by default because it "
        "tells the gate the answer; use only to test the gate in isolation",
    )
    ap.add_argument(
        "--conversation-scope",
        choices=["pass", "shared"],
        default="pass",
        help="pass (default): fresh x-airlock-conversation-id per case per pass, so passes are "
        "independent; shared: let Airlock derive it (later passes reuse earlier vault sessions)",
    )
    ap.add_argument(
        "--auto-approve-review",
        action="store_true",
        help="when Airlock answers 409 airlock_review_required, approve through the review "
        "endpoint and score what is sent. Default: count the held request as a block",
    )
    ap.add_argument(
        "--reset-vault",
        action="store_true",
        help="POST /vault/reset before the run (clears declared terms and conversation mappings)",
    )
    ap.add_argument("--label", default="airlock", help="free-text target label for the report")
    ap.add_argument(
        "--judge",
        action="store_true",
        help="answer utility and distortion after the run (eval/utility.py; part of the "
        "published protocol). Sends raw synthetic prompts to Token Factory for the reference "
        "answers. See README before using",
    )
    ap.add_argument("--judge-passes", type=int, default=1, help="judge only the first N passes")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument(
        "--rescore", type=Path, default=None, help="recompute summary for an existing run dir"
    )
    return ap.parse_args(argv)


async def main_async(opts: argparse.Namespace) -> Path:
    cases, dataset_sha = load_cases(opts.cases)
    if opts.category:
        cases = [c for c in cases if c["category"] in set(opts.category)]
    if opts.limit:
        cases = cases[: opts.limit]
    started = datetime.now(UTC)
    opts.run_id = started.strftime("%Y%m%dT%H%M%SZ")
    out = opts.out or EVAL_DIR / "results" / opts.run_id
    out.mkdir(parents=True, exist_ok=True)

    headers = {}
    if opts.protection_level:
        headers["x-airlock-protection-level"] = opts.protection_level
    timeout = httpx.Timeout(opts.timeout, connect=10.0)
    async with httpx.AsyncClient(
        base_url=opts.base_url, timeout=timeout, headers=headers
    ) as client:
        health = None
        try:
            hr = await client.get("/healthz")
            health = hr.json() if hr.status_code == 200 else {"status": hr.status_code}
        except (httpx.HTTPError, ValueError) as exc:
            health = {"error": str(exc)}
        if opts.reset_vault:
            rr = await client.post("/vault/reset", json={})
            if rr.status_code >= 400:
                raise SystemExit(f"/vault/reset returned {rr.status_code}: {rr.text[:200]}")
        server_level = (health or {}).get("protection_level")
        if opts.protection_level and server_level and server_level != opts.protection_level:
            print(
                f"WARNING: --protection-level {opts.protection_level} but server reports "
                f"{server_level}; restart Airlock with AIRLOCK_PROTECTION_LEVEL set",
                file=sys.stderr,
            )

        config = {
            "base_url": opts.base_url,
            "target_label": opts.label,
            "passes": opts.passes,
            "cases_glob": display_path(opts.cases),
            "cases": len(cases),
            "dataset_sha256": dataset_sha,
            "protection_level": opts.protection_level or server_level,
            "server_health": health,
            "model": opts.model,
            "concurrency": opts.concurrency,
            "shuffle": opts.shuffle,
            "conversation_scope": opts.conversation_scope,
            "seed": opts.seed,
            "register_canaries": opts.register_canaries,
            "auto_approve_review": opts.auto_approve_review,
            "reset_vault": opts.reset_vault,
            "started_at": started.isoformat(),
            "harness_version": scoring.HARNESS_VERSION,
            "argv": sys.argv[1:],
        }
        (out / "config.json").write_text(
            json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        write_jsonl(out / "cases_snapshot.jsonl", cases)

        raw_passes = []
        for p in range(1, opts.passes + 1):
            raw_passes.append(await run_pass(client, cases, p, opts))

        config["finished_at"] = datetime.now(UTC).isoformat()
        (out / "config.json").write_text(
            json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        scored_passes, summary = score_and_summarize(cases, raw_passes, config)

    write_outputs(out, raw_passes, scored_passes, summary)
    if opts.judge:
        import utility

        util_opts = utility.parse_args(
            ["--results", str(out), "--passes", str(opts.judge_passes), "--yes"]
        )
        if await utility.run_utility(util_opts):
            summary["utility"] = json.loads(
                (out / "utility" / "summary.json").read_text(encoding="utf-8")
            )["overall"]
            write_outputs(out, raw_passes, scored_passes, summary)
    print_headline(summary)
    print(f"results: {out}")
    return out


def main(argv: list[str] | None = None) -> None:
    opts = parse_args(argv)
    scoring.set_hash_key(load_audit_hash_key())
    if opts.rescore:
        rescore(opts.rescore)
        return
    if opts.passes < 1:
        raise SystemExit("--passes must be >= 1")
    asyncio.run(main_async(opts))


if __name__ == "__main__":
    main()
