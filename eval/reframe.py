# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx>=0.27"]
# ///
"""Unlinkability metrics: can the cloud say WHO has WHAT? One summary per system.

    uv run eval/reframe.py results eval/results/baseline-f0ba569
    uv run eval/reframe.py agent <agent run dir> --out eval/agent/results/demo/reframe --dry-run
    uv run eval/reframe.py agent <agent run dir> --out eval/agent/results/demo/reframe --yes

`results <dir>` (the 243-case harness) makes no network calls. It reads
* the harness pass files: `identity_leak_rate` from the scanner (eval/protected.py classes),
  computed from the stored audit records without rewriting them,
* `attack/` (eval/attack.py): identity recovery, situation inference, linkable disclosure,
* `utility/` (eval/utility.py): utility ratio and factual distortion,
* `summary.json`: over-redaction, benign masking, latency,
and writes `<dir>/reframe.json`, which eval/compare.py turns into the COMPARISON.md columns.

`agent <run dir>` (eval/agent) scores a finished agent-mode run with the same framing. Private
facts are classified in each scenario's `fact_classes`. It reuses the stored attacker outputs,
adds two kinds of Token Factory calls (both cached in --out and resumable):
* a situation grader without the named-anchor requirement (eval/attack.py rubric), per run,
* a blind pairwise utility judge per (scenario, pass): the unguarded answer is the reference,
  the Airlock answer the system, in a seeded random order (eval/utility.py rubric).
Everything is synthetic; the judge sees the scenario's fictional documents.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

EVAL_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(EVAL_DIR))
import attack  # noqa: E402
import protected  # noqa: E402
import scoring  # noqa: E402
import utility  # noqa: E402

REFRAME_VERSION = "1.0.0"
AGENT_MODES = ("unguarded", "airlock")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def load_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _rate(num: float, den: float) -> float | None:
    return None if den == 0 else num / den


def linkable_metrics(identity: list[bool | None], situation: list[bool | None]) -> dict:
    """Pure metric math over per-case flags (None = not eligible for that metric).

    linkable counts a case only when it is eligible for both and both are true.
    """
    id_cases = [x for x in identity if x is not None]
    sit_cases = [x for x in situation if x is not None]
    both = [
        (i, s) for i, s in zip(identity, situation, strict=True) if i is not None and s is not None
    ]
    return {
        "identity_rate": _rate(sum(id_cases), len(id_cases)),
        "situation_rate": _rate(sum(sit_cases), len(sit_cases)),
        "linkable_rate": _rate(sum(1 for i, s in both if i and s), len(both)),
        "identity_cases": len(id_cases),
        "situation_cases": len(sit_cases),
        "linkable_cases": len(both),
    }


# --------------------------------------------------------------------------------------------
# 243-case results directories
# --------------------------------------------------------------------------------------------


def identity_leak_pass(cases: dict[str, dict], records: list[dict[str, Any]]) -> dict[str, Any]:
    scored = [scoring.score_case(cases[r["case_id"]], r) for r in records]
    ok = [s for s in scored if s["status"] != "error" and s["has_identity"]]

    def rate(items: list[dict]) -> float | None:
        return _rate(sum(bool(s["identity_leaked"]) for s in items), len(items))

    return {
        "identity_leak_rate": rate(ok),
        "by_lang": {lang: rate([s for s in ok if s["lang"] == lang]) for lang in ("ko", "en")},
        "cases": len(ok),
    }


def results_reframe(run_dir: Path) -> dict[str, Any]:
    cases = {c["id"]: c for c in read_jsonl(run_dir / "cases_snapshot.jsonl")}
    passes = [
        [row["record"] for row in read_jsonl(p)] for p in sorted(run_dir.glob("pass_*.jsonl"))
    ]
    leak = [identity_leak_pass(cases, p) for p in passes]
    summary = load_json(run_dir / "summary.json") or {}
    atk = load_json(run_dir / "attack" / "summary.json") or {}
    util = load_json(run_dir / "utility" / "summary.json") or {}

    def pick(source: dict, key: str, lang: str | None = None) -> dict[str, Any]:
        if lang:
            return (source.get("by_lang") or {}).get(lang, {}).get(key) or {"n": 0}
        return (source.get("overall") or {}).get(key) or {"n": 0}

    metrics: dict[str, Any] = {}
    for lang in (None, "ko", "en"):
        m = {
            "identity_leak_rate": scoring.describe(
                (p["by_lang"][lang] if lang else p["identity_leak_rate"]) for p in leak
            ),
            "attack_identity_recovery_rate": pick(atk, "attack_identity_recovery_rate", lang),
            "situation_inference_rate": pick(atk, "situation_inference_rate", lang),
            "linkable_disclosure_rate": pick(atk, "linkable_disclosure_rate", lang),
            "utility_mean": pick(util, "utility_mean", lang),
            "utility_ratio_vs_reference": pick(util, "utility_ratio_vs_reference", lang),
            "distortion_rate": pick(util, "distortion_rate", lang),
            "reference_distortion_rate": pick(util, "reference_distortion_rate", lang),
            "over_redaction_rate": pick(summary, "over_redaction_rate", lang),
            "benign_false_positive_rate": pick(summary, "benign_false_positive_rate", lang),
            "leak_rate": pick(summary, "leak_rate", lang),
            "block_rate": pick(summary, "block_rate", lang),
            "overhead_ms_p50": pick(summary, "overhead_ms_p50", lang),
            "overhead_ms_p95": pick(summary, "overhead_ms_p95", lang),
        }
        metrics[lang or "overall"] = m
    return {
        "reframe_version": REFRAME_VERSION,
        "results_dir": run_dir.name,
        "target_label": (summary.get("config") or {}).get("target_label"),
        "harness_passes": len(passes),
        "attacked_passes": atk.get("passes", 0),
        "judged_passes": util.get("passes", 0),
        "overall": metrics["overall"],
        "by_lang": {"ko": metrics["ko"], "en": metrics["en"]},
        "identity_leak_per_pass": leak,
        "generated_at": datetime.now(UTC).isoformat(),
    }


def cmd_results(opts: argparse.Namespace) -> None:
    for run_dir in opts.dirs:
        data = results_reframe(run_dir)
        (run_dir / "reframe.json").write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        o = data["overall"]

        def f(stat: dict) -> str:
            return "n/a" if not stat.get("n") else f"{stat['mean'] * 100:.1f}%"

        print(
            f"{run_dir.name}: identity leak {f(o['identity_leak_rate'])}, identity recovered "
            f"{f(o['attack_identity_recovery_rate'])}, situation {f(o['situation_inference_rate'])}"
            f", linkable {f(o['linkable_disclosure_rate'])}, distortion {f(o['distortion_rate'])}"
        )


# --------------------------------------------------------------------------------------------
# Agent-mode runs
# --------------------------------------------------------------------------------------------


def agent_identity_flags(
    scenario: dict[str, Any], graded: dict[str, Any], views_all: list[dict[str, Any]] | None
) -> dict[str, Any]:
    """Per-run identity/situation flags from the stored attacker facts and the outbound views."""
    classes = protected.scenario_fact_classes(scenario)
    facts = graded["all_hops"]["facts"]["facts"]
    identity_facts = [f for f in facts if classes[f["fact"]] == protected.IDENTITY]
    situation_facts = [f for f in facts if classes[f["fact"]] == protected.SITUATION]
    leaked = None
    if views_all is not None:
        hays = [scoring.Haystack(v.get("payload")) for v in views_all]
        leaked = any(
            h.find(f["fact"]) for f in identity_facts for h in hays
        )  # scanner, no attacker
    return {
        "identity_leaked": leaked,
        "identity_recovered": any(f["match"] == "exact" for f in identity_facts),
        "identity_facts": len(identity_facts),
        "identity_facts_recovered": sum(f["match"] == "exact" for f in identity_facts),
        "situation_facts": len(situation_facts),
        "situation_facts_recovered": sum(f["match"] == "exact" for f in situation_facts),
    }


def agent_judge_request(scenario: dict[str, Any]) -> str:
    docs = "\n\n".join(f"--- {name} ---\n{text}" for name, text in scenario["docs"])
    rubric = "\n".join(f"- {r}" for r in scenario["answer_rubric"])
    return (
        f"[user question] {scenario['question']}\n\n"
        f"[the user's private documents, which the assistant could read]\n{docs}\n\n"
        f"[what a good answer covers]\n{rubric}"
    )


def agent_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Rates pooled over the runs of one mode and pass."""
    link = linkable_metrics(
        [r["identity_recovered"] for r in rows], [r["situation_new"] for r in rows]
    )
    id_n = sum(r["identity_facts"] for r in rows)
    sit_n = sum(r["situation_facts"] for r in rows)
    judged = [r for r in rows if r.get("usefulness") is not None]
    leak_flags = [r["identity_leaked"] for r in rows if r["identity_leaked"] is not None]
    return {
        "runs": len(rows),
        "identity_leak_rate": _rate(sum(leak_flags), len(leak_flags)),
        "attack_identity_recovery_rate": link["identity_rate"],
        "identity_fact_recovery": _rate(sum(r["identity_facts_recovered"] for r in rows), id_n),
        "situation_fact_recovery": _rate(sum(r["situation_facts_recovered"] for r in rows), sit_n),
        "situation_inference_rate": link["situation_rate"],
        "situation_inference_strict": _rate(sum(r["situation_strict"] for r in rows), len(rows)),
        "linkable_disclosure_rate": link["linkable_rate"],
        "rubric_utility_mean": statistics.fmean(
            [r["rubric_utility"] for r in rows if r["rubric_utility"] is not None]
        )
        if any(r["rubric_utility"] is not None for r in rows)
        else None,
        "pairwise_utility_mean": statistics.fmean(r["usefulness"] for r in judged)
        if judged
        else None,
        "distortion_rate": _rate(sum(r["distortion"] for r in judged), len(judged)),
    }


AGENT_KEYS = (
    "identity_leak_rate",
    "attack_identity_recovery_rate",
    "identity_fact_recovery",
    "situation_fact_recovery",
    "situation_inference_rate",
    "situation_inference_strict",
    "linkable_disclosure_rate",
    "rubric_utility_mean",
    "pairwise_utility_mean",
    "distortion_rate",
)


async def agent_calls(opts, scenarios, graded_all, runs_by_key, out: Path) -> dict[str, Any]:
    """Situation grades per run and pairwise utility judgments per (scenario, pass). Cached."""
    import httpx

    sit_path = out / "situation.jsonl"
    util_path = out / "utility.jsonl"
    sit_done = {(r["scenario_id"], r["mode"], r["pass"]): r for r in read_jsonl(sit_path)}
    util_done = {(r["scenario_id"], r["pass"]): r for r in read_jsonl(util_path)}
    sit_todo = [g for g in graded_all if (g["scenario_id"], g["mode"], g["pass"]) not in sit_done]
    pairs = sorted({(g["scenario_id"], g["pass"]) for g in graded_all})
    util_todo = [
        p
        for p in pairs
        if p not in util_done and all((p[0], m, p[1]) in runs_by_key for m in AGENT_MODES)
    ]
    tok = attack.estimate_tokens
    sit_prompt = sum(
        tok(attack.SITUATION_GRADER_SYSTEM) + tok(true_situation(scenarios[g["scenario_id"]])) + 400
        for g in sit_todo
    )
    util_prompt = sum(
        tok(utility.JUDGE_SYSTEM)
        + tok(agent_judge_request(scenarios[sid]))
        + sum(tok(runs_by_key[(sid, m, p)].get("answer") or "") for m in AGENT_MODES)
        for sid, p in util_todo
    )
    est = {
        "situation_calls": len(sit_todo),
        "utility_judge_calls": len(util_todo),
        "prompt_tokens_est": sit_prompt + util_prompt,
        "completion_tokens_max": len(sit_todo) * attack.GRADER_MAX_TOKENS
        + len(util_todo) * utility.JUDGE_MAX_TOKENS,
    }
    print(
        f"agent reframe estimate: {est['situation_calls']} situation grader + "
        f"{est['utility_judge_calls']} utility judge calls, ~{est['prompt_tokens_est']:,} prompt "
        f"tokens, <= {est['completion_tokens_max']:,} completion tokens",
        file=sys.stderr,
    )
    usage = {"prompt_tokens": 0, "completion_tokens": 0}
    if opts.dry_run or not (sit_todo or util_todo):
        return {"estimate": est, "usage": usage, "situation": sit_done, "utility": util_done}
    if not opts.yes:
        raise SystemExit("not running: pass --yes to make these calls (synthetic data only)")
    key = attack.read_env_key()
    if not key:
        raise SystemExit("NEBIUS_API_KEY is not set (environment or .env)")
    out.mkdir(parents=True, exist_ok=True)
    async with httpx.AsyncClient(
        base_url=opts.base_url,
        headers={"Authorization": f"Bearer {key}"},
        timeout=httpx.Timeout(300.0, connect=15.0),
    ) as client:
        llm = attack.make_llm(client, opts.model)
        sem = asyncio.Semaphore(opts.concurrency)

        async def grade(g: dict[str, Any]) -> dict[str, Any]:
            s = scenarios[g["scenario_id"]]
            attacked = g["all_hops"].get("attack")
            row = {k: g[k] for k in ("scenario_id", "mode", "pass")}
            if not g["all_hops"].get("sent") or not attacked:
                row["situation_match"] = False
                return row
            attacked = attack.normalize_attack(attacked)
            if not (attacked["private_situation"].strip() or attacked["person_attributes"]):
                row["situation_match"] = False
                return row
            async with sem:
                reply = await llm(
                    attack.situation_messages(true_situation(s), attacked), "situation",
                    attack.GRADER_SCHEMA, "none", attack.GRADER_MAX_TOKENS,
                )  # fmt: skip
            row["situation_match"] = attack.parse_grade(reply.get("content"))
            row["raw"] = reply.get("content")
            row["usage"] = reply.get("usage")
            return row

        async def judge(pair: tuple[str, int]) -> dict[str, Any]:
            sid, pass_no = pair
            s = scenarios[sid]
            sys_answer = runs_by_key[(sid, "airlock", pass_no)].get("answer") or ""
            ref_answer = runs_by_key[(sid, "unguarded", pass_no)].get("answer") or ""
            system_first = utility.order_flip(sid, pass_no, "agent")
            a1, a2 = (sys_answer, ref_answer) if system_first else (ref_answer, sys_answer)
            shown = "Answer 1" if system_first else "Answer 2"
            row: dict[str, Any] = {"scenario_id": sid, "pass": pass_no, "system_shown_as": shown}
            async with sem:
                reply = await llm(
                    utility.judge_messages({}, a1, a2, request_text=agent_judge_request(s)),
                    "utility_judge", utility.JUDGE_SCHEMA, "none", utility.JUDGE_MAX_TOKENS,
                )  # fmt: skip
            row["raw"] = reply.get("content")
            row["usage"] = reply.get("usage")
            grades = utility.parse_judgment(reply.get("content"))
            if grades is not None:
                airlock_grade, unguarded_grade = utility.assign(grades, system_first)
                async with sem:
                    checks = await utility.verify_distortions(
                        llm,
                        agent_judge_request(s),
                        [(airlock_grade, sys_answer), (unguarded_grade, ref_answer)],
                    )
                row["verify"] = checks
                for mode, grade_, answer in (
                    ("airlock", airlock_grade, sys_answer),
                    ("unguarded", unguarded_grade, ref_answer),
                ):
                    if not answer.strip():
                        grade_ = {"usefulness": 1, "distortion": False,
                                  "distortion_detail": "(no answer)"}  # fmt: skip
                    row[mode] = grade_
            return row

        sit_rows = await asyncio.gather(*(grade(g) for g in sit_todo))
        util_rows = await asyncio.gather(*(judge(p) for p in util_todo))
    for r in [*sit_rows, *util_rows]:
        for u in attack.iter_usage(r):
            utility.add_usage(usage, u)
    with sit_path.open("a", encoding="utf-8") as f:
        for r in sit_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
            sit_done[(r["scenario_id"], r["mode"], r["pass"])] = r
    with util_path.open("a", encoding="utf-8") as f:
        for r in util_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
            util_done[(r["scenario_id"], r["pass"])] = r
    return {"estimate": est, "usage": usage, "situation": sit_done, "utility": util_done}


def true_situation(s: dict[str, Any]) -> str:
    return (
        f"User question: {s['question']}\n"
        f"Private situation: {s['private_situation']}\n"
        f"Private facts: {'; '.join(s['private_facts'])}"
    )


def cmd_agent(opts: argparse.Namespace) -> None:
    sys.path.insert(0, str(EVAL_DIR / "agent"))
    import run_agent_eval as ev  # imports the airlock package (observer views)

    run_dir: Path = opts.run_dir
    out: Path = opts.out
    scenarios = {s["id"]: s for s in ev.load_scenarios()}
    runs = [r for p in sorted((run_dir / "runs").glob("pass_*.jsonl")) for r in read_jsonl(p)]
    graded_all = [
        g
        for p in sorted((run_dir / "attack").glob("pass_*.jsonl"))
        for g in read_jsonl(p)
        if g["scenario_id"] in scenarios
    ]
    runs_by_key = {(r["scenario_id"], r["mode"], r["pass"]): r for r in runs}
    graded_all = [g for g in graded_all if (g["scenario_id"], g["mode"], g["pass"]) in runs_by_key]
    calls = asyncio.run(agent_calls(opts, scenarios, graded_all, runs_by_key, out))
    if opts.dry_run:
        return
    rows = []
    for g in graded_all:
        k = (g["scenario_id"], g["mode"], g["pass"])
        s = scenarios[g["scenario_id"]]
        views = ev.observer_views(runs_by_key[k].get("audit") or {})
        flags = agent_identity_flags(s, g, views["all"])
        sit = calls["situation"].get(k, {}).get("situation_match")
        judged = (calls["utility"].get((g["scenario_id"], g["pass"])) or {}).get(g["mode"])
        rows.append(
            {
                "scenario_id": g["scenario_id"],
                "lang": g["lang"],
                "mode": g["mode"],
                "pass": g["pass"],
                **flags,
                "situation_new": bool(sit) if sit is not None else None,
                "situation_strict": bool(g["all_hops"].get("situation")),
                "rubric_utility": (g.get("utility") or {}).get("score"),
                "usefulness": (judged or {}).get("usefulness"),
                "distortion": (judged or {}).get("distortion"),
                "distortion_detail": (judged or {}).get("distortion_detail"),
            }
        )
    passes = sorted({r["pass"] for r in rows})
    summary: dict[str, Any] = {
        "reframe_version": REFRAME_VERSION,
        "source_run": str(run_dir),
        "passes": len(passes),
        "modes": {},
    }
    for mode in AGENT_MODES:
        per_pass = [
            agent_metrics([r for r in rows if r["mode"] == mode and r["pass"] == p]) for p in passes
        ]
        by_lang = {
            lang: {
                k: scoring.describe(
                    agent_metrics(
                        [
                            r
                            for r in rows
                            if r["mode"] == mode and r["pass"] == p and r["lang"] == lang
                        ]
                    )[k]
                    for p in passes
                )
                for k in AGENT_KEYS
            }
            for lang in ("ko", "en")
        }
        summary["modes"][mode] = {
            "overall": {k: scoring.describe(pp[k] for pp in per_pass) for k in AGENT_KEYS},
            "by_lang": by_lang,
            "per_pass": per_pass,
        }
    ug = summary["modes"]["unguarded"]["per_pass"]
    al = summary["modes"]["airlock"]["per_pass"]
    summary["utility_ratio_vs_unguarded"] = scoring.describe(
        (a["pairwise_utility_mean"] / u["pairwise_utility_mean"])
        if a["pairwise_utility_mean"] and u["pairwise_utility_mean"]
        else None
        for a, u in zip(al, ug, strict=True)
    )
    summary["rows"] = rows
    cfg_path = out / "config.json"
    cfg = load_json(cfg_path) or {}
    cfg.update({"reframe_version": REFRAME_VERSION, "source_run": str(run_dir),
                "model": opts.model})  # fmt: skip
    if calls["usage"]["prompt_tokens"]:
        cfg.setdefault("runs", []).append(
            {
                "at": datetime.now(UTC).isoformat(),
                "estimate": calls["estimate"],
                "usage": calls["usage"],
            }  # fmt: skip
        )
    out.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    summary["config"] = cfg
    (out / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (out / "summary.md").write_text(render_agent_markdown(summary), encoding="utf-8")
    print((out / "summary.md").read_text(encoding="utf-8").split("\n## ")[0])


AGENT_LABELS = (
    ("identity_leak_rate", "Identity leak: any identity fact in the outbound payloads (scanner)"),
    ("attack_identity_recovery_rate", "Identity recovered: attacker names any identity fact"),
    ("identity_fact_recovery", "Identity facts recovered (share of facts)"),
    ("situation_fact_recovery", "Situation facts recovered (share of facts)"),
    ("situation_inference_rate", "Situation inferred (grader, no anchor needed)"),
    ("situation_inference_strict", "Situation inferred (original grader, named anchor required)"),
    ("linkable_disclosure_rate", "Linkable disclosure: identity recovered AND situation inferred"),
    ("rubric_utility_mean", "Answer utility, rubric grader (1-5)"),
    ("pairwise_utility_mean", "Answer utility, blind pairwise judge (1-5)"),
    ("distortion_rate", "Factual distortion (blind pairwise judge)"),
)


def render_agent_markdown(summary: dict[str, Any]) -> str:
    def cell(stat: dict[str, Any], key: str) -> str:
        if not stat or not stat.get("n") or stat.get("mean") is None:
            return "n/a"
        if "utility_mean" in key:
            return f"{stat['mean']:.2f} ± {stat['std']:.2f}"
        return f"{stat['mean'] * 100:.1f}% ± {stat['std'] * 100:.1f}"

    usage = {"prompt_tokens": 0, "completion_tokens": 0}
    for run in (summary.get("config") or {}).get("runs") or []:
        utility.add_usage(usage, run.get("usage"))
    ratio = summary["utility_ratio_vs_unguarded"]
    lines = [
        "# Agent mode, reframed: who has what",
        "",
        f"- source run: `{Path(summary['source_run']).name}` ({summary['passes']} passes, 16 "
        "scenarios, 2 modes); attacker outputs reused from that run",
        "- new calls: situation grader without the named-anchor requirement, and a blind "
        "pairwise utility/distortion judge (unguarded answer = reference); "
        f"tokens: prompt {usage['prompt_tokens']:,}, completion {usage['completion_tokens']:,}",
        "- utility ratio airlock / unguarded (pairwise judge): "
        + ("n/a" if not ratio.get("n") else f"{ratio['mean']:.2f} ± {ratio['std']:.2f}"),
        "",
        "| Metric | unguarded | airlock |",
        "|---|---:|---:|",
    ]
    for key, label in AGENT_LABELS:
        cells = [cell(summary["modes"][m]["overall"][key], key) for m in AGENT_MODES]
        lines.append(f"| {label} | " + " | ".join(cells) + " |")
    lines += [
        "",
        "Mean ± sample sd across passes; rates pooled over the 16 scenarios of a pass.",
        "",
    ]
    for lang in ("ko", "en"):
        lines += [f"## {lang}", "", "| Metric | unguarded | airlock |", "|---|---:|---:|"]
        for key, label in AGENT_LABELS:
            cells = [cell(summary["modes"][m]["by_lang"][lang][key], key) for m in AGENT_MODES]
            lines.append(f"| {label} | " + " | ".join(cells) + " |")
        lines.append("")
    distorted = [r for r in summary["rows"] if r.get("distortion")]
    if distorted:
        lines += ["## Distorted answers", "", "| Scenario | Mode | Pass | Judge's evidence |",
                  "|---|---|---:|---|"]  # fmt: skip
        for r in sorted(distorted, key=lambda r: (r["scenario_id"], r["mode"], r["pass"])):
            detail = (r.get("distortion_detail") or "").replace("|", "\\|")[:300]
            lines.append(f"| {r['scenario_id']} | {r['mode']} | {r['pass']} | {detail} |")
        lines.append("")
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("results", help="243-case results directories (no network)")
    r.add_argument("dirs", type=Path, nargs="+")
    a = sub.add_parser("agent", help="an agent-mode run directory (runs/ and attack/)")
    a.add_argument("run_dir", type=Path)
    a.add_argument("--out", type=Path, required=True)
    a.add_argument("--base-url", default=attack.DEFAULT_BASE_URL)
    a.add_argument("--model", default=attack.DEFAULT_MODEL)
    a.add_argument("--concurrency", type=int, default=6)
    a.add_argument("--dry-run", action="store_true")
    a.add_argument("--yes", action="store_true")
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    opts = parse_args(argv)
    if opts.cmd == "results":
        cmd_results(opts)
    else:
        cmd_agent(opts)


if __name__ == "__main__":
    main()
