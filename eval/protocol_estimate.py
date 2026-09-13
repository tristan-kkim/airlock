# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx>=0.27"]
# ///
"""Cloud call and token estimate for eval/final_protocol.sh, printed before anything runs.

    uv run eval/protocol_estimate.py --passes 3 --systems raw regex presidio_ko gliner_pii \
        --airlock-variants 2 --baseline-judge-passes 1 --variants
    uv run eval/protocol_estimate.py --subset stratified:120 --seed 0 --airlock-variants 2

Before the runs exist the outbound payloads are unknown, so every payload is estimated from the
raw case text (an upper-leaning bound: masking only shortens prompts). Token counts use the same
heuristic as eval/attack.py (about 4 ASCII characters or 1 non-ASCII character per token).
Dollars use Token Factory list prices (eval/attack.py MODEL_PRICES) for the model of each part:
answers come from the upstream model, the four scoring roles from their role models
(AIRLOCK_ATTACK_MODEL, AIRLOCK_GRADER_MODEL, AIRLOCK_UTILITY_MODEL,
AIRLOCK_DISTORTION_CONFIRM_MODEL, or the defaults chosen in eval/results/JUDGE_CALIBRATION.md).

Reuse (eval/reuse.py): the baselines are deterministic, so with --reuse-identical-passes only one
baseline pass needs scoring (`--baseline-judge-passes 1`), and none when their pass 1 is reused
from the committed runs (`--baseline-judge-passes 0`). Airlock passes are assumed to differ.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

EVAL_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(EVAL_DIR))
import attack  # noqa: E402
import protected  # noqa: E402
import subset  # noqa: E402
import utility  # noqa: E402

AIRLOCK_NOTE_TOKENS = 120  # the privacy note Airlock prepends to upstream requests
SEARCH_ANSWER_PROMPT = 1500  # search results the answer step reads
ATTACK_COMPLETION_TYPICAL = 350  # measured: 175k prompt / 82k completion over 243 raw payloads
GRADER_COMPLETION_TYPICAL = 95  # measured: 10k completion over 107 situation grades
JUDGE_COMPLETION_TYPICAL = 240  # measured: 44k-50k completion over 208 judge calls
VERIFY_SHARE = 0.22  # measured: 57-96 confirmations per 208 judged cases (2 answers each)
VERIFY_PROMPT_TYPICAL = 1300  # measured: 83k-132k prompt over 57-96 confirmations
VERIFY_COMPLETION_TYPICAL = 50


def load_cases() -> list[dict]:
    return [
        json.loads(line)
        for p in sorted((EVAL_DIR / "cases").glob("*.jsonl"))
        for line in p.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def case_text(case: dict) -> str:
    if case["task"] == "chat":
        return json.dumps(case["messages"], ensure_ascii=False)
    return json.dumps({"query": case["query"]}, ensure_ascii=False)


PART_ROLES = {
    "airlock upstream answers": None,
    "attacker": "attack",
    "intent + situation graders": "grader",
    "reference + baseline answers": None,
    "utility judge": "utility",
    "distortion confirmation": "distortion_confirm",
}
BASELINES = ["raw", "regex", "presidio_ko", "gliner_pii"]
COUNTS = ("calls", "prompt", "completion_typical", "completion_max")


def estimate(
    passes: int,
    judge_passes: int,
    systems: list[str],
    variants: int,
    models: dict[str, str | None] | None = None,
    subset_spec: str | None = None,
    seed: int = 0,
    baseline_judge_passes: int | None = None,
) -> dict:
    """Calls and tokens per part, priced with each part's model.

    `passes` harness passes per Airlock variant (upstream answers), `judge_passes` scored passes
    per Airlock variant, `baseline_judge_passes` scored passes per baseline (default
    `judge_passes`; 1 with reuse of identical passes, 0 when reused from committed runs).
    `models` maps roles to models (default: attack.role_model). Answers always come from the
    upstream model (Ultra): they are what the systems are measured on, not a judge.
    """
    models = {role: (models or {}).get(role) or attack.role_model(role) for role in attack.ROLE_ENV}
    bjp = judge_passes if baseline_judge_passes is None else baseline_judge_passes
    tok = attack.estimate_tokens
    cases, _ = subset.select(load_cases(), subset_spec, seed)
    chat = [c for c in cases if c["task"] == "chat"]
    search = [c for c in cases if c["task"] == "search"]
    out: dict[str, dict] = {}

    chat_prompt = sum(tok(case_text(c)) + AIRLOCK_NOTE_TOKENS for c in chat)
    runs = passes * variants
    out["airlock upstream answers"] = {
        "calls": runs * (len(chat) + len(search)),
        "prompt": runs * (chat_prompt + len(search) * SEARCH_ANSWER_PROMPT),
        "completion_typical": runs * (len(chat) + len(search)) * utility.ANSWER_TOKENS_TYPICAL,
        "completion_max": runs * (len(chat) + len(search)) * utility.ANSWER_MAX_TOKENS,
        "tavily_searches": runs * len(search),
    }

    attacker_prompt = sum(tok(attack.ATTACKER_SYSTEM) + tok(case_text(c)) + 60 for c in cases)
    intent = [c for c in cases if c["category"] == "intent_leak_search"]
    sensitive = [c for c in cases if protected.classify_case(c)["situation_sensitive"]]
    grader_prompt = sum(
        tok(attack.GRADER_SYSTEM) + tok(attack.true_situation(c)) + 300 for c in intent
    ) + sum(attack.situation_prompt_estimate(c) for c in sensitive)
    graders = len(intent) + len(sensitive)
    scored = judge_passes * variants + bjp * len(systems)  # scored (system, pass) runs
    out["attacker"] = {
        "calls": scored * len(cases),
        "prompt": scored * attacker_prompt,
        "completion_typical": scored * len(cases) * ATTACK_COMPLETION_TYPICAL,
        "completion_max": scored * len(cases) * attack.MAX_OUTPUT_TOKENS,
    }
    out["intent + situation graders"] = {
        "calls": scored * graders,
        "prompt": scored * grader_prompt,
        "completion_typical": scored * graders * GRADER_COMPLETION_TYPICAL,
        "completion_max": scored * graders * attack.GRADER_MAX_TOKENS,
    }

    ref_cached = sum(
        1
        for c in chat
        if utility.load_reference(
            utility.REFERENCE_DIR,
            c["id"],
            attack.DEFAULT_MODEL,
            utility.reference_body(c, attack.DEFAULT_MODEL),
        )
    )
    refs = (len(chat) - ref_cached) if scored else 0
    baseline_answers = bjp * len(systems) * len(chat)
    judges = scored * len(chat)
    verifies = int(judges * 2 * VERIFY_SHARE)
    judge_prompt = sum(
        tok(utility.JUDGE_SYSTEM) + tok(utility.render_request(c["messages"])) for c in chat
    )
    out["reference + baseline answers"] = {
        "calls": refs + baseline_answers,
        "prompt": refs * (chat_prompt // max(len(chat), 1)) + bjp * len(systems) * chat_prompt,
        "completion_typical": (refs + baseline_answers) * utility.ANSWER_TOKENS_TYPICAL,
        "completion_max": (refs + baseline_answers) * utility.ANSWER_MAX_TOKENS,
        "reference_answers_cached": ref_cached,
    }
    out["utility judge"] = {
        "calls": judges,
        "prompt": scored * (judge_prompt + 2 * len(chat) * utility.ANSWER_TOKENS_TYPICAL),
        "completion_typical": judges * JUDGE_COMPLETION_TYPICAL,
        "completion_max": judges * utility.JUDGE_MAX_TOKENS,
    }
    out["distortion confirmation"] = {
        "calls": verifies,
        "prompt": verifies * VERIFY_PROMPT_TYPICAL,
        "completion_typical": verifies * VERIFY_COMPLETION_TYPICAL,
        "completion_max": verifies * utility.VERIFY_MAX_TOKENS,
    }
    for name, part in out.items():
        role = PART_ROLES[name]
        part["model"] = models[role] if role else attack.DEFAULT_MODEL
        spent = {"prompt_tokens": part["prompt"], "completion_tokens": part["completion_typical"]}
        part["usd"] = attack.usage_cost(part["model"], spent) or 0.0
        part["usd_all_ultra"] = attack.usage_cost(attack.ULTRA, spent) or 0.0
    total = {k: sum(v.get(k, 0) for v in out.values()) for k in COUNTS}
    total["tokens"] = total["prompt"] + total["completion_typical"]
    total["usd"] = sum(v["usd"] for v in out.values())
    total["usd_all_ultra"] = sum(v["usd_all_ultra"] for v in out.values())
    return {"parts": out, "total": total, "models": models, "cases": len(cases)}


def print_estimate(title: str, est: dict) -> None:
    print(title)
    for name, part in est["parts"].items():
        extra = ""
        if "tavily_searches" in part:
            extra = f", {part['tavily_searches']} Tavily searches"
        if "reference_answers_cached" in part:
            extra = f", {part['reference_answers_cached']} reference answers already cached"
        print(
            f"  {name} [{short_model(part['model'])}]: {part['calls']:,} calls, "
            f"~{part['prompt']:,} prompt + ~{part['completion_typical']:,} completion tokens "
            f"(completion <= {part['completion_max']:,}), ~${part['usd']:.2f}{extra}"
        )
    t = est["total"]
    print(
        f"  TOTAL: {t['calls']:,} calls, ~{t['prompt']:,} prompt + ~{t['completion_typical']:,} "
        f"completion tokens typical = ~{t['tokens']:,} tokens, ~${t['usd']:.2f} at list prices "
        f"(all roles on Ultra: ~${t['usd_all_ultra']:.2f})"
    )


def short_model(model: str) -> str:
    return model.split("/")[-1]


VARIANTS = (
    ("(a) 243 cases, Airlock 3 passes x 1 config", None, 1),
    ("(b) 243 cases, Airlock 3 passes x 2 configs", None, 2),
    ("(c) stratified 120, Airlock 3 passes x 2 configs", "stratified:120", 2),
)


def variant_rows(models: dict[str, str | None] | None = None, seed: int = 0) -> list[dict]:
    """The protocol variants: Airlock passes differ; baselines are deterministic.

    For each: the Airlock part (upstream answers + scoring every pass), the baselines scored
    once (identical passes reused), and the baselines reused entirely from committed runs.
    """
    rows = []
    for title, spec, configs in VARIANTS:
        airlock = estimate(3, 3, [], configs, models, spec, seed)["total"]
        once = estimate(3, 3, BASELINES, configs, models, spec, seed, baseline_judge_passes=1)
        reused = estimate(3, 3, BASELINES, configs, models, spec, seed, baseline_judge_passes=0)
        no_reuse = estimate(3, 3, BASELINES, configs, models, spec, seed)
        rows.append(
            {
                "variant": title,
                "cases": once["cases"],
                "airlock": airlock,
                "baselines_once": {
                    k: once["total"][k] - airlock[k] for k in ("tokens", "usd", "usd_all_ultra")
                },
                "total_once": once["total"],
                "total_reused": reused["total"],
                "total_no_reuse": no_reuse["total"],
                "airlock_upstream": once["parts"]["airlock upstream answers"],
            }
        )
    return rows


def print_variants(models: dict[str, str | None] | None = None, seed: int = 0) -> None:
    print(
        "Protocol variants (list prices; tokens = prompt + typical completion; Airlock passes "
        "assumed to differ, baselines identical across passes):"
    )
    print(
        "  | variant | Airlock upstream (Ultra) | Airlock scoring | baselines scored once | "
        "TOTAL, baselines scored once | TOTAL, baselines reused from committed runs | "
        "TOTAL without reuse |"
    )

    def cell(tokens: float, usd: float) -> str:
        return f"{tokens / 1e6:.1f}M ${usd:.2f}"

    for r in variant_rows(models, seed):
        up = r["airlock_upstream"]
        up_tokens = up["prompt"] + up["completion_typical"]
        a = r["airlock"]
        print(
            f"  | {r['variant']} | {cell(up_tokens, up['usd'])} | "
            f"{cell(a['tokens'] - up_tokens, a['usd'] - up['usd'])} | "
            f"{cell(r['baselines_once']['tokens'], r['baselines_once']['usd'])} | "
            f"{cell(r['total_once']['tokens'], r['total_once']['usd'])} | "
            f"{cell(r['total_reused']['tokens'], r['total_reused']['usd'])} | "
            f"{cell(r['total_no_reuse']['tokens'], r['total_no_reuse']['usd'])} |"
        )


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--passes", type=int, default=3)
    ap.add_argument("--judge-passes", type=int, default=None, help="default: --passes")
    ap.add_argument(
        "--baseline-judge-passes",
        type=int,
        default=None,
        help="scored passes per baseline (default --judge-passes; 1 when identical passes are "
        "reused, 0 when pass 1 is reused from committed runs)",
    )
    ap.add_argument("--systems", nargs="*", default=BASELINES)
    ap.add_argument("--airlock-variants", type=int, default=1)
    ap.add_argument("--subset", default=None, help="stratified:N or ids:PATH")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--attack-model", default=None)
    ap.add_argument("--grader-model", default=None)
    ap.add_argument("--judge-model", default=None)
    ap.add_argument("--confirm-model", default=None)
    ap.add_argument("--variants", action="store_true", help="also print the protocol variants")
    args = ap.parse_args(argv)
    models = {
        "attack": args.attack_model,
        "grader": args.grader_model,
        "utility": args.judge_model,
        "distortion_confirm": args.confirm_model,
    }
    judge_passes = args.judge_passes or args.passes
    est = estimate(
        args.passes,
        judge_passes,
        args.systems,
        args.airlock_variants,
        models,
        args.subset,
        args.seed,
        args.baseline_judge_passes,
    )
    roles = ", ".join(f"{r} {short_model(m)}" for r, m in est["models"].items())
    bjp = judge_passes if args.baseline_judge_passes is None else args.baseline_judge_passes
    print_estimate(
        f"Cloud estimate: {est['cases']} cases, Airlock {args.passes} passes x "
        f"{args.airlock_variants} variant(s) ({judge_passes} scored), baselines "
        f"{' '.join(args.systems) or '-'} ({bjp} scored pass(es) each); roles: {roles}",
        est,
    )
    if args.variants:
        print()
        print_variants(models, args.seed)


if __name__ == "__main__":
    main()
