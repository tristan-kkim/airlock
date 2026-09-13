# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx>=0.27"]
# ///
"""Cloud call and token estimate for eval/final_protocol.sh, printed before anything runs.

    uv run eval/protocol_estimate.py --passes 3 --systems raw regex presidio_ko gliner_pii \
        --airlock-variants 2

Before the runs exist the outbound payloads are unknown, so every payload is estimated from the
raw case text (an upper-leaning bound: masking only shortens prompts). Token counts use the same
heuristic as eval/attack.py (about 4 ASCII characters or 1 non-ASCII character per token).
Dollars use Token Factory list prices (eval/attack.py MODEL_PRICES) for the model of each part:
answers come from the upstream model, the four scoring roles from their role models
(AIRLOCK_ATTACK_MODEL, AIRLOCK_GRADER_MODEL, AIRLOCK_UTILITY_MODEL,
AIRLOCK_DISTORTION_CONFIRM_MODEL, or the defaults chosen in eval/results/JUDGE_CALIBRATION.md).
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
    "airlock runs: upstream answers": None,
    "attacker": "attack",
    "intent + situation graders": "grader",
    "reference + baseline answers": None,
    "utility judge": "utility",
    "distortion confirmation": "distortion_confirm",
}


def estimate(
    passes: int,
    judge_passes: int,
    systems: list[str],
    variants: int,
    models: dict[str, str] | None = None,
    case_share: float = 1.0,
) -> dict:
    """Calls and tokens per part, priced with each part's model.

    `models` maps roles to models (default: attack.role_model). Answers always come from the
    upstream model (Ultra): they are what the systems are measured on, not a judge. `case_share`
    scales every per-case count, for a stratified subset of the cases.
    """
    models = {role: (models or {}).get(role) or attack.role_model(role) for role in attack.ROLE_ENV}
    tok = attack.estimate_tokens
    cases = load_cases()
    chat = [c for c in cases if c["task"] == "chat"]
    search = [c for c in cases if c["task"] == "search"]
    n_systems = len(systems) + variants
    out: dict[str, dict] = {}

    chat_prompt = sum(tok(case_text(c)) + AIRLOCK_NOTE_TOKENS for c in chat)
    runs = passes * variants
    out["airlock runs: upstream answers"] = {
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
    scored = judge_passes * n_systems
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
    refs = len(chat) - ref_cached
    baseline_answers = judge_passes * len(systems) * len(chat)
    judges = judge_passes * n_systems * len(chat)
    verifies = int(judges * 2 * VERIFY_SHARE)
    judge_prompt = sum(
        tok(utility.JUDGE_SYSTEM) + tok(utility.render_request(c["messages"])) for c in chat
    )
    out["reference + baseline answers"] = {
        "calls": refs + baseline_answers,
        "prompt": refs * (chat_prompt // max(len(chat), 1))
        + judge_passes * len(systems) * chat_prompt,
        "completion_typical": (refs + baseline_answers) * utility.ANSWER_TOKENS_TYPICAL,
        "completion_max": (refs + baseline_answers) * utility.ANSWER_MAX_TOKENS,
        "reference_answers_cached": ref_cached,
    }
    out["utility judge"] = {
        "calls": judges,
        "prompt": judge_passes
        * n_systems
        * (judge_prompt + 2 * len(chat) * utility.ANSWER_TOKENS_TYPICAL),
        "completion_typical": judges * JUDGE_COMPLETION_TYPICAL,
        "completion_max": judges * utility.JUDGE_MAX_TOKENS,
    }
    out["distortion confirmation"] = {
        "calls": verifies,
        "prompt": verifies * VERIFY_PROMPT_TYPICAL,
        "completion_typical": verifies * VERIFY_COMPLETION_TYPICAL,
        "completion_max": verifies * utility.VERIFY_MAX_TOKENS,
    }
    counts = ("calls", "prompt", "completion_typical", "completion_max")
    for name, part in out.items():
        role = PART_ROLES[name]
        for k in (*counts, "tavily_searches"):
            if k in part:
                part[k] = round(part[k] * case_share)
        part["model"] = models[role] if role else attack.DEFAULT_MODEL
        part["usd"] = attack.usage_cost(
            part["model"],
            {"prompt_tokens": part["prompt"], "completion_tokens": part["completion_typical"]},
        )
        part["usd_all_ultra"] = attack.usage_cost(
            attack.ULTRA,
            {"prompt_tokens": part["prompt"], "completion_tokens": part["completion_typical"]},
        )
    total = {k: sum(v.get(k, 0) for v in out.values()) for k in counts}
    total["usd"] = sum(v["usd"] or 0.0 for v in out.values())
    total["usd_all_ultra"] = sum(v["usd_all_ultra"] or 0.0 for v in out.values())
    return {"parts": out, "total": total, "models": models}


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
        f"completion tokens typical = ~{t['prompt'] + t['completion_typical']:,} tokens, "
        f"~${t['usd']:.2f} at list prices (all roles on Ultra: ~${t['usd_all_ultra']:.2f})"
    )


def short_model(model: str) -> str:
    return model.split("/")[-1]


BASELINES = ["raw", "regex", "presidio_ko", "gliner_pii"]


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--passes", type=int, default=3)
    ap.add_argument("--judge-passes", type=int, default=None, help="default: --passes")
    ap.add_argument("--systems", nargs="*", default=BASELINES)
    ap.add_argument("--airlock-variants", type=int, default=1)
    ap.add_argument("--attack-model", default=None)
    ap.add_argument("--grader-model", default=None)
    ap.add_argument("--judge-model", default=None)
    ap.add_argument("--confirm-model", default=None)
    ap.add_argument(
        "--projections",
        action="store_true",
        help="also print the reference projections: 5 systems x 3 passes, 2 passes, and a "
        "stratified 120-case subset",
    )
    args = ap.parse_args(argv)
    models = {
        "attack": args.attack_model,
        "grader": args.grader_model,
        "utility": args.judge_model,
        "distortion_confirm": args.confirm_model,
    }
    est = estimate(
        args.passes,
        args.judge_passes or args.passes,
        args.systems,
        args.airlock_variants,
        models,
    )
    roles = ", ".join(f"{r} {short_model(m)}" for r, m in est["models"].items())
    print_estimate(
        f"Cloud estimate: {args.passes} passes, baselines {' '.join(args.systems) or '-'}, "
        f"{args.airlock_variants} Airlock variant(s); roles: {roles}",
        est,
    )
    if args.projections:
        n_cases = len(load_cases())
        for title, passes, share in (
            ("Projection: 5 systems (4 baselines + 1 Airlock variant) x 3 passes", 3, 1.0),
            ("Projection, reduced: 5 systems x 2 passes", 2, 1.0),
            (f"Projection, reduced: 5 systems x 3 passes on a stratified 120 of {n_cases} cases",
             3, 120 / n_cases),
        ):  # fmt: skip
            print()
            print_estimate(title, estimate(passes, passes, BASELINES, 1, models, share))


if __name__ == "__main__":
    main()
