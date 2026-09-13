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
VERIFY_SHARE = 0.25  # share of judged answers the verifier re-checks (flagged distortions)


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


def estimate(passes: int, judge_passes: int, systems: list[str], variants: int) -> dict:
    tok = attack.estimate_tokens
    cases = load_cases()
    chat = [c for c in cases if c["task"] == "chat"]
    search = [c for c in cases if c["task"] == "search"]
    n_systems = len(systems) + variants
    out: dict[str, dict[str, int]] = {}

    chat_prompt = sum(tok(case_text(c)) + AIRLOCK_NOTE_TOKENS for c in chat)
    runs = passes * variants
    out["airlock runs (upstream answers)"] = {
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
    out["attack + situation graders"] = {
        "calls": passes * n_systems * (len(cases) + graders),
        "prompt": passes * n_systems * (attacker_prompt + grader_prompt),
        "completion_typical": passes
        * n_systems
        * (len(cases) * ATTACK_COMPLETION_TYPICAL + graders * 60),
        "completion_max": passes
        * n_systems
        * (len(cases) * attack.MAX_OUTPUT_TOKENS + graders * attack.GRADER_MAX_TOKENS),
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
    out["utility (references, baseline answers, judge, verifier)"] = {
        "calls": refs + baseline_answers + judges + verifies,
        "prompt": refs * (chat_prompt // max(len(chat), 1))
        + judge_passes * len(systems) * chat_prompt
        + judge_passes * n_systems * (judge_prompt + 2 * len(chat) * utility.ANSWER_TOKENS_TYPICAL)
        + verifies * 1500,
        "completion_typical": (refs + baseline_answers) * utility.ANSWER_TOKENS_TYPICAL
        + judges * 250
        + verifies * 80,
        "completion_max": (refs + baseline_answers) * utility.ANSWER_MAX_TOKENS
        + judges * utility.JUDGE_MAX_TOKENS
        + verifies * utility.VERIFY_MAX_TOKENS,
        "reference_answers_cached": ref_cached,
    }
    total = {
        k: sum(v.get(k, 0) for v in out.values())
        for k in ("calls", "prompt", "completion_typical", "completion_max")
    }
    return {"parts": out, "total": total}


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--passes", type=int, default=3)
    ap.add_argument("--judge-passes", type=int, default=None, help="default: --passes")
    ap.add_argument("--systems", nargs="*", default=["raw", "regex", "presidio_ko", "gliner_pii"])
    ap.add_argument("--airlock-variants", type=int, default=1)
    args = ap.parse_args(argv)
    est = estimate(
        args.passes, args.judge_passes or args.passes, args.systems, args.airlock_variants
    )
    print(
        f"Cloud estimate: {args.passes} passes, baselines {' '.join(args.systems) or '-'}, "
        f"{args.airlock_variants} Airlock variant(s), model {attack.DEFAULT_MODEL}"
    )
    for name, part in est["parts"].items():
        extra = ""
        if "tavily_searches" in part:
            extra = f", {part['tavily_searches']} Tavily searches"
        if "reference_answers_cached" in part:
            extra = f", {part['reference_answers_cached']} reference answers already cached"
        print(
            f"  {name}: {part['calls']:,} calls, ~{part['prompt']:,} prompt tokens, "
            f"~{part['completion_typical']:,} completion typical (<= {part['completion_max']:,})"
            f"{extra}"
        )
    t = est["total"]
    print(
        f"  TOTAL: {t['calls']:,} calls, ~{t['prompt']:,} prompt + ~{t['completion_typical']:,} "
        f"completion tokens typical (completion <= {t['completion_max']:,})"
    )


if __name__ == "__main__":
    main()
