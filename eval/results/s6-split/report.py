"""S6 report: B1 vs s6-placeholder vs s6-surrogate on the test split.

    uv run python eval/results/s6-split/report.py > eval/results/s6-split/REPORT.md

Leak, identity leak, benign masking, over-redaction, blocks and detect latency: all 171 test
cases (one harness pass each). Linkable disclosure, utility ratio and distortion: the stratified
90-case subset (`test90.json`), from `attack/` and `utility/` in the `*-test90` directories.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
EVAL = HERE.parents[1]
sys.path.insert(0, str(EVAL))
import attack  # noqa: E402
import reframe  # noqa: E402
import scoring  # noqa: E402

RUNS = [
    ("B1 (GLiNER ensemble, main)", "ensemble-B1-gliner", "s6-B1-test90"),
    ("s6-placeholder", "s6-placeholder", "s6-placeholder-test90"),
    ("s6-surrogate", "s6-surrogate", "s6-surrogate-test90"),
]


def pct(v: float | None) -> str:
    return "n/a" if v is None else f"{100 * v:.1f}%"


def percentile(values: list[float], q: float) -> float | None:
    return scoring._percentile(values, q)


def full_metrics(run: str, ids: set[str]) -> dict:
    d = EVAL / "results" / run
    cases = {c["id"]: c for c in reframe.read_jsonl(d / "cases_snapshot.jsonl")}
    records = [json.loads(x)["record"] for x in (d / "pass_01.jsonl").open(encoding="utf-8")]
    records = [r for r in records if r["case_id"] in ids]
    scored = [scoring.score_case(cases[r["case_id"]], r) for r in records]
    out = {"all": scoring.compute_metrics(scored)}
    for lang in ("ko", "en"):
        out[lang] = scoring.compute_metrics([s for s in scored if s["lang"] == lang])
    ident = reframe.identity_leak_pass(cases, records)
    out["identity"] = ident
    detect = [
        (r.get("audit") or {}).get("timings_ms", {}).get("detect")
        for r in records
        if (r.get("audit") or {}).get("kind") == "chat"
    ]
    detect = [x for x in detect if x is not None]
    out["detect_p50"], out["detect_p95"] = percentile(detect, 0.5), percentile(detect, 0.95)
    tokens = 0
    for r in records:
        for o in (r.get("audit") or {}).get("outbound") or []:
            if o.get("destination") == "upstream":
                tokens += attack.estimate_tokens(json.dumps(o["payload"], ensure_ascii=False))
        tokens += attack.estimate_tokens(r.get("answer") or "")
    out["upstream_tokens_est"] = tokens
    return out


def sub_metrics(run: str) -> dict:
    d = EVAL / "results" / run
    atk = reframe.load_json(d / "attack" / "summary.json") or {}
    util = reframe.load_json(d / "utility" / "summary.json") or {}

    def get(src: dict, key: str, lang: str | None = None):
        block = (src.get("by_lang") or {}).get(lang, {}) if lang else src.get("overall") or {}
        stat = block.get(key) or {}
        return stat.get("mean") if stat.get("n") else None

    out = {}
    for lang in (None, "ko", "en"):
        out[lang or "all"] = {
            "linkable": get(atk, "linkable_disclosure_rate", lang),
            "identity_recovered": get(atk, "attack_identity_recovery_rate", lang),
            "situation": get(atk, "situation_inference_rate", lang),
            "utility_ratio": get(util, "utility_ratio_vs_reference", lang),
            "distortion": get(util, "distortion_rate", lang),
            "reference_distortion": get(util, "reference_distortion_rate", lang),
        }
    usage = {"prompt_tokens": 0, "completion_tokens": 0}
    for cfg in (d / "attack" / "config.json", d / "utility" / "config.json"):
        data = reframe.load_json(cfg) or {}
        # A copied attack config (B1) carries the usage of the original 243-case attack: only the
        # situation backfill made for this subset counts.
        own = [] if (d / "attack" / "config.json") == cfg and data.get("situation_backfill") else [
            data.get("usage") or {}
        ]  # fmt: skip
        for part in own + [
            b.get("usage") or {} for b in data.get("situation_backfill") or []
        ]:
            for k in usage:
                usage[k] += int(part.get(k) or 0)
        for run_usage in data.get("runs") or []:
            for part in (run_usage.get("usage") or {}).values():
                for k in usage:
                    usage[k] += int(part.get(k) or 0)
    out["usage"] = usage
    return out


def main() -> None:
    split = json.loads((EVAL / "results/ensemble-split.json").read_text())
    test = set(split["test"])
    sub = json.loads((HERE / "test90.json").read_text())
    full = {name: full_metrics(run, test) for name, run, _ in RUNS}
    subs = {name: sub_metrics(run90) for name, _, run90 in RUNS}
    names = [n for n, _, _ in RUNS]
    print("# S6 detector round two: test split\n")
    print(
        f"Test split of `ensemble-split.json` (seed {split['seed']}): {len(test)} cases, one pass "
        "each; rules were tuned on the 72 dev cases only. Attack and utility columns use a "
        f"stratified {sub['n']}-case subset of the test split (`test90.json`, seed {sub['seed']}) "
        "to stay under the Token Factory budget. Attacker, graders and utility judge: Nemotron 3 "
        "Ultra (the S8 calibration kept Ultra for every role).\n"
    )
    rows = [
        ("Leak rate (171)", lambda n: pct(full[n]["all"]["leak_rate"])),
        ("Identity leak (171)", lambda n: pct(full[n]["identity"]["identity_leak_rate"])),
        ("Quasi re-id, scanner (171)", lambda n: pct(full[n]["all"]["quasi_reid_rate"])),
        ("**Linkable disclosure** (90)", lambda n: pct(subs[n]["all"]["linkable"])),
        ("Identity recovered, attacker (90)", lambda n: pct(subs[n]["all"]["identity_recovered"])),
        ("Situation inferred (90)", lambda n: pct(subs[n]["all"]["situation"])),
        ("Utility ratio (90)", lambda n: f"{subs[n]['all']['utility_ratio']:.2f}"
         if subs[n]["all"]["utility_ratio"] is not None else "n/a"),  # fmt: skip
        ("Distortion (90)", lambda n: pct(subs[n]["all"]["distortion"])),
        ("Distortion of the reference answers (90)",
         lambda n: pct(subs[n]["all"]["reference_distortion"])),  # fmt: skip
        ("Benign masked (171)", lambda n: pct(full[n]["all"]["benign_false_positive_rate"])),
        ("Over-block benign (171)", lambda n: pct(full[n]["all"]["over_block_benign"])),
        ("Over-redaction (171)", lambda n: pct(full[n]["all"]["over_redaction_rate"])),
        ("Block rate (171)", lambda n: pct(full[n]["all"]["block_rate"])),
        ("Leak ko / en (171)", lambda n: f"{pct(full[n]['ko']['leak_rate'])} / "
         f"{pct(full[n]['en']['leak_rate'])}"),  # fmt: skip
        ("Identity leak ko / en (171)", lambda n: f"{pct(full[n]['identity']['by_lang']['ko'])} / "
         f"{pct(full[n]['identity']['by_lang']['en'])}"),  # fmt: skip
        ("Linkable ko / en (90)", lambda n: f"{pct(subs[n]['ko']['linkable'])} / "
         f"{pct(subs[n]['en']['linkable'])}"),  # fmt: skip
        ("Utility ratio ko / en (90)", lambda n: " / ".join(
            "n/a" if subs[n][lang]["utility_ratio"] is None else f"{subs[n][lang]['utility_ratio']:.2f}"
            for lang in ("ko", "en"))),  # fmt: skip
        ("Distortion ko / en (90)", lambda n: f"{pct(subs[n]['ko']['distortion'])} / "
         f"{pct(subs[n]['en']['distortion'])}"),  # fmt: skip
        ("Detect p50 / p95, chat (ms)", lambda n: f"{full[n]['detect_p50']:.0f} / "
         f"{full[n]['detect_p95']:.0f}"),  # fmt: skip
        ("Local overhead p50 / p95 (ms)", lambda n: f"{full[n]['all']['overhead_ms_p50']:.0f} / "
         f"{full[n]['all']['overhead_ms_p95']:.0f}"),  # fmt: skip
    ]
    print("| Metric | " + " | ".join(names) + " |")
    print("|---|" + "---:|" * len(names))
    for label, fn in rows:
        print(f"| {label} | " + " | ".join(fn(n) for n in names) + " |")
    print("\n## Token Factory usage\n")
    print("| Run | Attack + utility for this report (measured) | Harness upstream (estimated) |")
    print("|---|---:|---:|")
    for n in names:
        u = subs[n]["usage"]
        est = "not re-run" if n.startswith("B1") else f"~{full[n]['upstream_tokens_est']:,}"
        print(f"| {n} | {u['prompt_tokens'] + u['completion_tokens']:,} | {est} |")


if __name__ == "__main__":
    main()
