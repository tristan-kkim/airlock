"""S9 dev-split table: main vs feat/distortion, one pass each, 72 dev cases.

    uv run python eval/results/s9-distortion/report.py

Scanner metrics come from `pass_*.jsonl` (all passes of the run), attack and utility metrics
from `attack/` and `utility/` (one pass). Runs without attack or utility show n/a.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
EVAL = HERE.parents[1]
sys.path.insert(0, str(EVAL))
import reframe  # noqa: E402
import scoring  # noqa: E402

RUNS = [
    ("main 2e92453", "dev-main"),
    ("branch 4d3bc0a (first fixes)", "dev-branch-4d3bc0a"),
    ("branch 91d21f3", "dev-branch"),
]
STUB_RUNS = [
    ("main 2e92453, stub upstream", "stub-main"),
    ("branch 91d21f3, stub upstream", "stub-branch"),
]


def pct(v: float | None) -> str:
    return "n/a" if v is None else f"{100 * v:.1f}%"


def scanner(run: str) -> list[dict]:
    """Per-pass scanner metrics plus identity leak."""
    d = HERE / run
    cases = {c["id"]: c for c in reframe.read_jsonl(d / "cases_snapshot.jsonl")}
    out = []
    for path in sorted(d.glob("pass_*.jsonl")):
        records = [json.loads(x)["record"] for x in path.open(encoding="utf-8")]
        scored = [scoring.score_case(cases[r["case_id"]], r) for r in records]
        m = scoring.compute_metrics(scored)
        m["identity_leak_rate"] = reframe.identity_leak_pass(cases, records)["identity_leak_rate"]
        out.append(m)
    return out


def mean(values: list[float | None]) -> float | None:
    vals = [v for v in values if v is not None]
    return sum(vals) / len(vals) if vals else None


def cloud(run: str) -> dict:
    d = HERE / run
    atk = reframe.load_json(d / "attack" / "summary.json") or {}
    util = reframe.load_json(d / "utility" / "summary.json") or {}

    def get(src: dict, key: str):
        stat = (src.get("overall") or {}).get(key) or {}
        return stat.get("mean") if stat.get("n") else None

    usage = 0
    for cfg in (d / "attack" / "config.json", d / "utility" / "config.json"):
        data = reframe.load_json(cfg) or {}
        usage += sum(int(v or 0) for v in (data.get("usage") or {}).values())
        for run_usage in data.get("runs") or []:
            for part in (run_usage.get("usage") or {}).values():
                usage += int(part.get("prompt_tokens") or 0) + int(
                    part.get("completion_tokens") or 0
                )
    return {
        "linkable": get(atk, "linkable_disclosure_rate"),
        "identity_recovered": get(atk, "attack_identity_recovery_rate"),
        "situation": get(atk, "situation_inference_rate"),
        "utility_ratio": get(util, "utility_ratio_vs_reference"),
        "distortion": get(util, "distortion_rate"),
        "reference_distortion": get(util, "reference_distortion_rate"),
        "usefulness": get(util, "utility_mean"),
        "reference_usefulness": get(util, "reference_utility_mean"),
        "judged": get(util, "judged"),
        "tokens": usage,
    }


def table(runs: list[tuple[str, str]], with_cloud: bool) -> None:
    runs = [(n, r) for n, r in runs if (HERE / r / "pass_01.jsonl").is_file()]
    scan = {r: scanner(r) for _, r in runs}
    cl = {r: cloud(r) for _, r in runs} if with_cloud else {}

    def s(key: str):
        return lambda r: pct(mean([m.get(key) for m in scan[r]]))

    rows = []
    if with_cloud:
        rows += [
            ("**Linkable disclosure** (attacker)", lambda r: pct(cl[r]["linkable"])),
            ("Identity recovered (attacker)", lambda r: pct(cl[r]["identity_recovered"])),
            ("Situation inferred (attacker)", lambda r: pct(cl[r]["situation"])),
            ("**Distortion**", lambda r: pct(cl[r]["distortion"])),
            ("Distortion of the reference answers", lambda r: pct(cl[r]["reference_distortion"])),
            (
                "Usefulness, system / reference (1-5)",
                lambda r: (
                    "n/a"
                    if cl[r]["usefulness"] is None
                    else f"{cl[r]['usefulness']:.2f} / {cl[r]['reference_usefulness']:.2f}"
                ),
            ),
            (
                "Chat answers judged",
                lambda r: "n/a" if cl[r]["judged"] is None else f"{cl[r]['judged']:.0f}",
            ),
            (
                "**Utility ratio**",
                lambda r: (
                    "n/a" if cl[r]["utility_ratio"] is None else f"{cl[r]['utility_ratio']:.2f}"
                ),
            ),
        ]
    rows += [
        ("**Identity leak** (scanner)", s("identity_leak_rate")),
        ("Leak rate", s("leak_rate")),
        ("Quasi re-id (scanner)", s("quasi_reid_rate")),
        ("**Over-redaction**", s("over_redaction_rate")),
        ("Benign masked", s("benign_false_positive_rate")),
        ("Block rate", s("block_rate")),
        ("Passes", lambda r: str(len(scan[r]))),
    ]
    if with_cloud:
        rows.append(("Attack + utility tokens (measured)", lambda r: f"{cl[r]['tokens']:,}"))
    print("| Metric | " + " | ".join(n for n, _ in runs) + " |")
    print("|---|" + "---:|" * len(runs))
    for label, fn in rows:
        print(f"| {label} | " + " | ".join(fn(r) for _, r in runs) + " |")


def main() -> None:
    print("### Dev split, Token Factory upstream, attacker and judge (1 pass)\n")
    table(RUNS, with_cloud=True)
    if any((HERE / r / "pass_01.jsonl").is_file() for _, r in STUB_RUNS):
        print("\n### Dev split, stub upstream (scanner metrics only, no cloud calls)\n")
        table(STUB_RUNS, with_cloud=False)


if __name__ == "__main__":
    main()
