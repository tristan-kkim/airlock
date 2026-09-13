# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""A/B report for the GLiNER ensemble on a seeded dev/test split of the eval cases.

    uv run eval/ensemble_split.py --write-split eval/results/ensemble-split.json   # once
    uv run eval/ensemble_split.py eval/results/ensemble-A-head eval/results/ensemble-B-gliner

Thresholds and policy were chosen by looking only at the dev cases (30%, stratified by category
and language). The test cases (70%) are the numbers to quote. Rates come from the stored
`pass_01.jsonl` scores via `scoring.compute_metrics`, so they match `run.py --rescore`.
Latency percentiles for the ensemble come from the audit `meta.detector` counters.
"""

from __future__ import annotations

import argparse
import collections
import glob
import json
import random
import sys
from pathlib import Path
from typing import Any

EVAL_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(EVAL_DIR))
import scoring  # noqa: E402

SEED = 20260914
DEV_FRACTION = 0.3

ROWS = [
    ("leak_rate", "Leak rate"),
    ("canary_leak_rate", "Canary leak"),
    ("quasi_reid_rate", "Quasi re-id"),
    ("benign_false_positive_rate", "Benign masked"),
    ("over_redaction_rate", "Over-redaction"),
    ("block_rate", "Block rate"),
    ("over_block_benign", "Over-block benign"),
]


def write_split(path: Path) -> None:
    cases = [
        json.loads(line)
        for f in sorted(glob.glob(str(EVAL_DIR / "cases/*.jsonl")))
        for line in Path(f).read_text(encoding="utf-8").splitlines()
    ]
    rng = random.Random(SEED)
    strata: dict[tuple[str, str], list[str]] = collections.defaultdict(list)
    for c in cases:
        strata[(c["category"], c["lang"])].append(c["id"])
    dev: list[str] = []
    for key in sorted(strata):
        ids = sorted(strata[key])
        rng.shuffle(ids)
        dev += ids[: round(len(ids) * DEV_FRACTION)]
    dev_set = set(dev)
    split = {
        "seed": SEED,
        "method": "stratified by (category, lang), round(30%) of each stratum to dev",
        "dev": sorted(dev),
        "test": sorted(c["id"] for c in cases if c["id"] not in dev_set),
    }
    path.write_text(json.dumps(split, indent=1) + "\n", encoding="utf-8")
    print(f"dev {len(split['dev'])}, test {len(split['test'])} -> {path}")


def load(run: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in (run / "pass_01.jsonl").open(encoding="utf-8")]


def pct(value: float | None) -> str:
    return "n/a" if value is None else f"{100 * value:.1f}%"


def percentile(values: list[float], q: float) -> float | None:
    return scoring._percentile(values, q)


def subset_metrics(rows: list[dict[str, Any]], ids: set[str] | None) -> dict[str, Any]:
    scored = [r["score"] for r in rows if ids is None or r["score"]["case_id"] in ids]
    out = scoring.compute_metrics(scored)
    for lang in ("ko", "en"):
        out[f"leak_{lang}"] = scoring.compute_metrics(
            [s for s in scored if s["lang"] == lang]
        )["leak_rate"]
        out[f"benign_{lang}"] = scoring.compute_metrics(
            [s for s in scored if s["lang"] == lang]
        )["benign_false_positive_rate"]
    return out


def detector_latency(rows: list[dict[str, Any]], ids: set[str] | None) -> dict[str, Any]:
    gl, adj, adj_nonzero, calls, cands = [], [], [], 0, 0
    yes = no = 0
    for r in rows:
        if ids is not None and r["score"]["case_id"] not in ids:
            continue
        det = ((r["record"].get("audit") or {}).get("meta") or {}).get("detector") or {}
        if "gliner_ms" not in det:
            continue
        gl.append(det["gliner_ms"])
        adj.append(det["adjudication_ms"])
        if det["adjudication_calls"]:
            adj_nonzero.append(det["adjudication_ms"])
        calls += det["adjudication_calls"]
        cands += det["gliner_candidates"]
        yes += det["adjudicated_yes"]
        no += det["adjudicated_no"]
    return {
        "requests": len(gl),
        "gliner_ms_p50": percentile(gl, 0.5),
        "gliner_ms_p95": percentile(gl, 0.95),
        "adjudication_ms_p50_all": percentile(adj, 0.5),
        "adjudication_ms_p95_all": percentile(adj, 0.95),
        "adjudication_ms_p50_when_called": percentile(adj_nonzero, 0.5),
        "adjudication_ms_p95_when_called": percentile(adj_nonzero, 0.95),
        "requests_with_adjudication": len(adj_nonzero),
        "adjudication_calls": calls,
        "candidates": cands,
        "adjudicated_yes": yes,
        "adjudicated_no": no,
    }


def report(runs: list[Path], split: dict[str, Any]) -> str:
    subsets = {"test (70%)": set(split["test"]), "dev (30%)": set(split["dev"]), "all": None}
    data = {run: load(run) for run in runs}
    lines = [
        "# GLiNER ensemble A/B on a dev/test split",
        "",
        f"Split: seed {split['seed']}, {split['method']}; {len(split['dev'])} dev and "
        f"{len(split['test'])} test cases (`ensemble-split.json`). Thresholds and policy were "
        "chosen on dev only; quote the test column. One pass per config, so no standard deviation.",
        "",
    ]
    for name, ids in subsets.items():
        lines += [f"## {name}", "", "| Metric | " + " | ".join(r.name for r in runs) + " |",
                  "|---|" + "---:|" * len(runs)]  # fmt: skip
        metrics = {run: subset_metrics(data[run], ids) for run in runs}
        extra = [("leak_ko", "Leak ko"), ("leak_en", "Leak en"), ("benign_ko", "Benign masked ko"),
                 ("benign_en", "Benign masked en")]  # fmt: skip
        for key, label in ROWS + extra:
            lines.append(f"| {label} | " + " | ".join(pct(metrics[r][key]) for r in runs) + " |")
        for key, label in (("overhead_ms_p50", "Local overhead p50"),
                           ("overhead_ms_p95", "Local overhead p95")):  # fmt: skip
            cells = [
                "n/a" if metrics[r][key] is None else f"{metrics[r][key]:.0f} ms" for r in runs
            ]
            lines.append(f"| {label} | " + " | ".join(cells) + " |")
        lines.append("| Cases / errors | " + " | ".join(
            f"{metrics[r]['cases']} / {metrics[r]['errors']}" for r in runs) + " |")  # fmt: skip
        lines.append("")
    for run in runs:
        lat = detector_latency(data[run], None)
        if lat["requests"]:
            lines += [f"## Ensemble counters: {run.name} (all chat requests)", "", "```",
                      json.dumps(lat, indent=1), "```", ""]  # fmt: skip
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("runs", nargs="*", type=Path)
    ap.add_argument("--split", type=Path, default=EVAL_DIR / "results/ensemble-split.json")
    ap.add_argument("--write-split", type=Path, default=None)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    if args.write_split:
        write_split(args.write_split)
        return 0
    text = report(args.runs, json.loads(args.split.read_text(encoding="utf-8")))
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
