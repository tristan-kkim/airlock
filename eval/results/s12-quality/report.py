"""S12 dev-split table: main vs feat/s12-quality on the 72 dev cases, with ko/en splits.

    uv run python eval/results/s12-quality/report.py

* Scanner metrics: `stub-*` runs, 2 passes each with a server reset before every pass and a stub
  upstream (no cloud calls). Mean over the passes.
* Benign Korean searches: `ben-ko-search-branch`, the three `ben-ko` search cases of the whole
  eval set (two are in the test split), local scan only, per pass.
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

CONFIGS = [("main d97a815", "main"), ("branch", "branch")]
LANGS = (None, "ko", "en")


def pct(v: float | None) -> str:
    return "n/a" if v is None else f"{100 * v:.1f}%"


def mean(values: list[float | None]) -> float | None:
    vals = [v for v in values if v is not None]
    return sum(vals) / len(vals) if vals else None


def scored_passes(run: Path) -> tuple[dict, list[list[dict]], list[list[dict]]]:
    cases = {c["id"]: c for c in reframe.read_jsonl(run / "cases_snapshot.jsonl")}
    records, scored = [], []
    for path in sorted(run.glob("pass_*.jsonl")):
        recs = [json.loads(x)["record"] for x in path.open(encoding="utf-8")]
        records.append(recs)
        scored.append([scoring.score_case(cases[r["case_id"]], r) for r in recs])
    return cases, records, scored


def scanner(run: Path, lang: str | None) -> dict[str, float | None]:
    cases, records, scored = scored_passes(run)
    rows = []
    for recs, sc in zip(records, scored, strict=True):
        sc = [s for s in sc if lang is None or s["lang"] == lang]
        m = scoring.compute_metrics(sc)
        leak = reframe.identity_leak_pass(cases, recs)
        m["identity_leak_rate"] = leak["by_lang"][lang] if lang else leak["identity_leak_rate"]
        benign = [s for s in sc if s["category"] == "benign" and s["status"] != "error"]
        m["benign_masked_n"] = sum(1 for s in benign if s["masking_detections"] > 0)
        m["benign_blocked_n"] = sum(1 for s in benign if s["blocked"])
        m["benign_n"] = len(benign)
        rows.append(m)
    keys = ("identity_leak_rate", "quasi_reid_rate", "over_redaction_rate",
            "benign_false_positive_rate", "over_block_benign", "block_rate", "leak_rate",
            "benign_masked_n", "benign_blocked_n", "benign_n")  # fmt: skip
    out = {k: mean([r.get(k) for r in rows]) for k in keys}
    out["passes"] = len(rows)
    return out


def split(fn, runs: list[Path], key: str, fmt=pct) -> list[str]:
    cells = []
    for run in runs:
        vals = [fn(run, lang).get(key) for lang in LANGS]
        cells.append(" / ".join(fmt(v) for v in vals))
    return cells


def main() -> None:
    stub = [HERE / f"stub-{c}" for _, c in CONFIGS]
    names = [n for n, _ in CONFIGS]
    print("### Dev split (72 cases): main vs branch, all / ko / en\n")
    print("| Metric | " + " | ".join(names) + " |")
    print("|---|" + "---:|" * len(names))
    rows = [
        ("**Identity leak** (scanner, 2 passes)", split(scanner, stub, "identity_leak_rate")),
        ("Leak rate, cases (scanner)", split(scanner, stub, "leak_rate")),
        ("Quasi re-id (scanner)", split(scanner, stub, "quasi_reid_rate")),
        ("**Over-redaction** (scanner, 2 passes)", split(scanner, stub, "over_redaction_rate")),
        ("Benign masked", split(scanner, stub, "benign_false_positive_rate")),
        ("Benign blocked", split(scanner, stub, "over_block_benign")),
        ("Block rate, all cases", split(scanner, stub, "block_rate")),
    ]
    for label, cells in rows:
        print(f"| {label} | " + " | ".join(cells) + " |")
    print()
    for name, run in zip(names, stub, strict=True):
        if any(run.glob("pass_*.jsonl")):
            s = scanner(run, None)
            print(
                f"- {name}: scanner passes {s['passes']}, benign masked "
                f"{s['benign_masked_n']:.1f} / blocked {s['benign_blocked_n']:.1f} of "
                f"{s['benign_n']:.0f} per pass"
            )
    benign_searches()
    differing()


def differing() -> None:
    """The dev cases whose leak flags differed between the two dev runs, rerun 4 passes each on
    both checkouts against the same llama-server (`diff-main`, `diff-branch`)."""
    runs = [(n, HERE / f"diff-{c}") for n, c in CONFIGS if (HERE / f"diff-{c}").is_dir()]
    if not runs:
        return
    print("\n### The dev cases that differed, rerun 4 passes on each checkout\n")
    print("| Case | " + " | ".join(f"{n}: leaks / blocks / Nano proposals" for n, _ in runs) + " |")
    print("|---|" + "---|" * len(runs))
    per_run = {name: scored_passes(run) for name, run in runs}
    ids = sorted(per_run[runs[0][0]][0])
    for cid in ids:
        cells = []
        for name, _ in runs:
            _, records, scored = per_run[name]
            leaks = blocks = 0
            proposals = []
            for recs, sc in zip(records, scored, strict=True):
                s = next(x for x in sc if x["case_id"] == cid)
                r = next(x for x in recs if x["case_id"] == cid)
                leaks += bool(s["identity_leaked"])
                blocks += bool(s["blocked"])
                meta = (r.get("audit") or {}).get("meta") or {}
                proposals.append(str((meta.get("detector") or {}).get("llm_proposed", 0)))
            cells.append(f"{leaks}/{len(records)} / {blocks} / {' '.join(proposals)}")
        print(f"| `{cid}` | " + " | ".join(cells) + " |")


def benign_searches() -> None:
    run = HERE / "ben-ko-search-branch"
    if not run.is_dir():
        return
    print("\n### Benign Korean searches on the branch, local scan only (per pass)\n")
    print("| Case | pass | sent | masking detections | outbound query |")
    print("|---|---|---|---:|---|")
    _, records, scored = scored_passes(run)
    for n, (recs, sc) in enumerate(zip(records, scored, strict=True), start=1):
        for rec, s in zip(recs, sc, strict=True):
            queries = [
                o.get("payload", {}).get("query")
                for o in (rec.get("audit") or {}).get("outbound") or []
            ]
            print(
                f"| `{s['case_id']}` | {n} | {'blocked' if s['blocked'] else 'sent'} | "
                f"{s['masking_detections']} | {', '.join(q for q in queries if q)} |"
            )


if __name__ == "__main__":
    main()
