"""S10 dev-split table: main vs feat/s10-hardening on the 72 dev cases, with ko/en splits.

    uv run python eval/results/s10-hardening/report.py

* Local scanner metrics: `stub-*` runs, 2 passes each with a server reset before every pass and
  a stub upstream (no cloud calls). Mean over the passes.
* Attacker and utility metrics: `dev-*` runs, 1 pass each with Nemotron 3 Ultra as upstream,
  attacker, graders, judge and distortion verifier.
* Diagnostic: the 9 cases linkable in every pass of the final measurement, local scan only
  (`diag-*`), never attacked.
* Named Korean cases: the benign and adversarial Korean cases FINAL.md names as blocked, masked
  or leaking (`named-ko-*`), local scan only.
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

CONFIGS = [("main 4236df9", "main"), ("branch", "branch")]
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


def cloud(run: Path, lang: str | None) -> dict[str, float | None]:
    atk = reframe.load_json(run / "attack" / "summary.json") or {}
    util = reframe.load_json(run / "utility" / "summary.json") or {}

    def get(src: dict, key: str):
        block = (src.get("by_lang") or {}).get(lang, {}) if lang else src.get("overall") or {}
        stat = block.get(key) or {}
        return stat.get("mean") if stat.get("n") else None

    return {
        "linkable": get(atk, "linkable_disclosure_rate"),
        "identity_recovered": get(atk, "attack_identity_recovery_rate"),
        "situation": get(atk, "situation_inference_rate"),
        "usefulness": get(util, "utility_mean"),
        "reference_usefulness": get(util, "reference_utility_mean"),
        "utility_ratio": get(util, "utility_ratio_vs_reference"),
        "distortion": get(util, "distortion_rate"),
        "reference_distortion": get(util, "reference_distortion_rate"),
        "judged": get(util, "judged"),
    }


def tokens(run: Path) -> dict[str, int]:
    """Measured attack and utility tokens, plus the harness upstream estimated from payloads."""
    out = {"attack": 0, "utility": 0, "upstream_est": 0}
    cfg = reframe.load_json(run / "attack" / "config.json") or {}
    out["attack"] = sum(int(v or 0) for v in (cfg.get("usage") or {}).values())
    cfg = reframe.load_json(run / "utility" / "config.json") or {}
    for r in cfg.get("runs") or []:
        for part in (r.get("usage") or {}).values():
            out["utility"] += int(part.get("prompt_tokens") or 0) + int(
                part.get("completion_tokens") or 0
            )
    for path in run.glob("pass_*.jsonl"):
        for line in path.open(encoding="utf-8"):
            rec = json.loads(line)["record"]
            for hop in (rec.get("audit") or {}).get("outbound") or []:
                if hop.get("destination") == "upstream":
                    out["upstream_est"] += attack.estimate_tokens(
                        json.dumps(hop.get("payload"), ensure_ascii=False)
                    )
                    out["upstream_est"] += attack.estimate_tokens(str(rec.get("answer") or ""))
    return out


def split(fn, runs: list[Path], key: str, fmt=pct) -> list[str]:
    cells = []
    for run in runs:
        vals = [fn(run, lang).get(key) for lang in LANGS]
        cells.append(" / ".join(fmt(v) for v in vals))
    return cells


def num(v: float | None) -> str:
    return "n/a" if v is None else f"{v:.2f}"


def main() -> None:
    stub = [HERE / f"stub-{c}" for _, c in CONFIGS]
    dev = [HERE / f"dev-{c}" for _, c in CONFIGS]
    names = [n for n, _ in CONFIGS]
    print("### Dev split (72 cases): main vs branch, all / ko / en\n")
    print("| Metric | " + " | ".join(names) + " |")
    print("|---|" + "---:|" * len(names))
    rows = [
        ("**Identity leak** (scanner, 2 passes)", split(scanner, stub, "identity_leak_rate")),
        ("**Linkable disclosure** (attacker, 1 pass)", split(cloud, dev, "linkable")),
        ("Identity recovered (attacker)", split(cloud, dev, "identity_recovered")),
        ("Situation inferred (attacker)", split(cloud, dev, "situation")),
        ("**Usefulness** 1-5 (judge)", split(cloud, dev, "usefulness", num)),
        ("Reference usefulness", split(cloud, dev, "reference_usefulness", num)),
        ("**Utility ratio**", split(cloud, dev, "utility_ratio", num)),
        ("**Distortion**", split(cloud, dev, "distortion")),
        ("Reference distortion", split(cloud, dev, "reference_distortion")),
        ("**Over-redaction** (scanner, 2 passes)", split(scanner, stub, "over_redaction_rate")),
        ("Quasi re-id (scanner)", split(scanner, stub, "quasi_reid_rate")),
        ("Benign masked", split(scanner, stub, "benign_false_positive_rate")),
        ("Benign blocked", split(scanner, stub, "over_block_benign")),
        ("Block rate, all cases", split(scanner, stub, "block_rate")),
    ]
    for label, cells in rows:
        print(f"| {label} | " + " | ".join(cells) + " |")
    print()
    for name, run in zip(names, dev, strict=True):
        if run.is_dir():
            print(f"- {name}: tokens {tokens(run)}")
    print()
    for name, run in zip(names, stub, strict=True):
        if run.is_dir():
            s = scanner(run, None)
            print(
                f"- {name}: scanner passes {s['passes']}, benign masked "
                f"{s['benign_masked_n']:.1f} / blocked {s['benign_blocked_n']:.1f} of "
                f"{s['benign_n']:.0f} per pass"
            )
    diag()
    named()


def named() -> None:
    runs = [(n, HERE / f"named-ko-{c}") for n, c in CONFIGS if (HERE / f"named-ko-{c}").is_dir()]
    if not runs:
        return
    print("\n### Korean cases named in FINAL.md, local scan only (per pass)\n")
    print("| Case | " + " | ".join(n for n, _ in runs) + " |")
    print("|---|" + "---|" * len(runs))
    per_run = {name: scored_passes(run) for name, run in runs}
    ids = sorted(per_run[runs[0][0]][0])
    for cid in ids:
        cells = []
        for name, _ in runs:
            _, _, scored = per_run[name]
            parts = []
            for sc in scored:
                s = next(x for x in sc if x["case_id"] == cid)
                bits = ["blocked" if s["blocked"] else "sent"]
                if s.get("identity_leaked"):
                    bits.append("identity leak")
                if s["category"] == "benign" and s["masking_detections"]:
                    bits.append("masked")
                if s["must_keep_missing"]:
                    bits.append("missing " + ", ".join(s["must_keep_missing"]))
                parts.append(", ".join(bits))
            cells.append("<br>".join(parts))
        print(f"| `{cid}` | " + " | ".join(cells) + " |")


def diag() -> None:
    runs = [(n, HERE / f"diag-{c}") for n, c in CONFIGS if (HERE / f"diag-{c}").is_dir()]
    if not runs:
        return
    print("\n### Diagnostic: the 9 persistent linkable cases, local scan only\n")
    print("Attributes of each case's quasi group found in the outbound payload, per pass.\n")
    print("| Case | split | identity_k | " + " | ".join(n for n, _ in runs) + " |")
    print("|---|---|---:|" + "---|" * len(runs))
    split_ids = json.loads((EVAL / "results" / "ensemble-split.json").read_text())
    dev = set(split_ids["dev"])
    per_run = {}
    for name, run in runs:
        cases, _records, scored = scored_passes(run)
        per_run[name] = (cases, scored)
    cases = per_run[runs[0][0]][0]
    for cid in sorted(cases):
        case = cases[cid]
        k = case["protected"]["identity_k"]
        cells = []
        for name, _ in runs:
            _, scored = per_run[name]
            parts = []
            for sc in scored:
                s = next(x for x in sc if x["case_id"] == cid)
                found = sorted({i for v in (s["quasi"] or {}).get("per_destination", {}).values()
                                for i in v})  # fmt: skip
                attrs = [case["quasi_group"][i][0] for i in found]
                mark = "leak" if s.get("identity_leaked") else "ok"
                parts.append(f"{mark}: {', '.join(attrs) or '-'}")
            cells.append("<br>".join(parts))
        where = "dev" if cid in dev else "test"
        print(f"| `{cid}` | {where} | {k} | " + " | ".join(cells) + " |")


if __name__ == "__main__":
    main()
