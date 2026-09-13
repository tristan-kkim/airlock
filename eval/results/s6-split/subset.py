"""S6 glue: test-split case files, a stratified 90-case subset, and subset copies of run dirs.

    uv run python eval/results/s6-split/subset.py split           # dev.jsonl, test.jsonl, test90.json
    uv run python eval/results/s6-split/subset.py copy SRC DST     # SRC restricted to test90

The 90 cases are drawn from the 171 test cases of `ensemble-split.json`, proportional to each
(category, language) stratum by largest remainder, seeded shuffle inside each stratum (seed 6).
`copy` writes pass_01.jsonl, cases_snapshot.jsonl and config.json for the subset, plus
attack/pass_01.jsonl and attack/config.json when SRC has them; summaries are rebuilt with
`eval/run.py --rescore` and `eval/attack.py --score-only`.
"""

from __future__ import annotations

import collections
import glob
import json
import random
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
EVAL = HERE.parents[1]
SEED = 6
N = 90


def cases() -> list[dict]:
    return [
        json.loads(line)
        for f in sorted(glob.glob(str(EVAL / "cases/*.jsonl")))
        for line in Path(f).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def split() -> None:
    sp = json.loads((EVAL / "results/ensemble-split.json").read_text())
    all_cases = cases()
    for name in ("dev", "test"):
        ids = set(sp[name])
        rows = [json.dumps(c, ensure_ascii=False) for c in all_cases if c["id"] in ids]
        (HERE / f"{name}.jsonl").write_text("\n".join(rows) + "\n", encoding="utf-8")
    test = [c for c in all_cases if c["id"] in set(sp["test"])]
    strata: dict[str, list[str]] = collections.defaultdict(list)
    for c in test:
        strata[f"{c['category']}/{c['lang']}"].append(c["id"])
    quotas = {k: len(v) * N / len(test) for k, v in strata.items()}
    counts = {k: int(q) for k, q in quotas.items()}
    for k in sorted(quotas, key=lambda k: (-(quotas[k] - counts[k]), k))[: N - sum(counts.values())]:
        counts[k] += 1
    rng = random.Random(SEED)
    chosen: list[str] = []
    for k in sorted(strata):
        ids = sorted(strata[k])
        rng.shuffle(ids)
        chosen += ids[: counts[k]]
    out = {"seed": SEED, "n": len(chosen), "method": "stratified by (category, lang) within the "
           "ensemble-split test cases, largest remainder", "ids": sorted(chosen)}  # fmt: skip
    (HERE / "test90.json").write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    print(f"test90: {len(chosen)} cases")


def copy(src: Path, dst: Path) -> None:
    ids = set(json.loads((HERE / "test90.json").read_text())["ids"])
    dst.mkdir(parents=True, exist_ok=True)

    def filt(name: str, key) -> None:
        rows = [
            line
            for line in (src / name).read_text(encoding="utf-8").splitlines()
            if line.strip() and key(json.loads(line)) in ids
        ]
        (dst / name).parent.mkdir(parents=True, exist_ok=True)
        (dst / name).write_text("\n".join(rows) + "\n", encoding="utf-8")

    filt("pass_01.jsonl", lambda r: r["record"]["case_id"])
    filt("cases_snapshot.jsonl", lambda c: c["id"])
    config = json.loads((src / "config.json").read_text())
    config["subset"] = {"file": "eval/results/s6-split/test90.json", "source": src.name}
    (dst / "config.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    if (src / "attack/pass_01.jsonl").exists():
        filt("attack/pass_01.jsonl", lambda r: r["case_id"])
        shutil.copy(src / "attack/config.json", dst / "attack/config.json")


if __name__ == "__main__":
    if sys.argv[1] == "split":
        split()
    else:
        copy(Path(sys.argv[2]), Path(sys.argv[3]))
