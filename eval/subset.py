"""Case subsets shared by run.py, attack.py, utility.py and final_protocol.sh.

    --subset stratified:120 --seed 0     120 cases, stratified by category x language
    --subset ids:eval/results/<run>       the exact case ids another run used (its config.json)
    --subset ids:ids.txt                  one case id per line

Stratified selection is proportional to each (category, language) stratum's size, rounded by
largest remainder, with a seeded shuffle inside each stratum. It depends only on the case list,
N and the seed, so every system gets the same ids; the chosen ids are written to each results
`config.json` under `subset` and can be passed on with `ids:`. Stdlib only.
"""

from __future__ import annotations

import json
import math
import random
from collections.abc import Iterable
from pathlib import Path
from typing import Any


def parse_spec(spec: str) -> tuple[str, str]:
    kind, sep, arg = spec.partition(":")
    if not sep or kind not in ("stratified", "ids") or not arg:
        raise ValueError(f"--subset must be stratified:N or ids:PATH, not {spec!r}")
    if kind == "stratified" and (not arg.isdigit() or int(arg) <= 0):
        raise ValueError(f"stratified subset size must be a positive integer, not {arg!r}")
    return kind, arg


def stratum(case: dict[str, Any]) -> str:
    return f"{case['category']}/{case['lang']}"


def allocate(sizes: dict[str, int], n: int) -> dict[str, int]:
    """Per-stratum counts summing to min(n, total), proportional by largest remainder."""
    total = sum(sizes.values())
    n = min(n, total)
    if total == 0:
        return dict.fromkeys(sizes, 0)
    exact = {k: n * v / total for k, v in sizes.items()}
    counts = {k: math.floor(x) for k, x in exact.items()}
    order = sorted(sizes, key=lambda k: (-(exact[k] - counts[k]), -sizes[k], k))
    for k in order[: n - sum(counts.values())]:
        counts[k] += 1
    return counts


def stratified_ids(cases: Iterable[dict[str, Any]], n: int, seed: int) -> list[str]:
    groups: dict[str, list[str]] = {}
    for case in cases:
        groups.setdefault(stratum(case), []).append(case["id"])
    counts = allocate({k: len(v) for k, v in groups.items()}, n)
    chosen = []
    for key in sorted(groups):
        ids = sorted(groups[key])
        random.Random(f"subset:{seed}:{key}").shuffle(ids)
        chosen += ids[: counts[key]]
    return sorted(chosen)


def read_ids(path: Path) -> list[str]:
    """Case ids from a results directory, a config.json with `subset`, or a text file."""
    if path.is_dir():
        path = path / "config.json"
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        data = json.loads(text)
        subset = data.get("subset") if isinstance(data, dict) else None
        if not subset or not subset.get("case_ids"):
            raise ValueError(f"{path} has no subset.case_ids")
        return list(subset["case_ids"])
    return [line.strip() for line in text.splitlines() if line.strip()]


def select(
    cases: list[dict[str, Any]], spec: str | None, seed: int = 0
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """(cases in the subset, in their original order; the `subset` record for config.json)."""
    if not spec:
        return cases, None
    kind, arg = parse_spec(spec)
    if kind == "stratified":
        ids = stratified_ids(cases, int(arg), seed)
    else:
        known = {c["id"] for c in cases}
        wanted = read_ids(Path(arg))
        missing = [i for i in wanted if i not in known]
        if missing:
            raise ValueError(f"subset ids not in the case list: {', '.join(missing[:5])}")
        ids = sorted(set(wanted))
    keep = set(ids)
    chosen = [c for c in cases if c["id"] in keep]
    strata: dict[str, int] = {}
    for c in chosen:
        strata[stratum(c)] = strata.get(stratum(c), 0) + 1
    info = {
        "spec": spec,
        "seed": seed if kind == "stratified" else None,
        "cases": len(chosen),
        "of": len(cases),
        "strata": dict(sorted(strata.items())),
        "case_ids": ids,
    }
    return chosen, info
