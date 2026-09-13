"""Reuse attack and utility scores when a system's outputs are identical across passes.

The local baselines (raw, regex, presidio_ko, gliner_pii) are deterministic: every pass sends the
same payloads. Scoring passes 2..N again only re-samples the attacker and the judge. With
`--reuse-identical-passes`, attack.py and utility.py hash what the scorer would see for each case
(the outbound payloads, and for recorded answers the answer too) and reuse the pass-1 row, by
reference, for every case whose hash matches. A case whose hash differs is scored normally.
`--reuse-from DIR` does the same against pass 1 of an earlier results directory of the same
system, provided that run was scored with the same models. Stdlib only.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

REUSE_NOTE = "scored once; outputs identical across passes, verified by payload hash"


def canonical_sha256(obj: Any) -> str:
    return hashlib.sha256(
        json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def outbound_sha256(record: dict[str, Any]) -> str:
    """SHA-256 of every (destination, payload) that left the machine for one request."""
    hops = (record.get("audit") or {}).get("outbound") or []
    return canonical_sha256([[h.get("destination"), h.get("payload")] for h in hops])


def judged_sha256(record: dict[str, Any], answer_source: str) -> str:
    """What the utility judge depends on: the payloads, plus the answer when it is recorded."""
    parts: dict[str, Any] = {"outbound": outbound_sha256(record), "status": record.get("status")}
    if answer_source == "recorded":
        parts["answer"] = record.get("answer") or ""
    return canonical_sha256(parts)


def reference(pass_no: int, digest: str, results_dir: str | None = None) -> dict[str, Any]:
    ref: dict[str, Any] = {"pass": pass_no, "sha256": digest}
    if results_dir:
        ref["results_dir"] = results_dir
    return ref


def read_pass_records(run_dir: Path, pass_no: int = 1) -> dict[str, dict[str, Any]]:
    path = run_dir / f"pass_{pass_no:02d}.jsonl"
    if not path.exists():
        return {}
    rows = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    return {r["record"]["case_id"]: r["record"] for r in rows}


def read_rows(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    rows = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    return {r["case_id"]: r for r in rows}


def summarize(rows_by_pass: list[list[dict[str, Any]]], source: str | None) -> dict[str, Any]:
    """The `reuse` block for config.json: counts per pass and where rows came from."""
    by_pass = []
    for i, rows in enumerate(rows_by_pass, start=1):
        reused = [r for r in rows if r.get("reused_from")]
        by_pass.append(
            {
                "pass": i,
                "rows": len(rows),
                "reused_within_run": sum(
                    1 for r in reused if "results_dir" not in r["reused_from"]
                ),
                "reused_from_earlier_run": sum(
                    1 for r in reused if "results_dir" in r["reused_from"]
                ),
            }
        )
    total = sum(p["rows"] for p in by_pass)
    reused = sum(p["reused_within_run"] + p["reused_from_earlier_run"] for p in by_pass)
    return {
        "note": REUSE_NOTE,
        "from": source,
        "rows": total,
        "rows_reused": reused,
        "rows_scored": total - reused,
        "by_pass": by_pass,
    }
