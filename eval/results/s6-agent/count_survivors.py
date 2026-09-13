"""Deterministic identity-fact survivors in agent runs (no attacker, no cloud calls).

    uv run python eval/results/s6-agent/count_survivors.py eval/results/s6-agent/placeholder \
        eval/results/s6-agent/surrogate

For each run in `<dir>/runs/pass_*.jsonl`, every identity fact of the scenario (`fact_classes`)
is searched in everything that left the machine (all upstream messages and Tavily queries, with
the eval scanner's normalized and decoded variants). A fact found there is a survivor.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "eval"))
sys.path.insert(0, str(ROOT / "eval" / "agent"))

import scoring  # noqa: E402
from run_agent_eval import load_scenarios, observer_views  # noqa: E402


def survivors(run_dir: Path) -> list[dict]:
    scenarios = {s["id"]: s for s in load_scenarios()}
    rows = []
    for path in sorted((run_dir / "runs").glob("pass_*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            run = json.loads(line)
            if run["mode"] != "airlock":
                continue
            s = scenarios[run["scenario_id"]]
            identity = [f for f, c in s["fact_classes"].items() if c == "identity"]
            views = observer_views(run.get("audit") or {})["all"]
            hays = [scoring.Haystack(v["payload"]) for v in views]
            found = [f for f in identity if any(h.find(f) for h in hays)]
            rows.append(
                {
                    "scenario": s["id"],
                    "status": run["status"],
                    "steps": run["steps"],
                    "identity_facts": len(identity),
                    "survivors": found,
                }
            )
    return rows


def main() -> None:
    for arg in sys.argv[1:]:
        run_dir = Path(arg)
        rows = survivors(run_dir)
        total = sum(r["identity_facts"] for r in rows)
        left = sum(len(r["survivors"]) for r in rows)
        print(f"## {run_dir.name}: {left} of {total} identity facts reached the cloud")
        for r in rows:
            print(f"- {r['scenario']} ({r['status']}, {r['steps']} steps): {r['survivors']}")
        (run_dir / "survivors.json").write_text(
            json.dumps(rows, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    main()
