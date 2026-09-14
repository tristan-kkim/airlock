"""Record live runs of the demo presets as the "recorded run" fallbacks, behind a leak gate.

Runs every preset (or the ids given) against a running demo server and writes
`airlock/demo/recorded/<preset_id>.json`. Each run makes real Token Factory and Tavily calls,
so it spends credit: about 2 to 6 cloud calls per chat or search preset and about 45 per agent run.

    AIRLOCK_DEMO=1 AIRLOCK_DETECTOR_BACKEND=cloud uv run airlock serve --port 8801   # or docker
    uv run python scripts/demo/record_presets.py --base http://127.0.0.1:8801
    uv run python scripts/demo/record_presets.py --base http://127.0.0.1:8801 --dry-run chat-rent-ko

The detector varies between runs, so a run is only accepted when it passes the gate:

- the run was live and produced an answer (search: results);
- none of the preset's declared private values (`tests/fixtures/demo_private_values.py`) appears
  in any outbound payload of the run's full audit record, or in the recording's outbound fields;
- the answer is on topic (keyword check) and has no leftover placeholder.

A preset that fails is retried up to `--attempts` times, then reported and left unchanged.
`--max-cloud-calls` stops starting new runs once the next one could cross the cap (the server's
own counter, read from /demo/status); it cannot interrupt a run already in flight.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "airlock" / "demo" / "recorded"
sys.path.insert(0, str(ROOT))

from tests.fixtures.demo_private_values import (  # noqa: E402
    PRIVATE_VALUES,
    answer_problems,
    find_private_values,
    recording_outbound,
)

# Cloud calls one run may need, per mode (measured on the 2026-09-14 local smoke test, rounded up).
CALL_ESTIMATE = {"chat": 6, "search": 8, "agent": 48}


def cloud_calls(client: httpx.Client) -> int:
    return int(client.get("/demo/status").json()["budget"]["cloud_calls"])


def audit_payloads(audit: dict[str, Any]) -> list[Any]:
    """Every exact payload that left the server: outbound entries and agent hop payloads."""
    return [o.get("payload") for o in audit.get("outbound") or []] + [
        h.get("payload") for h in audit.get("hops") or [] if h.get("payload") is not None
    ]


def gate(client: httpx.Client, preset_id: str, status: int, data: dict[str, Any]) -> list[str]:
    """Reasons to reject a run; empty means the run may become the recording."""
    if status != 200 or data.get("source") != "live" or data.get("error"):
        return [f"not a live result (HTTP {status}, source={data.get('source')})"]
    if not (data.get("answer") or data.get("results")):
        return ["no answer"]
    request_id = data.get("request_id")
    audit_resp = client.get(f"/audit/{request_id}") if request_id else None
    if audit_resp is None or audit_resp.status_code != 200:
        return ["audit record not available"]
    payloads = audit_payloads(audit_resp.json())
    if not payloads:
        return ["audit has no outbound payload"]
    problems = [
        f"private value sent to the cloud: {v!r}"
        for v in find_private_values([*payloads, recording_outbound(data)], preset_id)
    ]
    data["leak_check"] = {
        "outbound_payloads": len(payloads),
        "private_values": len(PRIVATE_VALUES[preset_id]),
        "found": len(problems),
    }
    return problems + answer_problems(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("ids", nargs="*", help="preset ids (default: all)")
    parser.add_argument("--base", default="http://127.0.0.1:8801")
    parser.add_argument("--out", type=Path, default=OUT)
    parser.add_argument("--dry-run", action="store_true", help="run and print, do not write")
    parser.add_argument("--attempts", type=int, default=3, help="live runs per preset at most")
    parser.add_argument("--max-cloud-calls", type=int, default=0, help="0 means no cap")
    args = parser.parse_args(argv)

    with httpx.Client(base_url=args.base, timeout=600) as client:
        presets = {p["id"]: p for p in client.get("/demo/presets").json()["presets"]}
        ids = args.ids or list(presets)
        start_calls = cloud_calls(client)
        summary: list[str] = []
        for preset_id in ids:
            mode = presets[preset_id]["mode"]
            outcome = "FAIL"
            attempt = 0
            for attempt in range(1, args.attempts + 1):  # noqa: B007
                spent = cloud_calls(client) - start_calls
                if args.max_cloud_calls and spent + CALL_ESTIMATE[mode] > args.max_cloud_calls:
                    print(f"{preset_id}: not started, {spent} calls spent and a {mode} run may "
                          f"need {CALL_ESTIMATE[mode]} (cap {args.max_cloud_calls})")  # fmt: skip
                    outcome = "SKIPPED (cap)"
                    attempt -= 1
                    break
                # A fresh session per attempt: a session caches detector results, so a retry in
                # the same session would replay the rejected detection instead of re-running it.
                client.cookies.clear()
                before = cloud_calls(client)
                started = time.perf_counter()
                r = client.post(f"/demo/presets/{preset_id}/run", json={})
                seconds = round(time.perf_counter() - started, 1)
                data = r.json()
                problems = gate(client, preset_id, r.status_code, data)
                used = cloud_calls(client) - before
                gate_decision = (data.get("gate") or {}).get("decision")
                verdict = "REJECTED" if problems else "ACCEPTED"
                print(f"{preset_id} attempt {attempt}: HTTP {r.status_code} "
                      f"source={data.get('source')} gate={gate_decision} {seconds}s "
                      f"{used} cloud calls -> {verdict}")  # fmt: skip
                for p in problems:
                    print(f"  - {p}")
                if problems:
                    continue
                data.update(
                    source="recorded",
                    fallback_reason=None,
                    recorded_at=datetime.now(UTC).isoformat(timespec="seconds"),
                    request_id=None,
                    recorded_seconds=seconds,
                )
                outcome = "PASS"
                if args.dry_run:
                    print(json.dumps(data, ensure_ascii=False, indent=2)[:2000])
                    break
                args.out.mkdir(parents=True, exist_ok=True)
                path = args.out / f"{preset_id}.json"
                text = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
                path.write_text(text, encoding="utf-8")
                print(f"  wrote {path.relative_to(ROOT)}")
                break
            summary.append(f"{preset_id}: {outcome} after {attempt} attempt(s)")
        total = cloud_calls(client) - start_calls
        print("\n".join(["", *summary, f"cloud calls used by this script: {total}"]))
    return 0 if all(": PASS" in s for s in summary) else 1


if __name__ == "__main__":
    sys.exit(main())
