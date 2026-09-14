"""Record live runs of the demo presets as the "recorded run" fallbacks.

Runs every preset (or the ids given) once against a running demo server and writes
`airlock/demo/recorded/<preset_id>.json`. Each run makes real Token Factory and Tavily calls,
so it spends credit: about 1 to 3 cloud calls per chat or search preset and 10 to 25 per agent run.

    AIRLOCK_DEMO=1 AIRLOCK_DETECTOR_BACKEND=cloud uv run airlock serve --port 8801   # or docker
    uv run python scripts/demo/record_presets.py --base http://127.0.0.1:8801
    uv run python scripts/demo/record_presets.py --base http://127.0.0.1:8801 --dry-run chat-rent-ko

A preset is only written when its run was live and produced an answer (or, for search, results).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "airlock" / "demo" / "recorded"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("ids", nargs="*", help="preset ids (default: all)")
    parser.add_argument("--base", default="http://127.0.0.1:8801")
    parser.add_argument("--out", type=Path, default=OUT)
    parser.add_argument("--dry-run", action="store_true", help="run and print, do not write")
    args = parser.parse_args(argv)

    with httpx.Client(base_url=args.base, timeout=600) as client:
        presets = client.get("/demo/presets").json()["presets"]
        ids = args.ids or [p["id"] for p in presets]
        failures = 0
        for preset_id in ids:
            started = time.perf_counter()
            r = client.post(f"/demo/presets/{preset_id}/run", json={})
            seconds = round(time.perf_counter() - started, 1)
            data = r.json()
            ok = (
                r.status_code == 200
                and data.get("source") == "live"
                and not data.get("error")
                and (data.get("answer") or data.get("results"))
            )
            gate = (data.get("gate") or {}).get("decision")
            print(f"{preset_id}: HTTP {r.status_code} source={data.get('source')} gate={gate} "
                  f"{seconds}s {'ok' if ok else 'NOT RECORDED'}")  # fmt: skip
            if not ok:
                failures += 1
                print(json.dumps(data.get("error") or data, ensure_ascii=False)[:600])
                continue
            data.update(
                source="recorded",
                fallback_reason=None,
                recorded_at=datetime.now(UTC).isoformat(timespec="seconds"),
                request_id=None,
                recorded_seconds=seconds,
            )
            if args.dry_run:
                print(json.dumps(data, ensure_ascii=False, indent=2)[:2000])
                continue
            args.out.mkdir(parents=True, exist_ok=True)
            path = args.out / f"{preset_id}.json"
            path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            print(f"  wrote {path.relative_to(ROOT)}")
        status = client.get("/demo/status").json()["budget"]
        print(f"server budget counters: {status['requests']} requests, "
              f"{status['cloud_calls']} cloud calls today")  # fmt: skip
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
