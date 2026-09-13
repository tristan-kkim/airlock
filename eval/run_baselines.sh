#!/usr/bin/env bash
# Run the leak harness against each local baseline (no cloud calls; answers are stubbed).
#
#   eval/run_baselines.sh                      # raw regex presidio_ko gliner_pii, 3 passes each
#   eval/run_baselines.sh raw presidio_ko      # a subset
#   PASSES=10 eval/run_baselines.sh regex
#
# Each baseline starts on its own port (raw 8801, regex 8802, presidio_ko 8803, gliner_pii 8804),
# the harness writes to eval/results/baseline-<name>/, and the server is stopped afterwards.
# Server logs go to eval/results/baseline-<name>.server.log (not committed). Finishes by
# regenerating eval/results/COMPARISON.md.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PASSES="${PASSES:-3}"
READY_TIMEOUT="${READY_TIMEOUT:-1800}"   # first start may download models
NAMES=("$@")
[ ${#NAMES[@]} -eq 0 ] && NAMES=(raw regex presidio_ko gliner_pii)

script_for() {
  case "$1" in
    raw) echo "eval/baselines/raw.py 8801" ;;
    regex) echo "eval/baselines/regex_only.py 8802" ;;
    presidio_ko) echo "eval/baselines/presidio_ko.py 8803" ;;
    gliner_pii) echo "eval/baselines/gliner_pii.py 8804" ;;
    *) echo "unknown baseline: $1" >&2; return 1 ;;
  esac
}

SERVER_PID=""
cleanup() { [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true; }
trap cleanup EXIT

for name in "${NAMES[@]}"; do
  read -r script port < <(script_for "$name")
  out="eval/results/baseline-$name"
  log="eval/results/baseline-$name.server.log"
  mkdir -p eval/results
  echo "== $name: starting $script on :$port"
  uv run "$script" --port "$port" >"$log" 2>&1 &
  SERVER_PID=$!
  waited=0
  until curl -sf "http://127.0.0.1:$port/healthz" >/dev/null; do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      echo "   $name exited during startup; see $log" >&2
      tail -20 "$log" >&2
      SERVER_PID=""
      continue 2
    fi
    if [ "$waited" -ge "$READY_TIMEOUT" ]; then
      echo "   $name not ready after ${READY_TIMEOUT}s; skipping (see $log)" >&2
      cleanup; SERVER_PID=""
      continue 2
    fi
    sleep 2; waited=$((waited + 2))
  done
  echo "   ready after ${waited}s; running $PASSES passes into $out"
  uv run eval/run.py --base-url "http://127.0.0.1:$port" --passes "$PASSES" --out "$out" \
    --label "baseline:$name" --reset-vault --timeout 600
  cleanup; wait "$SERVER_PID" 2>/dev/null || true; SERVER_PID=""
done

uv run eval/compare.py
