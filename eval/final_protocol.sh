#!/usr/bin/env bash
# Final measurement protocol: every system alone on the machine, then attack, utility and the
# unlinkability summary, then COMPARISON.md. See eval/README.md, "Final measurement protocol".
#
#   eval/final_protocol.sh --commit 1a2b3c4                 # print the plan and the cloud estimate
#   eval/final_protocol.sh --commit 1a2b3c4 --yes           # run it
#   eval/final_protocol.sh --commit 1a2b3c4 --gliner both --passes 3 --yes --publish
#
# Options:
#   --commit SHA        Airlock commit to measure (checked out into a temporary git worktree)
#   --gliner on|off|both   AIRLOCK_GLINER for the Airlock runs (default: both = two variants)
#   --passes N          harness passes per system (default 3)
#   --scoring-passes N  passes attacked and judged per system (default: --passes)
#   --systems "..."     subset of: raw regex presidio_ko gliner_pii airlock (default: all)
#   --out DIR           results directory (default eval/results/final-<UTC timestamp>)
#   --model PATH        local GGUF (default ~/.cache/airlock/models/NVIDIA-Nemotron3-Nano-4B-Q4_K_M.gguf)
#   --attack-model M    attacker model (default $AIRLOCK_ATTACK_MODEL or the calibrated default)
#   --grader-model M    intent + situation grader (default $AIRLOCK_GRADER_MODEL or calibrated)
#   --judge-model M     utility judge (default $AIRLOCK_UTILITY_MODEL or calibrated)
#   --confirm-model M   distortion confirmation (default $AIRLOCK_DISTORTION_CONFIRM_MODEL or calibrated)
#   --ultra             every scoring role on Nemotron 3 Ultra, overriding the environment
#   --yes               confirm cloud calls (Airlock upstream + Tavily, attacker, judge)
#   --publish           also write eval/results/COMPARISON.md from this run
#
# Scoring role defaults come from eval/results/JUDGE_CALIBRATION.md (eval/attack.py
# DEFAULT_ROLE_MODELS). The plan prints projected tokens and dollars at list prices before running.
#
# Isolation rules this script enforces:
#   * systems run one after another, never in parallel;
#   * it refuses to start while any llama-server is already running, starts exactly one
#     llama-server for each Airlock variant and stops it by the PID it recorded;
#   * it never uses pkill or killall; every process it stops is one it started.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMMIT=""
GLINER="both"
PASSES=3
SCORING_PASSES=""
SYSTEMS="raw regex presidio_ko gliner_pii airlock"
OUT=""
MODEL_PATH="${AIRLOCK_LOCAL_MODEL_PATH:-$HOME/.cache/airlock/models/NVIDIA-Nemotron3-Nano-4B-Q4_K_M.gguf}"
YES=0
PUBLISH=0
LLAMA_PORT="${LLAMA_PORT:-8181}"
AIRLOCK_EVAL_PORT="${AIRLOCK_EVAL_PORT:-8887}"
READY_TIMEOUT="${READY_TIMEOUT:-1800}"

while [ $# -gt 0 ]; do
  case "$1" in
    --commit) COMMIT="$2"; shift 2 ;;
    --gliner) GLINER="$2"; shift 2 ;;
    --passes) PASSES="$2"; shift 2 ;;
    --scoring-passes) SCORING_PASSES="$2"; shift 2 ;;
    --systems) SYSTEMS="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --model) MODEL_PATH="$2"; shift 2 ;;
    --attack-model) export AIRLOCK_ATTACK_MODEL="$2"; shift 2 ;;
    --grader-model) export AIRLOCK_GRADER_MODEL="$2"; shift 2 ;;
    --judge-model) export AIRLOCK_UTILITY_MODEL="$2"; shift 2 ;;
    --confirm-model) export AIRLOCK_DISTORTION_CONFIRM_MODEL="$2"; shift 2 ;;
    --ultra) ULTRA_MODEL=nvidia/Nemotron-3-Ultra-550b-a55b
      export AIRLOCK_ATTACK_MODEL="$ULTRA_MODEL" AIRLOCK_GRADER_MODEL="$ULTRA_MODEL" \
        AIRLOCK_UTILITY_MODEL="$ULTRA_MODEL" AIRLOCK_DISTORTION_CONFIRM_MODEL="$ULTRA_MODEL"
      shift ;;
    --yes) YES=1; shift ;;
    --publish) PUBLISH=1; shift ;;
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
SCORING_PASSES="${SCORING_PASSES:-$PASSES}"
OUT="${OUT:-eval/results/final-$(date -u +%Y%m%dT%H%M%SZ)}"

BASELINE_LIST=()
RUN_AIRLOCK=0
for s in $SYSTEMS; do
  case "$s" in
    raw|regex|presidio_ko|gliner_pii) BASELINE_LIST+=("$s") ;;
    airlock) RUN_AIRLOCK=1 ;;
    *) echo "unknown system: $s" >&2; exit 2 ;;
  esac
done
VARIANTS=()
if [ "$RUN_AIRLOCK" = 1 ]; then
  [ -n "$COMMIT" ] || { echo "--commit is required when measuring airlock" >&2; exit 2; }
  COMMIT="$(git rev-parse --short "$COMMIT")"
  case "$GLINER" in
    on) VARIANTS=(gliner) ;;
    off) VARIANTS=(nogliner) ;;
    both) VARIANTS=(nogliner gliner) ;;
    *) echo "--gliner must be on, off or both" >&2; exit 2 ;;
  esac
fi

echo "== Final measurement protocol"
echo "   results:   $OUT"
echo "   baselines: ${BASELINE_LIST[*]:-none}"
echo "   airlock:   ${COMMIT:-not measured} variants: ${VARIANTS[*]:-none}"
echo "   passes:    $PASSES harness, $SCORING_PASSES attacked and judged"
echo
# Role models reach every script through the AIRLOCK_*_MODEL variables exported above.
uv run --quiet eval/protocol_estimate.py --passes "$PASSES" --judge-passes "$SCORING_PASSES" \
  --systems ${BASELINE_LIST[@]+"${BASELINE_LIST[@]}"} --airlock-variants "${#VARIANTS[@]}" \
  --projections
echo
echo "   Every value in the dataset is synthetic. The raw baseline, the reference answers and the"
echo "   attacker send those synthetic prompts to Token Factory."
if [ "$YES" != 1 ]; then
  echo "   Not running: pass --yes to start (the estimate above is what it will cost)."
  exit 0
fi

# ---------------------------------------------------------------------------------------------
# Preflight: nothing else may share the machine's model runtime.
# ---------------------------------------------------------------------------------------------
if pgrep -x llama-server >/dev/null 2>&1; then
  echo "refusing to start: a llama-server is already running (pids: $(pgrep -x llama-server | tr '\n' ' '))." >&2
  echo "Stop it first; latency must be measured with each system alone." >&2
  exit 1
fi
for port in 8801 8802 8803 8804 "$LLAMA_PORT" "$AIRLOCK_EVAL_PORT"; do
  if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "refusing to start: port $port is in use" >&2
    exit 1
  fi
done
if ! grep -Eq '^NEBIUS_API_KEY=.+' .env 2>/dev/null && [ -z "${NEBIUS_API_KEY:-}" ]; then
  echo "refusing to start: NEBIUS_API_KEY is not set in the environment or .env" >&2
  exit 1
fi
if [ "$RUN_AIRLOCK" = 1 ]; then
  command -v llama-server >/dev/null || { echo "llama-server not found" >&2; exit 1; }
  [ -f "$MODEL_PATH" ] || { echo "model not found: $MODEL_PATH" >&2; exit 1; }
fi

mkdir -p "$OUT/logs"
SERVER_PID=""
LLAMA_PID=""
WORKTREE=""
stop_pid() {  # stop one process we started, by PID, and wait for it
  local pid="$1"
  [ -n "$pid" ] || return 0
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 100); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
  fi
  wait "$pid" 2>/dev/null || true
}
cleanup() {
  stop_pid "$SERVER_PID"; SERVER_PID=""
  stop_pid "$LLAMA_PID"; LLAMA_PID=""
  if [ -n "$WORKTREE" ] && [ -d "$WORKTREE" ]; then
    git worktree remove --force "$WORKTREE" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

wait_http() {  # url pid log
  local url="$1" pid="$2" log="$3" waited=0
  until curl -sf --max-time 2 "$url" >/dev/null; do
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "   process $pid exited during startup; see $log" >&2; tail -20 "$log" >&2; return 1
    fi
    if [ "$waited" -ge "$READY_TIMEOUT" ]; then
      echo "   not ready after ${READY_TIMEOUT}s: $url" >&2; return 1
    fi
    sleep 2; waited=$((waited + 2))
  done
  echo "   ready after ${waited}s: $url"
}

run_harness() {  # base_url out label [extra args]
  local base="$1" out="$2" label="$3"; shift 3
  uv run eval/run.py --base-url "$base" --passes "$PASSES" --out "$out" --label "$label" \
    --reset-vault --timeout 600 "$@"
}

# ---------------------------------------------------------------------------------------------
# 1. Local baselines, one at a time (no cloud calls)
# ---------------------------------------------------------------------------------------------
for name in ${BASELINE_LIST[@]+"${BASELINE_LIST[@]}"}; do
  case "$name" in
    raw) script=eval/baselines/raw.py; port=8801 ;;
    regex) script=eval/baselines/regex_only.py; port=8802 ;;
    presidio_ko) script=eval/baselines/presidio_ko.py; port=8803 ;;
    gliner_pii) script=eval/baselines/gliner_pii.py; port=8804 ;;
  esac
  log="$OUT/logs/baseline-$name.server.log"
  echo "== baseline $name"
  uv run "$script" --port "$port" >"$log" 2>&1 &
  SERVER_PID=$!
  wait_http "http://127.0.0.1:$port/healthz" "$SERVER_PID" "$log"
  run_harness "http://127.0.0.1:$port" "$OUT/baseline-$name" "baseline:$name"
  stop_pid "$SERVER_PID"; SERVER_PID=""
done

# ---------------------------------------------------------------------------------------------
# 2. Airlock at COMMIT: one llama-server + one Airlock server per variant
# ---------------------------------------------------------------------------------------------
if [ "$RUN_AIRLOCK" = 1 ]; then
  WORKTREE="$(mktemp -d "${TMPDIR:-/tmp}/airlock-final-XXXXXX")"
  rmdir "$WORKTREE"
  git worktree add --detach "$WORKTREE" "$COMMIT" >/dev/null
  cp .env "$WORKTREE/.env"; chmod 600 "$WORKTREE/.env"
  (cd "$WORKTREE" && uv sync --quiet)
  for variant in "${VARIANTS[@]}"; do
    gliner_flag=0; [ "$variant" = gliner ] && gliner_flag=1
    dir="$OUT/baseline-$COMMIT-$variant"
    echo "== airlock $COMMIT ($variant, AIRLOCK_GLINER=$gliner_flag)"
    llama_log="$OUT/logs/llama-server-$variant.log"
    llama-server -m "$MODEL_PATH" --alias nemotron-3-nano-4b \
      --host 127.0.0.1 --port "$LLAMA_PORT" -ngl 999 -fa on -c 8192 -np 1 --jinja \
      --cache-ram 0 --reasoning off --cors-origins localhost --no-cors-credentials \
      --temp 0.6 --top-p 0.95 -n 512 --no-webui --metrics >"$llama_log" 2>&1 &
    LLAMA_PID=$!
    wait_http "http://127.0.0.1:$LLAMA_PORT/health" "$LLAMA_PID" "$llama_log"
    if [ "$(pgrep -x llama-server | wc -l | tr -d ' ')" != 1 ]; then
      echo "another llama-server appeared during the run; aborting" >&2; exit 1
    fi
    HASH_KEY="$(uv run --quiet python -c 'import secrets; print(secrets.token_hex(32))')"
    air_log="$OUT/logs/airlock-$variant.server.log"
    (
      cd "$WORKTREE"
      export AIRLOCK_LOCAL_BASE_URL="http://127.0.0.1:$LLAMA_PORT/v1"
      export AIRLOCK_GLINER="$gliner_flag"
      export AIRLOCK_VAULT_PATH=":memory:" AIRLOCK_AUDIT_DB=":memory:"
      export AIRLOCK_AUDIT_HASH_KEY="$HASH_KEY"
      export AIRLOCK_PROTECTION_LEVEL=balanced AIRLOCK_REVIEW=never
      export AIRLOCK_HOST=127.0.0.1 AIRLOCK_PORT="$AIRLOCK_EVAL_PORT"
      exec uv run airlock serve
    ) >"$air_log" 2>&1 &
    SERVER_PID=$!
    wait_http "http://127.0.0.1:$AIRLOCK_EVAL_PORT/healthz" "$SERVER_PID" "$air_log"
    AIRLOCK_AUDIT_HASH_KEY="$HASH_KEY" run_harness "http://127.0.0.1:$AIRLOCK_EVAL_PORT" "$dir" \
      "airlock@$COMMIT gliner=$gliner_flag" --protection-level balanced
    stop_pid "$SERVER_PID"; SERVER_PID=""
    stop_pid "$LLAMA_PID"; LLAMA_PID=""
  done
fi

# ---------------------------------------------------------------------------------------------
# 3. Cloud scoring per system: attacker + situation grader, utility judge, unlinkability summary
# ---------------------------------------------------------------------------------------------
for dir in "$OUT"/baseline-*/; do
  dir="${dir%/}"
  echo "== scoring $(basename "$dir")"
  uv run eval/attack.py --rescore "$dir" --passes "$SCORING_PASSES"
  uv run eval/utility.py --results "$dir" --passes "$SCORING_PASSES" --yes
done
uv run eval/reframe.py results "$OUT"/baseline-*/
uv run eval/compare.py --results "$OUT" --out "$OUT/COMPARISON.md"
if [ "$PUBLISH" = 1 ]; then
  uv run eval/compare.py --results "$OUT" --out eval/results/COMPARISON.md
fi
echo "done: $OUT/COMPARISON.md"
