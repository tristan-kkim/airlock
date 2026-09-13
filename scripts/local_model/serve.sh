#!/usr/bin/env bash
# Start (idempotently) the Airlock local privacy-gate model: Nemotron-3-Nano-4B via llama-server.
#
#   scripts/local_model/serve.sh          # start if not running, wait until healthy
#   scripts/local_model/serve.sh stop     # stop the server started by this script
#   scripts/local_model/serve.sh status   # print health / pid
#
# Env:
#   AIRLOCK_LOCAL_MODEL_PATH  GGUF path (default ~/.cache/airlock/models/NVIDIA-Nemotron3-Nano-4B-Q4_K_M.gguf)
#   AIRLOCK_LOCAL_HOST        bind host (default 127.0.0.1 - keep it loopback-only)
#   AIRLOCK_LOCAL_PORT        port (default 8081)
#   AIRLOCK_LOCAL_CTX         context size (default 8192)
#   AIRLOCK_LOCAL_PARALLEL    server slots (default 1)
#   AIRLOCK_LOCAL_REASONING   on|off|auto (default off). This is only the default: a request can still send
#                             chat_template_kwargs {"enable_thinking": true|false} to override it (verified).
#   AIRLOCK_LOCAL_CACHE_RAM_MIB  host prompt-cache size in MiB (default 0 = off; llama.cpp default 8192 grew the
#                             server to a 9.2 GB footprint because each hybrid-model cache entry is ~326 MiB)
#   AIRLOCK_LOCAL_API_KEY     optional bearer key required by the server (recommended outside a demo)
#
# Model download (no token needed, ~2.8 GB):
#   mkdir -p ~/.cache/airlock/models && curl -L --fail -C - \
#     -o ~/.cache/airlock/models/NVIDIA-Nemotron3-Nano-4B-Q4_K_M.gguf \
#     https://huggingface.co/nvidia/NVIDIA-Nemotron-3-Nano-4B-GGUF/resolve/main/NVIDIA-Nemotron3-Nano-4B-Q4_K_M.gguf
set -euo pipefail

MODEL_PATH="${AIRLOCK_LOCAL_MODEL_PATH:-$HOME/.cache/airlock/models/NVIDIA-Nemotron3-Nano-4B-Q4_K_M.gguf}"
HOST="${AIRLOCK_LOCAL_HOST:-127.0.0.1}"
PORT="${AIRLOCK_LOCAL_PORT:-8081}"
CTX="${AIRLOCK_LOCAL_CTX:-8192}"
PARALLEL="${AIRLOCK_LOCAL_PARALLEL:-1}"
REASONING="${AIRLOCK_LOCAL_REASONING:-off}"
CACHE_RAM="${AIRLOCK_LOCAL_CACHE_RAM_MIB:-0}"
STATE_DIR="$HOME/.cache/airlock/run"
PID_FILE="$STATE_DIR/llama-server-$PORT.pid"
LOG_FILE="$STATE_DIR/llama-server-$PORT.log"
BASE_URL="http://$HOST:$PORT"

mkdir -p "$STATE_DIR"

healthy() { curl -fsS --max-time 2 "$BASE_URL/health" >/dev/null 2>&1; }
our_pid() { [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null && cat "$PID_FILE"; }

case "${1:-start}" in
  stop)
    if pid=$(our_pid); then
      kill "$pid" && echo "stopped llama-server pid $pid"
      for _ in $(seq 1 50); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    else
      echo "no llama-server started by this script on port $PORT"
    fi
    rm -f "$PID_FILE"
    exit 0
    ;;
  status)
    if healthy; then echo "healthy at $BASE_URL (pid $(our_pid || echo unknown))"; else echo "not running at $BASE_URL"; exit 1; fi
    exit 0
    ;;
  start) ;;
  *) echo "usage: $0 [start|stop|status]" >&2; exit 2 ;;
esac

if healthy; then
  echo "llama-server already healthy at $BASE_URL (pid $(our_pid || echo 'not ours'))"
  exit 0
fi

if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "port $PORT is in use by another process that is not a healthy llama-server:" >&2
  lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >&2 || true
  exit 1
fi

command -v llama-server >/dev/null || { echo "llama-server not found. Install: brew install llama.cpp" >&2; exit 1; }
[[ -f "$MODEL_PATH" ]] || { echo "model not found: $MODEL_PATH (see download command in this script header)" >&2; exit 1; }

# Notes on flags:
#  -ngl 999             offload all layers to Metal
#  --reasoning off      renders "<think></think>" in the generation prompt (= enable_thinking=false);
#                       '--chat-template-kwargs {"enable_thinking":false}' is deprecated in this build
#  --cors-origins localhost  do not let arbitrary web pages read the gate (default is '*')
#  -c / -np             small context, single slot: prompts are short and the gate runs sequentially.
#                       The live slot still reuses the shared system-prompt prefix (cache_n ~970 tokens).
#  --temp 0.6 --top-p 0.95 -n 512  defaults if the client omits them; temp 0 hit a repetition loop to max_tokens
#                       on one Korean case, so keep a hard output cap and treat finish_reason=length as a gate failure
#  --cache-ram 0        disable the host-RAM prompt cache (see AIRLOCK_LOCAL_CACHE_RAM_MIB)
#  --no-webui           API only
EXTRA_ARGS=()
if [[ -n "${AIRLOCK_LOCAL_API_KEY:-}" ]]; then EXTRA_ARGS+=(--api-key "$AIRLOCK_LOCAL_API_KEY"); fi

nohup llama-server \
  -m "$MODEL_PATH" \
  --alias nemotron-3-nano-4b \
  --host "$HOST" --port "$PORT" \
  -ngl 999 -fa on \
  -c "$CTX" -np "$PARALLEL" \
  --jinja \
  --cache-ram "$CACHE_RAM" \
  --reasoning "$REASONING" \
  --cors-origins localhost --no-cors-credentials \
  --temp 0.6 --top-p 0.95 -n 512 \
  --no-webui --metrics \
  ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"} \
  >"$LOG_FILE" 2>&1 &
echo $! >"$PID_FILE"

start_ts=$(date +%s)
for _ in $(seq 1 240); do
  if healthy; then
    echo "llama-server healthy at $BASE_URL (pid $(cat "$PID_FILE"), ready in $(( $(date +%s) - start_ts ))s, log $LOG_FILE)"
    exit 0
  fi
  if ! kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "llama-server exited during startup; last log lines:" >&2
    tail -n 30 "$LOG_FILE" >&2
    rm -f "$PID_FILE"
    exit 1
  fi
  sleep 0.5
done
echo "timed out waiting for $BASE_URL/health (log $LOG_FILE)" >&2
exit 1
