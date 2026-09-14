#!/bin/sh
# Option (a) for the hosted demo: llama.cpp llama-server with Nemotron-3-Nano-4B in the same
# container as Airlock. Detection never leaves the container. Used by the Dockerfile `sidecar`
# target; the default `demo` target uses the Token Factory cloud detector instead.
set -eu

LLAMA_PORT="${LLAMA_PORT:-8091}"
LLAMA_THREADS="${LLAMA_THREADS:-$(nproc)}"

if [ ! -s "$LLAMA_MODEL_PATH" ]; then
  echo "sidecar: downloading $(basename "$LLAMA_MODEL_PATH") (about 2.8 GB)" >&2
  curl -fL --retry 3 -o "$LLAMA_MODEL_PATH.part" "$LLAMA_MODEL_URL"
  mv "$LLAMA_MODEL_PATH.part" "$LLAMA_MODEL_PATH"
fi

/opt/llama/llama-server -m "$LLAMA_MODEL_PATH" --alias "$AIRLOCK_LOCAL_MODEL" \
  --host 127.0.0.1 --port "$LLAMA_PORT" -c 8192 --threads "$LLAMA_THREADS" --jinja &
LLAMA_PID=$!
trap 'kill "$LLAMA_PID" 2>/dev/null || true' EXIT INT TERM

i=0
until curl -fs "http://127.0.0.1:$LLAMA_PORT/health" >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 300 ] || ! kill -0 "$LLAMA_PID" 2>/dev/null; then
    echo "sidecar: llama-server did not become healthy" >&2
    exit 1
  fi
  sleep 1
done
echo "sidecar: llama-server ready on 127.0.0.1:$LLAMA_PORT" >&2

airlock serve &
AIRLOCK_PID=$!
trap 'kill "$AIRLOCK_PID" "$LLAMA_PID" 2>/dev/null || true' EXIT INT TERM
# Exit (and let the platform restart the container) if either process dies.
while kill -0 "$LLAMA_PID" 2>/dev/null && kill -0 "$AIRLOCK_PID" 2>/dev/null; do
  sleep 5
done
exit 1
