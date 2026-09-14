#!/usr/bin/env bash
# Option A: Airlock demo on a Nebius AI Cloud Serverless Endpoint (cpu-d3, 2vcpu-8gb, managed HTTPS).
#
# Run step by step in October, from the repo root, after `nebius profile create` (DEMO_RUNBOOK.md):
#
#   deploy/nebius/deploy.sh registry     # once: create the Container Registry, print its path
#   deploy/nebius/deploy.sh push         # build linux/amd64 and push
#   deploy/nebius/deploy.sh secrets      # once: store NEBIUS_API_KEY and TAVILY_API_KEY (prompts)
#   deploy/nebius/deploy.sh dry-run      # validate the endpoint request without creating it
#   deploy/nebius/deploy.sh create       # create the endpoint (about 5 minutes)
#   deploy/nebius/deploy.sh url | logs | stop | start | delete
#
# CLI syntax checked against docs.nebius.com (CLI reference "Auto generated on 14-Sep-2026").
# Things the docs do not state are marked UNVERIFIED in DEMO_RUNBOOK.md.
set -euo pipefail

# ---- TODO(October): fill these in (or export them before running) -----------------------------
REGION="${REGION:-eu-north1}"                 # TODO: region of the project (Serverless AI regions: eu-north1, eu-west1, us-central1, ...)
REGISTRY_PATH="${REGISTRY_PATH:-}"            # TODO: output of `deploy.sh registry`
SUBNET_ID="${SUBNET_ID:-}"                    # TODO: `nebius vpc subnet list` (required if the project has several subnets)
PUBLIC_HOST="${PUBLIC_HOST:-*}"               # TODO: host of the managed URL after the first create, then recreate
ENDPOINT_NAME="${ENDPOINT_NAME:-airlock-demo}"
TAG="${TAG:-$(git rev-parse --short HEAD)}"
# ------------------------------------------------------------------------------------------------

IMAGE="cr.${REGION}.nebius.cloud/${REGISTRY_PATH}/airlock-demo:${TAG}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

need() { [[ -n "${!1}" ]] || { echo "set $1 first (see the TODO block in $0)" >&2; exit 2; }; }

endpoint_id() {
  nebius ai endpoint get-by-name --name "$ENDPOINT_NAME" --format jsonpath='{.metadata.id}'
}

create_args() {  # fills the global ARGS array (bash 3.2 compatible: macOS has no mapfile)
  ARGS=(
    --name "$ENDPOINT_NAME"
    --image "$IMAGE"
    --container-port 8801
    --platform cpu-d3
    --preset 2vcpu-8gb          # UNVERIFIED for endpoints: the quickstart uses 4vcpu-16gb
    --disk-size 32Gi            # default 250Gi costs about $22 more over the judging window
    --auth none                 # judges need free, unrestricted access
    --env "AIRLOCK_ALLOWED_HOSTS=${PUBLIC_HOST}"
    --env-secret "NEBIUS_API_KEY=airlock-demo-nebius"
    --env-secret "TAVILY_API_KEY=airlock-demo-tavily"
  )
  if [[ -n "$SUBNET_ID" ]]; then ARGS+=(--subnet-id "$SUBNET_ID"); fi
  while IFS= read -r line; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    ARGS+=(--env "$line")
  done < "$ROOT/deploy/demo.env"
}

store_secret() {  # name key: read the value without echo, never from argv history
  local name="$1" key="$2" value payload
  read -r -s -p "$key (input hidden): " value; echo
  payload="$(jq -cn --arg k "$key" --arg v "$value" '[{key: $k, string_value: $v}]')"
  nebius mysterybox secret create --name "$name" \
    --description "Airlock demo $key" --secret-version-payload "$payload" >/dev/null
  echo "stored $key in secret $name"
}

case "${1:-}" in
  registry)
    nebius registry create --name airlock --format json | jq -r ".metadata.id" | cut -d- -f 2
    ;;
  push)
    need REGISTRY_PATH
    nebius iam get-access-token | docker login "cr.${REGION}.nebius.cloud" --username iam --password-stdin
    docker buildx build --platform linux/amd64 --target demo -t "$IMAGE" --push "$ROOT"
    echo "pushed $IMAGE"
    ;;
  secrets)
    store_secret airlock-demo-nebius NEBIUS_API_KEY
    store_secret airlock-demo-tavily TAVILY_API_KEY
    ;;
  dry-run | create)
    need REGISTRY_PATH
    create_args
    if [[ "$1" == dry-run ]]; then ARGS+=(--dry-run); fi
    nebius ai endpoint create "${ARGS[@]}"
    ;;
  url)
    nebius ai endpoint get "$(endpoint_id)" --format json \
      | jq -r '.status.public_endpoints[] | select(startswith("https://"))' | head -1
    ;;
  logs) nebius ai endpoint logs "$(endpoint_id)" --follow ;;
  stop) nebius ai endpoint stop --id "$(endpoint_id)" ;;
  start) nebius ai endpoint start --id "$(endpoint_id)" ;;
  delete) nebius ai endpoint delete --id "$(endpoint_id)" ;;
  *)
    sed -n '2,14p' "$0"
    exit 2
    ;;
esac
