#!/usr/bin/env bash
# Smoke test for a running Airlock demo. Free by default; `--live` adds ONE live preset run.
#
#   deploy/smoke_test.sh http://127.0.0.1:8801
#   deploy/smoke_test.sh https://<public-url> --live
set -euo pipefail

BASE="${1:?usage: smoke_test.sh BASE_URL [--live]}"
LIVE="${2:-}"
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT
fail=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi; }
get() { curl -fsS -b "$JAR" -c "$JAR" "$BASE$1"; }

check "healthz demo=true"          '[[ "$(get /healthz | jq -r .demo)" == true ]]'
check "readyz ready, 5/5 recorded" '[[ "$(get /readyz | jq -r ".status + \" \" + .recorded_presets")" == "ready 5/5" ]]'
check "readyz live configured"     '[[ "$(get /readyz | jq -r .live_configured)" == true ]]'
page="$(get /)"
check "banner text"                'grep -qF "Don'"'"'t paste real personal data" <<<"$page"'
check "quickstart link"            'grep -qF "github.com/tristan-kkim/airlock#quickstart" <<<"$page"'
headers="$(curl -fsS -D - -o /dev/null "$BASE/")"
check "CSP with script hashes"     'grep -qi "^content-security-policy: .*script-src .sha256-" <<<"$headers"'
check "x-frame-options DENY"       'grep -qi "^x-frame-options: DENY" <<<"$headers"'
check "session cookie HttpOnly"    'grep -qi "^set-cookie: airlock_demo_sid=.*HttpOnly" <<<"$headers"'
check "5 presets listed"           '[[ "$(get /demo/presets | jq ".presets | length")" == 5 ]]'
check "OpenAPI docs hidden (404)"  '[[ "$(curl -s -o /dev/null -w "%{http_code}" "$BASE/docs")" == 404 ]]'
big="$(jq -cn --arg t "$(head -c 5000 /dev/zero | tr '\0' x)" '{messages: [{role: "user", content: $t}]}')"
check "input cap (413)"            '[[ "$(curl -s -o /dev/null -w "%{http_code}" -H "content-type: application/json" -d "$big" "$BASE/v1/chat/completions")" == 413 ]]'
status="$(get /demo/status)"
echo "info client_ip seen by server: $(jq -r .client_ip <<<"$status")  (compare: curl -s https://ifconfig.me)"
echo "info budget: $(jq -c .budget <<<"$status")"

if [[ "$LIVE" == "--live" ]]; then
  run="$(curl -fsS -b "$JAR" -c "$JAR" -H 'content-type: application/json' -d '{}' "$BASE/demo/presets/chat-secrets-en/run")"
  echo "info live preset: source=$(jq -r .source <<<"$run") gate=$(jq -r .gate.decision <<<"$run") detect_ms=$(jq -r .timings_ms.detect <<<"$run")"
  check "live preset ran live"     '[[ "$(jq -r .source <<<"$run")" == live ]]'
  check "secret never sent"        '! grep -qF "hunter22" <<<"$(jq -c .cloud_saw <<<"$run")"'
fi
exit $fail
