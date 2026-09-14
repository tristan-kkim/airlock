# Airlock public demo runbook

This runbook covers the hosted demo that judges use. The demo must stay free and unrestricted until the end of judging on **2026-12-15 12:00 PT**, and it should be live from **2026-11-02**, the earlier of the two judging start dates. Everything in this folder was built and smoke-tested locally on 2026-09-14. No cloud resource exists yet. In early October you create the accounts, set the secrets, and run the commands below.

## What gets deployed

```
browser ─▶ HTTPS (platform-managed) ─▶ container :8801  airlock serve  (AIRLOCK_DEMO=1)
                                        ├─ /healthz  /readyz              probes, no Host check
                                        ├─ /  /demo/*                     banner UI, 5 fictional presets, budget page
                                        └─ Airlock API (allowlisted)      input caps ─▶ rate limits ─▶ daily budget
                                               └─ per-session Airlock app: in-memory vault + audit, 30 min idle TTL
                                                    ├─ detector: Token Factory nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B  (cloud backend)
                                                    ├─ reasoning: Token Factory nvidia/Nemotron-3-Ultra-550b-a55b (fallback: Super)
                                                    └─ search: Tavily
```

- **Detector backend.** The default image (`--target demo`) uses the cloud detector adapter (`airlock/demo/cloud_detector.py`). Raw demo input reaches Nemotron-3-Nano-30B-A3B on Token Factory before redaction. That is acceptable only because presets are fictional and the banner tells visitors not to paste real data. The `sidecar` target runs llama.cpp with Nemotron-3-Nano-4B inside the container instead: detection stays on the demo server, but it needs about 4 GB RAM and CPU inference is slower (not measured on Nebius CPUs). `AIRLOCK_DETECTOR_BACKEND=cloud` is refused unless `AIRLOCK_DEMO=1`.
- **State.** Everything lives in memory: sessions, rate-limit windows, the daily budget. Run exactly **one** instance and never scale to zero. A restart resets the budget counters and drops every session, which is harmless for a demo.
- **Guards** (defaults in `deploy/demo.env`):

  | Guard | Default |
  |---|---|
  | Requests per session | 20 costly requests / 10 min |
  | Requests per IP | 20 costly requests / 10 min |
  | Input size | 4,000 characters, 64 KB body |
  | Upstream answer | 1,024 max tokens |
  | Agent run | 6 steps |
  | Concurrency | 8 costly requests at once |
  | Global daily budget (UTC) | 300 requests or 1,200 cloud calls |

  An HTTP 402 from Token Factory also exhausts the budget.
- **Recorded runs.** `airlock/demo/recorded/*.json` holds one real run of each preset, captured from the local container. A preset serves its recording, labeled "recorded run", in four cases: the budget is exhausted, the visitor is rate limited, the live run fails (including a detector that fails closed), or `AIRLOCK_DEMO_PRESETS=recorded`.

## Option A vs Option B

| | **A: Nebius Serverless Endpoint** | **B: Fly.io machine** |
|---|---|---|
| Size | `cpu-d3` `2vcpu-8gb` (smallest cpu-d3 preset), 32 GiB disk | `shared-cpu-1x`, 1 GB |
| Unit price | vCPU $0.012/h, RAM $0.0032/GiB·h, network SSD $0.071/GiB·730 h | $5.92 per 730 h ($0.00000228/s) |
| **11-02 to 12-15 (44 days, 1,056 h)** | compute $52.38 + disk $3.29 = **≈ $56** (≈ $78 with the 250 GiB default disk) | **≈ $8.67** (512 MB: ≈ $4.80) |
| 10-05 to 12-15 (71 days, 1,704 h) | ≈ $90 (or stop it until 10-30) | ≈ $14 |
| Health checks | none documented (no probe flags); watch status and logs yourself | `/readyz` HTTP check in `fly.toml` |
| Scale-to-zero | none documented, manual stop/start only | turned off on purpose (`auto_stop_machines = "off"`) |
| Client IP for limits | proxy headers not documented (**UNVERIFIED**) | `Fly-Client-IP` header |
| Hackathon fit | "deployed on Nebius AI Cloud" is encouraged, not required | "Runs on Nebius" is already met by the Token Factory runtime calls |
| Sidecar (a) possible | yes, 8 GB RAM | would need a larger, pricier VM |

Token Factory and Tavily usage is the same under both options:

- **Token Factory.** Nano-30B costs $0.06/$0.24 per 1M tokens; Ultra costs $1/$3 per 1M.
  - The local smoke test made 2 cloud calls for a chat preset and 44 for the Korean agent preset.
  - At most, the daily caps allow about 27 agent runs a day. **Estimate, not measured:** about $0.05–0.10 per agent run, or under $3 a day in the worst case.
  - Check real usage in the Token Factory console after the October smoke test.
- **Tavily.** An agent run uses about 3 searches. The free plan gives 1,000 credits a month; pay-as-you-go is $0.008 per credit.

Sources, all checked 2026-09-14:

- Nebius compute pricing: https://docs.nebius.com/compute/resources/pricing.md ("Non-GPU AMD Epyc Genoa. CPU $0.012 / 1 CPU hour", "RAM $0.0032 / 1 GiB hour", "Network SSD disk $0.071")
- Nebius Serverless billing: https://docs.nebius.com/serverless/pricing-quotas.md ("billed under Compute VM pricing")
- Nebius cpu-d3 presets: https://docs.nebius.com/compute/virtual-machines/types.md
- Nebius stop/start billing: https://docs.nebius.com/serverless/endpoints/manage.md ("Computing resources of stopped endpoints aren't charged.")
- Fly.io pricing: https://fly.io/docs/about/pricing/ ("1GB $0.00000228 … $5.92"). There is no ongoing free tier: https://fly.io/docs/about/free-trial/
- Token Factory prices: https://tokenfactory.nebius.com/api/public/models_info
- Tavily credits: https://docs.tavily.com/documentation/api-credits.md
- Other hosts considered:
  - Google Cloud Run, request-based, min = max = 1: about $5–16; https://cloud.google.com/run/pricing. Whether the free tier offsets idle time is **UNVERIFIED**.
  - Render Starter: $7/mo; https://render.com/pricing
  - Hugging Face Spaces: Docker Spaces need PRO ($9/mo), and free hardware sleeps after 48 h, which drops in-memory state.

**Recommendation: Option B (Fly.io, cloud detector backend).** It costs about one-sixth as much, has a real HTTP health check, and gives a trustworthy client IP for the per-IP limit. Airlock already satisfies "runs on Nebius" through Token Factory. Choose Option A only if you get AI Cloud credits (FACTS Q3), or if you decide the "hosted on Nebius Serverless" line is worth about $47 more. Option A is also the only one with room for the sidecar detector.

---

## Early October checklist

### 0. Before deploying (in the repo)

- [ ] Merge the S10 detector branch, then rerun `uv run pytest -q` and `uv run ruff check`.
- [ ] **Re-record the presets.** Recordings must reflect the detector you ship, and detection varies between runs: a first run of `chat-medical-en` missed a name that a re-run masked. Recording costs about 5 live runs.
  ```bash
  docker build -t airlock-demo:local .
  docker run -d --name airlock-demo-rec --env-file .env --env-file deploy/demo.env \
    -e AIRLOCK_ALLOWED_HOSTS=127.0.0.1 -p 127.0.0.1:8801:8801 airlock-demo:local
  uv run python scripts/demo/record_presets.py --base http://127.0.0.1:8801
  git diff --stat airlock/demo/recorded/     # review every "cloud_saw" before committing
  deploy/smoke_test.sh http://127.0.0.1:8801 && docker rm -f airlock-demo-rec
  ```
- [ ] Commit the recordings and tag the deployed commit (for example `demo-2026-10`).

### 1. Accounts (you, in a browser)

- [ ] **Token Factory**
  - [ ] Billing account with a card; promo credits applied (`NEBIUS-DEVPOST-GLOBAL26`).
  - [ ] **Zero Data Retention on** (account profile).
  - [ ] Credit expiry checked: Builder Program credits expire 90 days after issue. Keep a card-backed balance through 12-15.
- [ ] **Token Factory API key for the demo only** (separate from your dev key, so it can be revoked on its own).
- [ ] **Tavily API key for the demo only.** Decide whether the free 1,000 credits a month are enough or add pay-as-you-go.
- [ ] Option A: **Nebius AI Cloud**
  - [ ] Tenant and project, with the `editor` role.
  - [ ] Quota: at least 1 Compute VM and 1 VPC allocation.
  - [ ] CLI installed and a profile created:
  ```bash
  curl -sSL https://storage.eu-north1.nebius.cloud/cli/install.sh | bash && exec -l $SHELL
  nebius profile create --profile airlock --endpoint api.nebius.cloud \
    --federation-endpoint auth.nebius.com --parent-id <PROJECT_ID>     # TODO: project ID
  nebius vpc subnet list                                                 # note the subnet ID
  ```
- [ ] Option B: **Fly.io**
  - [ ] Account with a card.
  - [ ] `flyctl` installed and logged in (`fly auth login`).
  - [ ] App created with `fly apps create <unique-name>`.
  - [ ] That name set in `deploy/fly/fly.toml` for both `app` and `AIRLOCK_ALLOWED_HOSTS` (`<name>.fly.dev`).

### 2. Secrets

Only the two API keys are secret. Never put them in `deploy/demo.env`, `fly.toml`, the image, or shell history.

- Option A: `deploy/nebius/deploy.sh secrets` prompts with hidden input and stores them in MysteryBox as `airlock-demo-nebius` and `airlock-demo-tavily`. The endpoint reads them through `--env-secret`.
- Option B:
  ```bash
  read -rs NK && read -rs TK && printf 'NEBIUS_API_KEY=%s\nTAVILY_API_KEY=%s\n' "$NK" "$TK" \
    | fly secrets import --stage -a <app>; unset NK TK
  ```

### 3. Deploy

**Option A (Nebius).** Fill in the TODO block at the top of `deploy/nebius/deploy.sh` first.

```bash
deploy/nebius/deploy.sh registry          # prints REGISTRY_PATH; export it
export REGISTRY_PATH=<path> SUBNET_ID=<subnet>
deploy/nebius/deploy.sh push              # buildx linux/amd64, pushes cr.<region>.nebius.cloud/<path>/airlock-demo:<sha>
deploy/nebius/deploy.sh dry-run           # validates flags, including the 2vcpu-8gb preset and 32Gi disk
deploy/nebius/deploy.sh create            # about 5 min; ERROR NotEnoughResources after 30 min means retry or another region
deploy/nebius/deploy.sh url               # https://… managed URL
```

The first create uses `AIRLOCK_ALLOWED_HOSTS=*`, because the managed hostname is unknown until the endpoint exists and endpoints have no `update` command. To pin the host:

```bash
deploy/nebius/deploy.sh delete
PUBLIC_HOST=<host-from-url> deploy/nebius/deploy.sh create
```

Leaving it at `*` is acceptable for the demo: the Host allowlist protects local installs from DNS rebinding, and the demo has no local data.

**Option B (Fly.io):**

```bash
fly deploy --config deploy/fly/fly.toml --dockerfile Dockerfile --ha=false
fly scale count 1 -a <app>                # make sure exactly one machine exists
fly status -a <app>
```

### 4. DNS

None needed. Use the managed URL (`*.nebius…` for Option A, `<app>.fly.dev` for Option B). A custom domain adds cost and a TLS step for no judging benefit.

### 5. Smoke test (against the public URL)

```bash
deploy/smoke_test.sh https://<public-url>           # free: probes, banner, CSP, cookie, presets, 413, /docs 404
deploy/smoke_test.sh https://<public-url> --live    # ONE live preset run (chat-secrets-en)
curl -s https://ifconfig.me                          # must equal "client_ip" printed by the smoke test
```

- If `client_ip` is a proxy address instead of yours, the per-IP limit becomes one global bucket.
  - Option B: check that `AIRLOCK_DEMO_CLIENT_IP_HEADER=fly-client-ip` is set.
  - Option A: the proxy headers are **UNVERIFIED**. Set `AIRLOCK_DEMO_TRUSTED_PROXY_HOPS=1` if `X-Forwarded-For` ends with your IP; otherwise set `AIRLOCK_DEMO_IP_LIMIT=1000` and rely on the session limit and the budget. Then recreate the endpoint.
- Open the URL in a browser and check four things:
  - The banner is visible.
  - Clicking a preset shows three panes and a "live run" badge.
  - The agent preset finishes, which can take up to a minute.
  - The Chat tab works with review mode on.

### 6. Cost alarms

- **Token Factory:** no spend cap or budget alert is documented (**UNVERIFIED** that none exists). The demo's daily caps are the real cap. Keep the balance small and top up deliberately.
- **Nebius AI Cloud (Option A):** Console → Budgets → monthly budget of $70 with email alerts at 50/80/100%. A budget "does not stop or cap your usage", and its data updates every few hours (https://docs.nebius.com/signup-billing/budgets.md).
- **Fly.io (Option B):** check the billing page weekly. A spend-alert feature is **UNVERIFIED**.
- **Tavily:** check usage in the dashboard weekly.

### 7. Judge-facing URL

- [ ] Replace `TBD` in the README section "Try the demo" with the URL, and commit.
- [ ] Put the same URL in the Devpost "Try it out" field and the video description.
- [ ] Write down the deploy date, commit, option and URL in `FRICTION_LOG.md` / PLAN.

---

## Operating until 12-15

**Daily (1 minute):**

```bash
curl -s https://<url>/readyz | jq                          # status ready, recorded_presets 5/5, budget_exhausted
curl -s https://<url>/demo/status | jq .budget             # requests / cloud_calls today (UTC)
```

**Weekly:**
- Check the Token Factory balance and usage, and the Tavily credits.
- Read the logs:
  - Option A: `deploy/nebius/deploy.sh logs`
  - Option B: `fly logs -a <app>`
- Click through all five presets once.

**External uptime check.** Point any uptime checker at `https://<url>/readyz`. `/healthz` and `/readyz` skip the Host check and never spend budget.

**Budget refill.**
- **Token Factory out of credit.** Airlock sees HTTP 402 and sets `out_of_credit: true`; the budget reads exhausted, and presets serve recorded runs automatically. Top up Token Factory, then restart the container to clear the flag. Without a restart it clears at 00:00 UTC. Restart commands:
  - Option A: `nebius ai endpoint restart --id <id>`. `restart` is listed in the CLI reference; its exact flags are **UNVERIFIED**.
  - Option B: `fly apps restart <app>`
- **Daily caps too tight for real judge traffic.** Raise `AIRLOCK_DEMO_DAILY_REQUESTS` / `AIRLOCK_DEMO_DAILY_CLOUD_CALLS` after checking the cost model above.
  - Option A: edit `deploy/demo.env`, then delete and recreate the endpoint.
  - Option B: edit `fly.toml`, then run `fly deploy`.

**"Recorded run" fallback.**
- **Automatic:** budget exhausted, a rate-limited visitor, a failed live run, or a detector that fails closed. The UI says why.
- **Forced**, for example while Token Factory has an incident or the credit is gone for good: set `AIRLOCK_DEMO_PRESETS=recorded` and redeploy. Presets then never call out. Free-text requests still try live calls until the budget is exhausted, so also set `AIRLOCK_DEMO_DAILY_REQUESTS=1` to stop them.

**Incidents:**

| Symptom | Cause | Action |
|---|---|---|
| Presets show "recorded run", status `out_of_credit: true` | Token Factory balance is empty | Top up, then restart |
| Chat answers use `nemotron-3-super` | Ultra 5xx or unavailable, automatic fallback | None; check the catalog status |
| `local_detector_malformed:timeout` blocks | Token Factory latency. The 2026-09-14 smoke test saw 13–27 s detector calls for a few minutes; the timeout is 60 s | Presets fall back to recordings; wait |
| `/readyz` 503 | No `NEBIUS_API_KEY` and missing recordings | Check the secrets and the image tag |
| Everyone rate limited at once | Client IP is the proxy's | See smoke test step 5 |
| Endpoint `ERROR` / `StartFailed` (Option A) | Capacity or image pull | `deploy.sh logs`, then `create` again or change region |

**Code freeze.** Submission closes 10-30 10:00 PT. After that, redeploy only for incidents, and only from the tagged commit plus the fix.

---

## Teardown (after 2026-12-15 12:00 PT = 12-16 05:00 KST)

- [ ] Option A:
  ```bash
  deploy/nebius/deploy.sh delete
  nebius mysterybox secret delete …        # airlock-demo-nebius, airlock-demo-tavily (flags UNVERIFIED)
  nebius registry delete …                 # images are free to store, but delete them anyway (flags UNVERIFIED)
  ```
  Then remove the budget in the console.
- [ ] Option B: `fly apps destroy <app>`
- [ ] Revoke the demo Token Factory key and the demo Tavily key.
- [ ] README: change "Try the demo" to say the hosted demo has ended and link the quickstart. Remove the URL from the Devpost "Try it out" field only if the rules allow editing then; otherwise leave it.
- [ ] Record the final Token Factory, Tavily and hosting spend in PLAN.md.

## UNVERIFIED items (check in October)

1. Nebius endpoint accepts `--preset 2vcpu-8gb` and `--disk-size 32Gi`. Run `deploy.sh dry-run`. If rejected, use `4vcpu-16gb` (≈ $108 for 44 days with a 32 GiB disk) and the smallest disk it accepts.
2. Nebius managed HTTPS URL: the Host header it forwards, and whether it adds `X-Forwarded-For` / `X-Forwarded-Proto`.
3. Whether a stopped endpoint's container disk is billed.
4. Nebius `restart`, `mysterybox secret delete` and `registry delete` flags.
5. That Token Factory has no spend cap or alert, and when the Devpost promo credit expires.
6. Fly.io: whether a shared IPv4 is included at no cost for `<app>.fly.dev`, and whether `Fly-Client-IP` overwrites a value sent by the client.
7. Per-run token cost (estimate above). Measure it with the October smoke test.

## Local verification record (2026-09-14)

| Item | Result |
|---|---|
| Image | `docker build .` → `demo` target, 241 MB, non-root uid 10001. Runs with `--read-only --cap-drop ALL`; container HEALTHCHECK on `/readyz` reports healthy |
| Memory | about 40 MiB after two sessions |
| Adapter check | One direct call to Nano-30B with the detector JSON schema: 1.6 s, 5 grounded spans |
| Preset runs | 8 live runs in total: 5 presets, 2 re-runs after Token Factory slowness caused detector timeouts, 1 final re-record of `chat-medical-en` on the fixed image (4.1 s). The agent preset took 51.6 s and 44 cloud calls |
| Budget fallback, no live calls | Budget set to 1 request. Free text got 429 `demo_budget_reached`; the agent preset served its recorded run labeled `budget_exhausted`; a 5,000-character input got 413 |
| Browser | Headless Chrome rendered the banner and the JS-built preset list under the hash-based CSP |
