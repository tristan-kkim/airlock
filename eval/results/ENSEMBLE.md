# GLiNER-PII ensemble: A/B evaluation

Generated from the run directories with `uv run eval/ensemble_split.py eval/results/ensemble-A-head eval/results/ensemble-B-gliner eval/results/ensemble-B1-gliner`, plus `uv run eval/attack.py --rescore <run>` on each.

## Setup

| Run | Commit | Detector |
|---|---|---|
| `ensemble-A-head` | 685d3c7 | HEAD detector (regex/entropy/vault, Korean rules, Nano-4B, verification) with `AIRLOCK_GLINER=off`. Disabled mode behaves like `main` (tested). |
| `ensemble-B-gliner` | 685d3c7 | + GLiNER-PII ensemble: threshold 0.4, CPU, adjudication on, every label may be adjudicated, Korean names of 2-4 syllables |
| `ensemble-B1-gliner` | 79e9891 | Variant 1, now the default: `AIRLOCK_GLINER_AGREEMENT_ONLY=city,date_of_birth`, `AIRLOCK_GLINER_KO_NAME_MIN_SYLLABLES=3` |

- 243 cases, 1 pass each, `--reset-vault`, `AIRLOCK_VAULT_PATH=:memory:`, `AIRLOCK_AUDIT_DB=:memory:`, protection level `balanced`, review off, audit HMAC key from the worktree's `.airlock/`. Upstream: Nemotron 3 Ultra on Token Factory. Local: Nemotron-3-Nano-4B Q4_K_M with the `scripts/local_model/serve.sh` flags (`-np 1`, `--cache-ram 0`); GLiNER weights `nvidia/gliner-PII` from a local directory.
- **Dev/test split.** Seeded (20260914) and stratified by category and language: 72 dev and 171 test cases (`ensemble-split.json`). The label set, shape rules, threshold, device and adjudication prompt were chosen by looking at dev cases only. The threshold is 0.4 because raw GLiNER scores on dev barely separate true from false spans anywhere between 0.3 and 0.6. The variant was chosen on dev numbers. **Quote the test column.**
- **Disclosure.** Before variant 1 was chosen, the list of blocked requests over all 243 cases of run B (case ids and gate reason codes, no texts) was printed while checking for errors. The variant itself came from dev adjudication precision: GLiNER-only cities were wrong in 4 of 8 accepted spans, the only benign dev false positive was a `2024-01-01` "birth date", and 2 of 3 two-syllable Hangul "names" were common words. No second variant was run.
- One pass per config, so Nano's sampling noise (temperature 0.6) is not averaged out. Nano malfunctions (repetition, length, timeout) blocked 3 requests in A and 4 to 5 in B and B1; that is detector noise, not the ensemble.

Split: seed 20260914, stratified by (category, lang), round(30%) of each stratum to dev; 72 dev and 171 test cases (`ensemble-split.json`). Thresholds and policy were chosen on dev only; quote the test column. One pass per config, so no standard deviation.

## test (70%)

| Metric | ensemble-A-head | ensemble-B-gliner | ensemble-B1-gliner |
|---|---:|---:|---:|
| Leak rate | 26.3% | 8.6% | 11.2% |
| Canary leak | 14.1% | 2.0% | 1.0% |
| Quasi re-id | 38.9% | 19.4% | 27.8% |
| Benign masked | 0.0% | 42.1% | 21.1% |
| Over-redaction | 14.1% | 15.4% | 15.5% |
| Block rate | 1.8% | 5.8% | 5.8% |
| Over-block benign | 0.0% | 15.8% | 10.5% |
| Leak ko | 26.0% | 11.7% | 13.0% |
| Leak en | 26.7% | 5.3% | 9.3% |
| Benign masked ko | 0.0% | 44.4% | 33.3% |
| Benign masked en | 0.0% | 40.0% | 10.0% |
| Local overhead p50 | 9920 ms | 6794 ms | 4384 ms |
| Local overhead p95 | 25113 ms | 19460 ms | 9983 ms |
| Cases / errors | 171 / 0 | 171 / 0 | 171 / 0 |

## dev (30%)

| Metric | ensemble-A-head | ensemble-B-gliner | ensemble-B1-gliner |
|---|---:|---:|---:|
| Leak rate | 32.8% | 7.8% | 10.9% |
| Canary leak | 17.4% | 0.0% | 0.0% |
| Quasi re-id | 50.0% | 35.7% | 35.7% |
| Benign masked | 0.0% | 12.5% | 0.0% |
| Over-redaction | 17.0% | 13.0% | 16.2% |
| Block rate | 0.0% | 5.6% | 2.8% |
| Over-block benign | 0.0% | 0.0% | 0.0% |
| Leak ko | 25.0% | 6.2% | 6.2% |
| Leak en | 40.6% | 9.4% | 15.6% |
| Benign masked ko | 0.0% | 0.0% | 0.0% |
| Benign masked en | 0.0% | 25.0% | 0.0% |
| Local overhead p50 | 11726 ms | 7360 ms | 4905 ms |
| Local overhead p95 | 22829 ms | 21599 ms | 9335 ms |
| Cases / errors | 72 / 0 | 72 / 0 | 72 / 0 |

## all

| Metric | ensemble-A-head | ensemble-B-gliner | ensemble-B1-gliner |
|---|---:|---:|---:|
| Leak rate | 28.2% | 8.3% | 11.1% |
| Canary leak | 15.2% | 1.4% | 0.7% |
| Quasi re-id | 42.0% | 24.0% | 30.0% |
| Benign masked | 0.0% | 33.3% | 14.8% |
| Over-redaction | 15.0% | 14.7% | 15.7% |
| Block rate | 1.2% | 5.8% | 4.9% |
| Over-block benign | 0.0% | 11.1% | 7.4% |
| Leak ko | 25.7% | 10.1% | 11.0% |
| Leak en | 30.8% | 6.5% | 11.2% |
| Benign masked ko | 0.0% | 30.8% | 23.1% |
| Benign masked en | 0.0% | 35.7% | 7.1% |
| Local overhead p50 | 10246 ms | 6938 ms | 4583 ms |
| Local overhead p95 | 24893 ms | 20159 ms | 9794 ms |
| Cases / errors | 243 / 0 | 243 / 0 | 243 / 0 |

## Ensemble counters: ensemble-B-gliner (all chat requests)

```
{
 "requests": 205,
 "gliner_ms_p50": 455.0,
 "gliner_ms_p95": 651.8,
 "adjudication_ms_p50_all": 0.0,
 "adjudication_ms_p95_all": 3630.7999999999984,
 "adjudication_ms_p50_when_called": 2195.5,
 "adjudication_ms_p95_when_called": 4240.099999999997,
 "requests_with_adjudication": 78,
 "adjudication_calls": 78,
 "candidates": 104,
 "adjudicated_yes": 94,
 "adjudicated_no": 10
}
```

## Ensemble counters: ensemble-B1-gliner (all chat requests)

```
{
 "requests": 206,
 "gliner_ms_p50": 456.5,
 "gliner_ms_p95": 635.0,
 "adjudication_ms_p50_all": 0.0,
 "adjudication_ms_p95_all": 1782.5,
 "adjudication_ms_p50_when_called": 1705.5,
 "adjudication_ms_p95_when_called": 2174.85,
 "requests_with_adjudication": 58,
 "adjudication_calls": 58,
 "candidates": 69,
 "adjudicated_yes": 64,
 "adjudicated_no": 5
}
```

## Latency

**Cross-run overhead is contaminated.** Other local models shared this M3 Pro (18 GB) during the runs, and the load fell over time: run A came first and shows the highest local overhead although it does the least work. Do not read the overhead rows above as the ensemble's cost.

Measured inside each request (`meta.detector`), run B1, 206 chat requests:

| Stage | p50 | p95 | Notes |
|---|---:|---:|---|
| GLiNER-PII inference (CPU, 2 label prompts per text) | 457 ms | 635 ms | runs in parallel with the Nano detector, so it adds at most this to wall time |
| Nano adjudication, requests that needed it (58 of 206, 28%) | 1706 ms | 2175 ms | one call per request |
| Nano adjudication, all requests | 0 ms | 1783 ms | requests without GLiNER-only candidates pay nothing |

In run B (every label adjudicated), 78 of 205 requests were adjudicated, at p50 2196 ms and p95 4240 ms. With `-np 1`, the adjudication prompt also evicts the detector prompt from the slot cache, so the next detector call re-reads its ~970-token system prompt. A second slot (`-np 2`) would avoid that, at the cost of context per slot.

Device: GLiNER alone was faster on MPS (p50 324 ms vs 456 ms on CPU over 30 eval texts). Inside Airlock, while Nano decodes on Metal, CPU won (61 dev requests: MPS p50 1165 / p95 1752 ms, CPU p50 467 / p95 649 ms). The default is CPU.

## Adversary inference (`eval/attack.py`, 1 attack pass over all 243 cases, Nemotron 3 Ultra, reasoning none)

| Run | Values recovered | Full or partial | Canaries recovered | Quasi re-id (attacker) | Intent inferred |
|---|---:|---:|---:|---:|---:|
| A (GLiNER off) | 9.9% | 11.5% | 15.2% | 42.0% | 44.4% |
| B | 0.6% | 2.4% | 1.4% | 30.0% | 14.8% |
| B1 (default) | 1.0% | 3.7% | 0.7% | 34.0% | 33.3% |

Intent inference also falls when a search is blocked (nothing is sent), so part of B's intent number comes from its blocks.

## Reference: single systems (`COMPARISON.md`, all 243 cases, 3 passes)

| System | Leak | Canary | Quasi re-id | Benign masked | Over-redaction |
|---|---:|---:|---:|---:|---:|
| regex only | 94.0% | 87.6% | 98.0% | 7.4% | 0.4% |
| Presidio + ko/en spaCy | 76.9% | 84.1% | 50.0% | 66.7% | 16.7% |
| NVIDIA GLiNER-PII alone | 19.0% | 12.4% | 10.0% | 59.3% | 14.1% |

## Reading this

- On the test split, the ensemble cuts the leak rate from 26.3% to 11.2% (B1) or 8.6% (B), and canary leaks from 14.1% to 1.0% (B1). Over all cases, the attacker's full value recovery falls from 9.9% to about 1%.
- It is not free. B1 masks something in 4 of the 19 benign test cases (21.1%), and 2 of those are blocked (10.5%): search queries where GLiNER flagged an organization that the local rewrite kept, so the gate stopped the request. HEAD masks none. This is far below GLiNER alone (59.3% masked over all cases), but it is a real utility cost, and 19 cases is a small sample. Over-redaction of `must_keep` strings does not change (14.1% vs 15.5%).
- Quasi re-identification improves less than value leaks (38.9% to 27.8% on test for B1). GLiNER has no label for roles or uniqueness cues, and B1 no longer takes GLiNER-only cities.
- Korean test cases: leak 26.0% to 13.0% (B1); 3 of 9 Korean benign test cases get a mask.
