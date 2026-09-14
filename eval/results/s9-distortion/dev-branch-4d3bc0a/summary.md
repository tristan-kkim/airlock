# Airlock eval summary

- Target: `http://127.0.0.1:8799` (airlock 4d3bc0a (feat/distortion), AIRLOCK_GLINER=on, placeholder, dev split)
- Passes: 1 · cases per pass: 72 · protection level: `balanced`
- Dataset sha256: `96855eb04745e708a67efc966d6eb2d9d3226e8a4a9ff77f4a41691390c9c7ad`
- Harness version: 1.0.0 · started 2026-09-13T23:34:25.442723+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 10.9% | 0.0 pp | 10.9% to 10.9% |
| Leak rate (individual values) | 1.0% | 0.0 pp | 1.0% to 1.0% |
| Leak rate (exact-string hits only) | 3.1% | 0.0 pp | 3.1% to 3.1% |
| Canary leak rate | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Quasi-identifier re-identification rate | 35.7% | 0.0 pp | 35.7% to 35.7% |
| Identity leak (any identity item or identifying quasi set) | 12.9% | 0.0 pp | 12.9% to 12.9% |
| Gate save rate (upper bound: request-level) | 75.0% | 0.0 pp | 75.0% to 75.0% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 3.9% | 0.0 pp | 3.9% to 3.9% |
| Block rate (all) | 2.8% | 0.0 pp | 2.8% to 2.8% |
| Block rate (non-benign) | 3.1% | 0.0 pp | 3.1% to 3.1% |
| Over-block on benign | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Benign cases with any masking | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Over-redaction (must_keep strings missing) | 9.0% | 0.0 pp | 9.0% to 9.0% |
| Over-redaction (cases with any missing) | 21.4% | 0.0 pp | 21.4% to 21.4% |
| Local overhead, mean (ms) | 4724 | 0.0 | 4724 to 4724 |
| Local overhead, p95 (ms) | 8950 | 0.0 | 8950 to 8950 |
| Client wall time, mean (ms) | 8337 | 0.0 | 8337 to 8337 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 0.0% ± 0.0 | 0.0% ± 0.0 | 7.1% ± 0.0 | n/a | n/a |
| benign | n/a | 0.0% ± 0.0 | 5.9% ± 0.0 | n/a | 0.0% ± 0.0 |
| direct_pii | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |
| finance | 12.5% ± 0.0 | 0.0% ± 0.0 | 4.0% ± 0.0 | 0.0% ± 0.0 | n/a |
| health | 12.5% ± 0.0 | 0.0% ± 0.0 | 10.0% ± 0.0 | 0.0% ± 0.0 | n/a |
| intent_leak_search | 0.0% ± 0.0 | 12.5% ± 0.0 | 70.0% ± 0.0 | 100.0% ± 0.0 | n/a |
| quasi_identifier | 62.5% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |
| secrets_in_code | 0.0% ± 0.0 | 0.0% ± 0.0 | 4.8% ± 0.0 | n/a | n/a |
| vault_terms | 0.0% ± 0.0 | 12.5% ± 0.0 | 10.0% ± 0.0 | 100.0% ± 0.0 | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 18.8% ± 0.0 | 2.8% ± 0.0 | 11.0% ± 0.0 |
| ko | 3.1% ± 0.0 | 2.8% ± 0.0 | 7.1% ± 0.0 |

## Cases that leaked in any pass

7 case(s) leaked in every pass; 0 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| fin-en-05 | finance | en | 1/1 | `orbit cactus harbor hazel hazel tundra meadow dynamo ember anchor dynamo velvet`: 1, exact |
| hlt-en-08 | health | en | 1/1 | `1953-01-15`: 1, exact |
| qid-en-04 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-05 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-06 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-10 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-14 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|
| ben-en-07 | en | 0/1 | 0/1 | `free-threaded` (1) |

## Value outcomes (summed over passes)

- `detected_removed`: 147
- `removed_unattributed`: 48
- `gate_saved`: 6
- `missed_leaked`: 2
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
