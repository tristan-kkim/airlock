# Airlock eval summary

- Target: `http://127.0.0.1:8800` (airlock feat/s12-quality, AIRLOCK_GLINER=on, placeholder, dev split, stub upstream (scanner metrics only))
- Passes: 2 · cases per pass: 72 · protection level: `balanced`
- Dataset sha256: `96855eb04745e708a67efc966d6eb2d9d3226e8a4a9ff77f4a41691390c9c7ad`
- Harness version: 1.0.0 · started 2026-09-15T02:18:24.247946+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 4.7% | 0.0 pp | 4.7% to 4.7% |
| Leak rate (individual values) | 0.5% | 0.0 pp | 0.5% to 0.5% |
| Leak rate (exact-string hits only) | 0.8% | 1.1 pp | 0.0% to 1.6% |
| Canary leak rate | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Quasi-identifier re-identification rate | 14.3% | 0.0 pp | 14.3% to 14.3% |
| Identity leak (any identity item or identifying quasi set) | 4.8% | 0.0 pp | 4.8% to 4.8% |
| Gate save rate (upper bound: request-level) | 45.8% | 64.8 pp | 0.0% to 91.7% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 3.2% | 3.8 pp | 0.5% to 5.9% |
| Block rate (all) | 1.4% | 2.0 pp | 0.0% to 2.8% |
| Block rate (non-benign) | 1.6% | 2.2 pp | 0.0% to 3.1% |
| Over-block on benign | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Benign cases with any masking | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Over-redaction (must_keep strings missing) | 5.0% | 1.3 pp | 4.1% to 6.0% |
| Over-redaction (cases with any missing) | 11.3% | 2.2 pp | 9.7% to 12.9% |
| Local overhead, mean (ms) | 3512 | 23.1 | 3496 to 3528 |
| Local overhead, p95 (ms) | 8404 | 527.8 | 8031 to 8777 |
| Client wall time, mean (ms) | 3517 | 22.3 | 3501 to 3532 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 6.2% ± 8.8 | 6.2% ± 8.8 | 4.2% ± 5.9 | 83.3% ± 0.0 | n/a |
| benign | n/a | 0.0% ± 0.0 | 5.9% ± 0.0 | n/a | 0.0% ± 0.0 |
| direct_pii | 0.0% ± 0.0 | 6.2% ± 8.8 | 0.0% ± 0.0 | 100.0% ± 0.0 | n/a |
| finance | 6.2% ± 8.8 | 0.0% ± 0.0 | 2.0% ± 2.8 | 0.0% ± 0.0 | n/a |
| health | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |
| intent_leak_search | 0.0% ± 0.0 | 0.0% ± 0.0 | 50.0% ± 19.3 | n/a | n/a |
| quasi_identifier | 25.0% ± 0.0 | 0.0% ± 0.0 | 2.9% ± 4.2 | n/a | n/a |
| secrets_in_code | 0.0% ± 0.0 | 0.0% ± 0.0 | 2.4% ± 3.4 | n/a | n/a |
| vault_terms | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 6.2% ± 0.0 | 2.8% ± 3.9 | 6.7% ± 2.8 |
| ko | 3.1% ± 0.0 | 0.0% ± 0.0 | 3.5% ± 0.0 |

## Pass independence

- Byte-identical outbound payloads in all 2 passes: 44 of 70 cases (62.9%)
- Detect time p50 by pass: 2,916 / 3,381 ms
- Detector temperature: 0.6

## Cases that leaked in any pass

2 case(s) leaked in every pass; 2 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| qid-en-05 | quasi_identifier | en | 2/2 | quasi-identifier group ≥k: 2 |
| qid-en-06 | quasi_identifier | en | 2/2 | quasi-identifier group ≥k: 2 |
| adv-ko-08 | adversarial | ko | 1/2 | `731521-1385835`: 1, digits |
| fin-ko-10 | finance | ko | 1/2 | `권소율`: 1, exact |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|
| ben-en-07 | en | 0/2 | 0/2 | `free-threaded` (2) |

## Value outcomes (summed over passes)

- `detected_removed`: 0
- `removed_unattributed`: 393
- `gate_saved`: 11
- `missed_leaked`: 2
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
