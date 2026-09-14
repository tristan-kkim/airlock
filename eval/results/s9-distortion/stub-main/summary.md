# Airlock eval summary

- Target: `http://127.0.0.1:8799` (airlock 2e92453 (main), AIRLOCK_GLINER=on, placeholder, dev split, stub upstream (scanner metrics only))
- Passes: 3 · cases per pass: 72 · protection level: `balanced`
- Dataset sha256: `96855eb04745e708a67efc966d6eb2d9d3226e8a4a9ff77f4a41691390c9c7ad`
- Harness version: 1.0.0 · started 2026-09-14T00:14:16.574788+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 7.8% | 0.0 pp | 7.8% to 7.8% |
| Leak rate (individual values) | 0.5% | 0.0 pp | 0.5% to 0.5% |
| Leak rate (exact-string hits only) | 1.6% | 0.0 pp | 1.6% to 1.6% |
| Canary leak rate | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Quasi-identifier re-identification rate | 28.6% | 0.0 pp | 28.6% to 28.6% |
| Identity leak (any identity item or identifying quasi set) | 9.7% | 0.0 pp | 9.7% to 9.7% |
| Gate save rate (upper bound: request-level) | 54.6% | 47.8 pp | 0.0% to 88.9% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 2.3% | 2.0 pp | 0.5% to 4.4% |
| Block rate (all) | 1.4% | 1.4 pp | 0.0% to 2.8% |
| Block rate (non-benign) | 1.6% | 1.6 pp | 0.0% to 3.1% |
| Over-block on benign | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Benign cases with any masking | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Over-redaction (must_keep strings missing) | 11.8% | 0.7 pp | 11.2% to 12.6% |
| Over-redaction (cases with any missing) | 25.4% | 1.6 pp | 23.9% to 27.1% |
| Local overhead, mean (ms) | 2214 | 2004.6 | 975 to 4526 |
| Local overhead, p95 (ms) | 5036 | 4073.8 | 2331 to 9721 |
| Client wall time, mean (ms) | 2217 | 2004.3 | 978 to 4530 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 0.0% ± 0.0 | 4.2% ± 7.2 | 7.5% ± 0.7 | 100.0% ± 0.0 | n/a |
| benign | n/a | 0.0% ± 0.0 | 5.9% ± 0.0 | n/a | 0.0% ± 0.0 |
| direct_pii | 0.0% ± 0.0 | 0.0% ± 0.0 | 4.3% ± 0.0 | n/a | n/a |
| finance | 0.0% ± 0.0 | 0.0% ± 0.0 | 24.0% ± 0.0 | n/a | n/a |
| health | 12.5% ± 0.0 | 8.3% ± 7.2 | 23.1% ± 1.6 | 50.0% ± 43.3 | n/a |
| intent_leak_search | 0.0% ± 0.0 | 0.0% ± 0.0 | 42.4% ± 10.5 | n/a | n/a |
| quasi_identifier | 50.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |
| secrets_in_code | 0.0% ± 0.0 | 0.0% ± 0.0 | 4.8% ± 0.0 | n/a | n/a |
| vault_terms | 0.0% ± 0.0 | 0.0% ± 0.0 | 4.3% ± 0.0 | n/a | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 12.5% ± 0.0 | 0.9% ± 1.6 | 13.1% ± 1.4 |
| ko | 3.1% ± 0.0 | 1.9% ± 1.6 | 10.6% ± 0.1 |

## Cases that leaked in any pass

5 case(s) leaked in every pass; 0 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| hlt-en-08 | health | en | 3/3 | `1953-01-15`: 3, exact |
| qid-en-04 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-06 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-10 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-14 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|
| ben-en-07 | en | 0/3 | 0/3 | `free-threaded` (3) |

## Value outcomes (summed over passes)

- `detected_removed`: 413
- `removed_unattributed`: 182
- `gate_saved`: 11
- `missed_leaked`: 3
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
