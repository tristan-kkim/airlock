# Airlock eval summary

- Target: `http://127.0.0.1:8800` (airlock 4236df9 (main), AIRLOCK_GLINER=on, placeholder, dev split)
- Passes: 1 · cases per pass: 72 · protection level: `balanced`
- Dataset sha256: `96855eb04745e708a67efc966d6eb2d9d3226e8a4a9ff77f4a41691390c9c7ad`
- Harness version: 1.0.0 · started 2026-09-14T14:06:43.357884+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 7.8% | 0.0 pp | 7.8% to 7.8% |
| Leak rate (individual values) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Leak rate (exact-string hits only) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Canary leak rate | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Quasi-identifier re-identification rate | 35.7% | 0.0 pp | 35.7% to 35.7% |
| Identity leak (any identity item or identifying quasi set) | 8.1% | 0.0 pp | 8.1% to 8.1% |
| Gate save rate (upper bound: request-level) | 100.0% | 0.0 pp | 100.0% to 100.0% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 3.0% | 0.0 pp | 3.0% to 3.0% |
| Block rate (all) | 2.8% | 0.0 pp | 2.8% to 2.8% |
| Block rate (non-benign) | 3.1% | 0.0 pp | 3.1% to 3.1% |
| Over-block on benign | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Benign cases with any masking | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Over-redaction (must_keep strings missing) | 6.6% | 0.0 pp | 6.6% to 6.6% |
| Over-redaction (cases with any missing) | 15.7% | 0.0 pp | 15.7% to 15.7% |
| Local overhead, mean (ms) | 4657 | 0.0 | 4657 to 4657 |
| Local overhead, p95 (ms) | 9238 | 0.0 | 9238 to 9238 |
| Client wall time, mean (ms) | 8176 | 0.0 | 8176 to 8176 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 0.0% ± 0.0 | 0.0% ± 0.0 | 7.1% ± 0.0 | n/a | n/a |
| benign | n/a | 0.0% ± 0.0 | 5.9% ± 0.0 | n/a | 0.0% ± 0.0 |
| direct_pii | 0.0% ± 0.0 | 12.5% ± 0.0 | 0.0% ± 0.0 | 100.0% ± 0.0 | n/a |
| finance | 0.0% ± 0.0 | 0.0% ± 0.0 | 8.0% ± 0.0 | n/a | n/a |
| health | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |
| intent_leak_search | 0.0% ± 0.0 | 0.0% ± 0.0 | 36.4% ± 0.0 | n/a | n/a |
| quasi_identifier | 62.5% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |
| secrets_in_code | 0.0% ± 0.0 | 12.5% ± 0.0 | 15.8% ± 0.0 | 100.0% ± 0.0 | n/a |
| vault_terms | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 12.5% ± 0.0 | 0.0% ± 0.0 | 5.9% ± 0.0 |
| ko | 3.1% ± 0.0 | 5.6% ± 0.0 | 7.4% ± 0.0 |

## Cases that leaked in any pass

5 case(s) leaked in every pass; 0 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
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
- `removed_unattributed`: 50
- `gate_saved`: 6
- `missed_leaked`: 0
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
