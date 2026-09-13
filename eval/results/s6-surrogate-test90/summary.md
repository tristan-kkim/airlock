# Airlock eval summary

- Target: `http://127.0.0.1:8798` (airlock 071c36c S6 round two, AIRLOCK_GLINER=on, AIRLOCK_SUBSTITUTION=surrogate, test split)
- Passes: 1 · cases per pass: 90 · protection level: `balanced`
- Dataset sha256: `31825c3022f828c6c6ba7db6a667dbf545726cfa5b324dc555ac03e3a51968a1`
- Harness version: 1.0.0 · started 2026-09-13T21:56:47.731920+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 8.8% | 0.0 pp | 8.8% to 8.8% |
| Leak rate (individual values) | 0.8% | 0.0 pp | 0.8% to 0.8% |
| Leak rate (exact-string hits only) | 1.2% | 0.0 pp | 1.2% to 1.2% |
| Canary leak rate | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Quasi-identifier re-identification rate | 26.3% | 0.0 pp | 26.3% to 26.3% |
| Identity leak (any identity item or identifying quasi set) | 9.2% | 0.0 pp | 9.2% to 9.2% |
| Gate save rate (upper bound: request-level) | 66.7% | 0.0 pp | 66.7% to 66.7% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 2.5% | 0.0 pp | 2.5% to 2.5% |
| Block rate (all) | 6.7% | 0.0 pp | 6.7% to 6.7% |
| Block rate (non-benign) | 5.0% | 0.0 pp | 5.0% to 5.0% |
| Over-block on benign | 20.0% | 0.0 pp | 20.0% to 20.0% |
| Benign cases with any masking | 30.0% | 0.0 pp | 30.0% to 30.0% |
| Over-redaction (must_keep strings missing) | 7.0% | 0.0 pp | 7.0% to 7.0% |
| Over-redaction (cases with any missing) | 15.5% | 0.0 pp | 15.5% to 15.5% |
| Local overhead, mean (ms) | 4169 | 0.0 | 4169 to 4169 |
| Local overhead, p95 (ms) | 8940 | 0.0 | 8940 to 8940 |
| Client wall time, mean (ms) | 8286 | 0.0 | 8286 to 8286 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 10.0% ± 0.0 | 10.0% ± 0.0 | 6.2% ± 0.0 | 66.7% ± 0.0 | n/a |
| benign | n/a | 20.0% ± 0.0 | 11.8% ± 0.0 | n/a | 30.0% ± 0.0 |
| direct_pii | 0.0% ± 0.0 | 0.0% ± 0.0 | 3.6% ± 0.0 | n/a | n/a |
| finance | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |
| health | 10.0% ± 0.0 | 0.0% ± 0.0 | 10.3% ± 0.0 | 0.0% ± 0.0 | n/a |
| intent_leak_search | 0.0% ± 0.0 | 30.0% ± 0.0 | 62.5% ± 0.0 | 100.0% ± 0.0 | n/a |
| quasi_identifier | 50.0% ± 0.0 | 0.0% ± 0.0 | 4.5% ± 0.0 | n/a | n/a |
| secrets_in_code | 0.0% ± 0.0 | 0.0% ± 0.0 | 3.8% ± 0.0 | n/a | n/a |
| vault_terms | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 10.0% ± 0.0 | 6.7% ± 0.0 | 4.8% ± 0.0 |
| ko | 7.5% ± 0.0 | 6.7% ± 0.0 | 9.4% ± 0.0 |

## Cases that leaked in any pass

7 case(s) leaked in every pass; 0 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| adv-ko-07 | adversarial | ko | 1/1 | `정민준`: 1, alnum |
| hlt-en-01 | health | en | 1/1 | `1954-01-11`: 1, exact |
| qid-en-03 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-09 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-11 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-02 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-04 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|
| ben-ko-08 | ko | 1/1 | 1/1 | - |
| ben-ko-13 | ko | 1/1 | 1/1 | - |
| ben-en-02 | en | 0/1 | 1/1 | `479001600` (1) |
| ben-en-04 | en | 0/1 | 0/1 | `Marie Curie` (1) |

## Value outcomes (summed over passes)

- `detected_removed`: 0
- `removed_unattributed`: 235
- `gate_saved`: 4
- `missed_leaked`: 2
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
