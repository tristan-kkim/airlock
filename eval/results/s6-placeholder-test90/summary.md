# Airlock eval summary

- Target: `http://127.0.0.1:8798` (airlock 071c36c S6 round two, AIRLOCK_GLINER=on, AIRLOCK_SUBSTITUTION=placeholder, test split)
- Passes: 1 · cases per pass: 90 · protection level: `balanced`
- Dataset sha256: `31825c3022f828c6c6ba7db6a667dbf545726cfa5b324dc555ac03e3a51968a1`
- Harness version: 1.0.0 · started 2026-09-13T21:33:32.682368+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 8.8% | 0.0 pp | 8.8% to 8.8% |
| Leak rate (individual values) | 1.2% | 0.0 pp | 1.2% to 1.2% |
| Leak rate (exact-string hits only) | 1.2% | 0.0 pp | 1.2% to 1.2% |
| Canary leak rate | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Quasi-identifier re-identification rate | 21.1% | 0.0 pp | 21.1% to 21.1% |
| Identity leak (any identity item or identifying quasi set) | 9.2% | 0.0 pp | 9.2% to 9.2% |
| Gate save rate (upper bound: request-level) | 66.7% | 0.0 pp | 66.7% to 66.7% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 3.7% | 0.0 pp | 3.7% to 3.7% |
| Block rate (all) | 7.8% | 0.0 pp | 7.8% to 7.8% |
| Block rate (non-benign) | 6.2% | 0.0 pp | 6.2% to 6.2% |
| Over-block on benign | 20.0% | 0.0 pp | 20.0% to 20.0% |
| Benign cases with any masking | 30.0% | 0.0 pp | 30.0% to 30.0% |
| Over-redaction (must_keep strings missing) | 6.6% | 0.0 pp | 6.6% to 6.6% |
| Over-redaction (cases with any missing) | 15.7% | 0.0 pp | 15.7% to 15.7% |
| Local overhead, mean (ms) | 4157 | 0.0 | 4157 to 4157 |
| Local overhead, p95 (ms) | 8044 | 0.0 | 8044 to 8044 |
| Client wall time, mean (ms) | 7565 | 0.0 | 7565 to 7565 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 20.0% ± 0.0 | 0.0% ± 0.0 | 5.6% ± 0.0 | 0.0% ± 0.0 | n/a |
| benign | n/a | 20.0% ± 0.0 | 5.9% ± 0.0 | n/a | 30.0% ± 0.0 |
| direct_pii | 10.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a |
| finance | 0.0% ± 0.0 | 10.0% ± 0.0 | 4.0% ± 0.0 | 100.0% ± 0.0 | n/a |
| health | 0.0% ± 0.0 | 0.0% ± 0.0 | 6.9% ± 0.0 | n/a | n/a |
| intent_leak_search | 0.0% ± 0.0 | 40.0% ± 0.0 | 83.3% ± 0.0 | 100.0% ± 0.0 | n/a |
| quasi_identifier | 40.0% ± 0.0 | 0.0% ± 0.0 | 9.1% ± 0.0 | n/a | n/a |
| secrets_in_code | 0.0% ± 0.0 | 0.0% ± 0.0 | 3.8% ± 0.0 | n/a | n/a |
| vault_terms | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 7.5% ± 0.0 | 8.9% ± 0.0 | 3.9% ± 0.0 |
| ko | 10.0% ± 0.0 | 6.7% ± 0.0 | 9.5% ± 0.0 |

## Cases that leaked in any pass

7 case(s) leaked in every pass; 0 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| adv-ko-07 | adversarial | ko | 1/1 | `정민준`: 1, alnum |
| adv-ko-13 | adversarial | ko | 1/1 | `5127214713788210`: 1, digits |
| pii-en-09 | direct_pii | en | 1/1 | `1999-05-21`: 1, exact |
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

## Value outcomes (summed over passes)

- `detected_removed`: 0
- `removed_unattributed`: 232
- `gate_saved`: 6
- `missed_leaked`: 3
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
