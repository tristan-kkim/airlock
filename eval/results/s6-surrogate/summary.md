# Airlock eval summary

- Target: `http://127.0.0.1:8798` (airlock 071c36c S6 round two, AIRLOCK_GLINER=on, AIRLOCK_SUBSTITUTION=surrogate, test split)
- Passes: 1 · cases per pass: 171 · protection level: `balanced`
- Dataset sha256: `31825c3022f828c6c6ba7db6a667dbf545726cfa5b324dc555ac03e3a51968a1`
- Harness version: 1.0.0 · started 2026-09-13T21:56:47.731920+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 7.9% | 0.0 pp | 7.9% to 7.9% |
| Leak rate (individual values) | 0.6% | 0.0 pp | 0.6% to 0.6% |
| Leak rate (exact-string hits only) | 1.3% | 0.0 pp | 1.3% to 1.3% |
| Canary leak rate | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Quasi-identifier re-identification rate | 25.0% | 0.0 pp | 25.0% to 25.0% |
| Identity leak (any identity item or identifying quasi set) | 8.3% | 0.0 pp | 8.3% to 8.3% |
| Gate save rate (upper bound: request-level) | 57.1% | 0.0 pp | 57.1% to 57.1% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 1.5% | 0.0 pp | 1.5% to 1.5% |
| Block rate (all) | 4.1% | 0.0 pp | 4.1% to 4.1% |
| Block rate (non-benign) | 3.3% | 0.0 pp | 3.3% to 3.3% |
| Over-block on benign | 10.5% | 0.0 pp | 10.5% to 10.5% |
| Benign cases with any masking | 21.1% | 0.0 pp | 21.1% to 21.1% |
| Over-redaction (must_keep strings missing) | 8.8% | 0.0 pp | 8.8% to 8.8% |
| Over-redaction (cases with any missing) | 18.9% | 0.0 pp | 18.9% to 18.9% |
| Local overhead, mean (ms) | 4113 | 0.0 | 4113 to 4113 |
| Local overhead, p95 (ms) | 7800 | 0.0 | 7800 to 7800 |
| Client wall time, mean (ms) | 8035 | 0.0 | 8035 to 8035 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 5.3% ± 0.0 | 5.3% ± 0.0 | 9.4% ± 0.0 | 66.7% ± 0.0 | n/a |
| benign | n/a | 10.5% ± 0.0 | 11.8% ± 0.0 | n/a | 21.1% ± 0.0 |
| direct_pii | 0.0% ± 0.0 | 0.0% ± 0.0 | 1.9% ± 0.0 | n/a | n/a |
| finance | 0.0% ± 0.0 | 0.0% ± 0.0 | 3.6% ± 0.0 | n/a | n/a |
| health | 10.5% ± 0.0 | 0.0% ± 0.0 | 14.3% ± 0.0 | 0.0% ± 0.0 | n/a |
| intent_leak_search | 0.0% ± 0.0 | 21.1% ± 0.0 | 64.7% ± 0.0 | 100.0% ± 0.0 | n/a |
| quasi_identifier | 47.4% ± 0.0 | 0.0% ± 0.0 | 4.8% ± 0.0 | n/a | n/a |
| secrets_in_code | 0.0% ± 0.0 | 0.0% ± 0.0 | 6.1% ± 0.0 | n/a | n/a |
| vault_terms | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 9.3% ± 0.0 | 4.7% ± 0.0 | 5.1% ± 0.0 |
| ko | 6.5% ± 0.0 | 3.5% ± 0.0 | 12.6% ± 0.0 |

## Cases that leaked in any pass

12 case(s) leaked in every pass; 0 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| adv-ko-07 | adversarial | ko | 1/1 | `정민준`: 1, alnum |
| hlt-en-01 | health | en | 1/1 | `1954-01-11`: 1, exact |
| hlt-en-05 | health | en | 1/1 | `Delacroix`: 1, exact |
| qid-en-03 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-08 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-09 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-11 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-12 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-02 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-04 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-08 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-11 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|
| ben-ko-08 | ko | 1/1 | 1/1 | - |
| ben-ko-13 | ko | 1/1 | 1/1 | - |
| ben-en-02 | en | 0/1 | 1/1 | `479001600` (1) |
| ben-ko-09 | ko | 0/1 | 1/1 | `장영실` (1) |
| ben-en-04 | en | 0/1 | 0/1 | `Marie Curie` (1) |
| ben-ko-05 | ko | 0/1 | 0/1 | `최저임금` (1) |

## Value outcomes (summed over passes)

- `detected_removed`: 354
- `removed_unattributed`: 114
- `gate_saved`: 4
- `missed_leaked`: 3
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
