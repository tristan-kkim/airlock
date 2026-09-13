# Airlock eval summary

- Target: `http://127.0.0.1:8798` (airlock 071c36c S6 round two, AIRLOCK_GLINER=on, AIRLOCK_SUBSTITUTION=placeholder, test split)
- Passes: 1 · cases per pass: 171 · protection level: `balanced`
- Dataset sha256: `31825c3022f828c6c6ba7db6a667dbf545726cfa5b324dc555ac03e3a51968a1`
- Harness version: 1.0.0 · started 2026-09-13T21:33:32.682368+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 8.6% | 0.0 pp | 8.6% to 8.6% |
| Leak rate (individual values) | 0.6% | 0.0 pp | 0.6% to 0.6% |
| Leak rate (exact-string hits only) | 0.7% | 0.0 pp | 0.7% to 0.7% |
| Canary leak rate | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Quasi-identifier re-identification rate | 27.8% | 0.0 pp | 27.8% to 27.8% |
| Identity leak (any identity item or identifying quasi set) | 9.0% | 0.0 pp | 9.0% to 9.0% |
| Gate save rate (upper bound: request-level) | 62.5% | 0.0 pp | 62.5% to 62.5% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 1.7% | 0.0 pp | 1.7% to 1.7% |
| Block rate (all) | 5.3% | 0.0 pp | 5.3% to 5.3% |
| Block rate (non-benign) | 4.6% | 0.0 pp | 4.6% to 4.6% |
| Over-block on benign | 10.5% | 0.0 pp | 10.5% to 10.5% |
| Benign cases with any masking | 21.1% | 0.0 pp | 21.1% to 21.1% |
| Over-redaction (must_keep strings missing) | 7.8% | 0.0 pp | 7.8% to 7.8% |
| Over-redaction (cases with any missing) | 17.9% | 0.0 pp | 17.9% to 17.9% |
| Local overhead, mean (ms) | 4319 | 0.0 | 4319 to 4319 |
| Local overhead, p95 (ms) | 8333 | 0.0 | 8333 to 8333 |
| Client wall time, mean (ms) | 8027 | 0.0 | 8027 to 8027 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 10.5% ± 0.0 | 0.0% ± 0.0 | 5.9% ± 0.0 | 0.0% ± 0.0 | n/a |
| benign | n/a | 10.5% ± 0.0 | 8.8% ± 0.0 | n/a | 21.1% ± 0.0 |
| direct_pii | 5.3% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a |
| finance | 0.0% ± 0.0 | 5.3% ± 0.0 | 3.8% ± 0.0 | 100.0% ± 0.0 | n/a |
| health | 0.0% ± 0.0 | 0.0% ± 0.0 | 7.1% ± 0.0 | n/a | n/a |
| intent_leak_search | 5.3% ± 0.0 | 31.6% ± 0.0 | 85.7% ± 0.0 | 100.0% ± 0.0 | n/a |
| quasi_identifier | 47.4% ± 0.0 | 0.0% ± 0.0 | 4.8% ± 0.0 | n/a | n/a |
| secrets_in_code | 0.0% ± 0.0 | 0.0% ± 0.0 | 6.1% ± 0.0 | n/a | n/a |
| vault_terms | 0.0% ± 0.0 | 0.0% ± 0.0 | 4.0% ± 0.0 | n/a | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 8.0% ± 0.0 | 7.1% ± 0.0 | 4.6% ± 0.0 |
| ko | 9.1% ± 0.0 | 3.5% ± 0.0 | 11.1% ± 0.0 |

## Cases that leaked in any pass

13 case(s) leaked in every pass; 0 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| adv-ko-07 | adversarial | ko | 1/1 | `정민준`: 1, alnum |
| adv-ko-13 | adversarial | ko | 1/1 | `5127214713788210`: 1, digits |
| int-en-07 | intent_leak_search | en | 1/1 | quasi-identifier group ≥k: 1 |
| pii-en-09 | direct_pii | en | 1/1 | `1999-05-21`: 1, exact |
| qid-en-08 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-09 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-11 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-12 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-02 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-04 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-08 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-09 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-11 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|
| ben-ko-08 | ko | 1/1 | 1/1 | - |
| ben-ko-13 | ko | 1/1 | 1/1 | - |
| ben-en-02 | en | 0/1 | 1/1 | `479001600` (1) |
| ben-ko-09 | ko | 0/1 | 1/1 | `장영실` (1) |
| ben-ko-05 | ko | 0/1 | 0/1 | `최저임금` (1) |

## Value outcomes (summed over passes)

- `detected_removed`: 353
- `removed_unattributed`: 114
- `gate_saved`: 5
- `missed_leaked`: 3
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
