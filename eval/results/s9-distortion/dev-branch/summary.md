# Airlock eval summary

- Target: `http://127.0.0.1:8799` (airlock 91d21f3 (feat/distortion), AIRLOCK_GLINER=on, placeholder, dev split)
- Passes: 1 · cases per pass: 72 · protection level: `balanced`
- Dataset sha256: `96855eb04745e708a67efc966d6eb2d9d3226e8a4a9ff77f4a41691390c9c7ad`
- Harness version: 1.0.0 · started 2026-09-14T00:02:18.586586+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 7.8% | 0.0 pp | 7.8% to 7.8% |
| Leak rate (individual values) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Leak rate (exact-string hits only) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Canary leak rate | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Quasi-identifier re-identification rate | 35.7% | 0.0 pp | 35.7% to 35.7% |
| Identity leak (any identity item or identifying quasi set) | 9.7% | 0.0 pp | 9.7% to 9.7% |
| Gate save rate (upper bound: request-level) | 100.0% | 0.0 pp | 100.0% to 100.0% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 4.9% | 0.0 pp | 4.9% to 4.9% |
| Block rate (all) | 2.8% | 0.0 pp | 2.8% to 2.8% |
| Block rate (non-benign) | 3.1% | 0.0 pp | 3.1% to 3.1% |
| Over-block on benign | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Benign cases with any masking | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Over-redaction (must_keep strings missing) | 6.0% | 0.0 pp | 6.0% to 6.0% |
| Over-redaction (cases with any missing) | 12.9% | 0.0 pp | 12.9% to 12.9% |
| Local overhead, mean (ms) | 4845 | 0.0 | 4845 to 4845 |
| Local overhead, p95 (ms) | 9647 | 0.0 | 9647 to 9647 |
| Client wall time, mean (ms) | 8505 | 0.0 | 8505 to 8505 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 0.0% ± 0.0 | 25.0% ± 0.0 | 10.0% ± 0.0 | 100.0% ± 0.0 | n/a |
| benign | n/a | 0.0% ± 0.0 | 5.9% ± 0.0 | n/a | 0.0% ± 0.0 |
| direct_pii | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |
| finance | 0.0% ± 0.0 | 0.0% ± 0.0 | 8.0% ± 0.0 | n/a | n/a |
| health | 0.0% ± 0.0 | 0.0% ± 0.0 | 5.0% ± 0.0 | n/a | n/a |
| intent_leak_search | 0.0% ± 0.0 | 0.0% ± 0.0 | 45.5% ± 0.0 | n/a | n/a |
| quasi_identifier | 62.5% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |
| secrets_in_code | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |
| vault_terms | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 12.5% ± 0.0 | 5.6% ± 0.0 | 3.7% ± 0.0 |
| ko | 3.1% ± 0.0 | 0.0% ± 0.0 | 8.1% ± 0.0 |

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

- `detected_removed`: 146
- `removed_unattributed`: 47
- `gate_saved`: 10
- `missed_leaked`: 0
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
