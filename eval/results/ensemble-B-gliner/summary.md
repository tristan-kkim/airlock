# Airlock eval summary

- Target: `http://127.0.0.1:8797` (airlock 685d3c7 AIRLOCK_GLINER=on (threshold 0.4, cpu, adjudication on))
- Passes: 1 · cases per pass: 243 · protection level: `balanced`
- Dataset sha256: `2549790dc5913bf1cac0d7f681427cf87b55af96a770b7f8678b83810bc82e70`
- Harness version: 1.0.0 · started 2026-09-13T18:52:00.304753+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 8.3% | 0.0 pp | 8.3% to 8.3% |
| Leak rate (individual values) | 0.9% | 0.0 pp | 0.9% to 0.9% |
| Leak rate (exact-string hits only) | 1.9% | 0.0 pp | 1.9% to 1.9% |
| Canary leak rate | 1.4% | 0.0 pp | 1.4% to 1.4% |
| Quasi-identifier re-identification rate | 24.0% | 0.0 pp | 24.0% to 24.0% |
| Gate save rate (upper bound: request-level) | 77.8% | 0.0 pp | 77.8% to 77.8% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 4.0% | 0.0 pp | 4.0% to 4.0% |
| Block rate (all) | 5.8% | 0.0 pp | 5.8% to 5.8% |
| Block rate (non-benign) | 5.1% | 0.0 pp | 5.1% to 5.1% |
| Over-block on benign | 11.1% | 0.0 pp | 11.1% to 11.1% |
| Benign cases with any masking | 33.3% | 0.0 pp | 33.3% to 33.3% |
| Over-redaction (must_keep strings missing) | 14.7% | 0.0 pp | 14.7% to 14.7% |
| Over-redaction (cases with any missing) | 29.7% | 0.0 pp | 29.7% to 29.7% |
| Local overhead, mean (ms) | 8408 | 0.0 | 8408 to 8408 |
| Local overhead, p95 (ms) | 20159 | 0.0 | 20159 to 20159 |
| Client wall time, mean (ms) | 12889 | 0.0 | 12889 to 12889 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 7.4% ± 0.0 | 0.0% ± 0.0 | 10.4% ± 0.0 | 0.0% ± 0.0 | n/a |
| benign | n/a | 11.1% ± 0.0 | 12.0% ± 0.0 | n/a | 33.3% ± 0.0 |
| direct_pii | 3.7% ± 0.0 | 7.4% ± 0.0 | 5.7% ± 0.0 | 90.9% ± 0.0 | n/a |
| finance | 3.7% ± 0.0 | 3.7% ± 0.0 | 14.3% ± 0.0 | 75.0% ± 0.0 | n/a |
| health | 0.0% ± 0.0 | 3.7% ± 0.0 | 35.1% ± 0.0 | 100.0% ± 0.0 | n/a |
| intent_leak_search | 0.0% ± 0.0 | 22.2% ± 0.0 | 72.0% ± 0.0 | 100.0% ± 0.0 | n/a |
| quasi_identifier | 44.4% ± 0.0 | 0.0% ± 0.0 | 5.1% ± 0.0 | n/a | n/a |
| secrets_in_code | 0.0% ± 0.0 | 3.7% ± 0.0 | 5.9% ± 0.0 | 100.0% ± 0.0 | n/a |
| vault_terms | 7.4% ± 0.0 | 0.0% ± 0.0 | 4.1% ± 0.0 | 0.0% ± 0.0 | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 6.5% ± 0.0 | 5.0% ± 0.0 | 11.4% ± 0.0 |
| ko | 10.1% ± 0.0 | 6.6% ± 0.0 | 18.2% ± 0.0 |

## Cases that leaked in any pass

18 case(s) leaked in every pass; 0 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| adv-ko-07 | adversarial | ko | 1/1 | `정민준`: 1, alnum |
| adv-ko-13 | adversarial | ko | 1/1 | `5127214713788210`: 1, digits |
| fin-ko-07 | finance | ko | 1/1 | `dynamo pepper canyon orbit ember velvet anchor hazel hazel harbor meadow harbor`: 1, exact |
| pii-ko-05 | direct_pii | ko | 1/1 | `장소율`: 1, exact |
| qid-en-05 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-06 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-08 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-09 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-10 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-11 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-02 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-03 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-07 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-10 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-11 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-14 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| vlt-en-12 | vault_terms | en | 1/1 | `Z2UI-3493`: 1, exact |
| vlt-ko-06 | vault_terms | ko | 1/1 | `O589-1700`: 1, exact |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|
| ben-ko-05 | ko | 1/1 | 1/1 | - |
| ben-ko-08 | ko | 1/1 | 1/1 | - |
| ben-ko-13 | ko | 1/1 | 1/1 | - |
| ben-en-01 | en | 0/1 | 1/1 | `Alan Turing` (1) |
| ben-en-02 | en | 0/1 | 1/1 | `479001600` (1) |
| ben-en-04 | en | 0/1 | 1/1 | `Marie Curie` (1) |
| ben-en-13 | en | 0/1 | 1/1 | - |
| ben-en-14 | en | 0/1 | 1/1 | `Kyoto` (1) |
| ben-ko-09 | ko | 0/1 | 1/1 | `장영실` (1) |
| ben-en-07 | en | 0/1 | 0/1 | `free-threaded` (1) |

## Value outcomes (summed over passes)

- `detected_removed`: 462
- `removed_unattributed`: 189
- `gate_saved`: 21
- `missed_leaked`: 6
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
