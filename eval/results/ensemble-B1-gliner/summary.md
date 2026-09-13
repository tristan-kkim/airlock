# Airlock eval summary

- Target: `http://127.0.0.1:8797` (airlock 79e9891 AIRLOCK_GLINER=on variant 1: agreement-only city,date_of_birth; Korean GLiNER-only names 3+ syllables)
- Passes: 1 · cases per pass: 243 · protection level: `balanced`
- Dataset sha256: `2549790dc5913bf1cac0d7f681427cf87b55af96a770b7f8678b83810bc82e70`
- Harness version: 1.0.0 · started 2026-09-13T19:46:56.931046+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 11.1% | 0.0 pp | 11.1% to 11.1% |
| Leak rate (individual values) | 1.8% | 0.0 pp | 1.8% to 1.8% |
| Leak rate (exact-string hits only) | 3.2% | 0.0 pp | 3.2% to 3.2% |
| Canary leak rate | 0.7% | 0.0 pp | 0.7% to 0.7% |
| Quasi-identifier re-identification rate | 30.0% | 0.0 pp | 30.0% to 30.0% |
| Gate save rate (upper bound: request-level) | 55.6% | 0.0 pp | 55.6% to 55.6% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 4.0% | 0.0 pp | 4.0% to 4.0% |
| Block rate (all) | 4.9% | 0.0 pp | 4.9% to 4.9% |
| Block rate (non-benign) | 4.6% | 0.0 pp | 4.6% to 4.6% |
| Over-block on benign | 7.4% | 0.0 pp | 7.4% to 7.4% |
| Benign cases with any masking | 14.8% | 0.0 pp | 14.8% to 14.8% |
| Over-redaction (must_keep strings missing) | 15.7% | 0.0 pp | 15.7% to 15.7% |
| Over-redaction (cases with any missing) | 29.0% | 0.0 pp | 29.0% to 29.0% |
| Local overhead, mean (ms) | 4912 | 0.0 | 4912 to 4912 |
| Local overhead, p95 (ms) | 9794 | 0.0 | 9794 to 9794 |
| Client wall time, mean (ms) | 10967 | 0.0 | 10967 to 10967 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 11.1% ± 0.0 | 0.0% ± 0.0 | 12.5% ± 0.0 | 0.0% ± 0.0 | n/a |
| benign | n/a | 7.4% ± 0.0 | 9.8% ± 0.0 | n/a | 14.8% ± 0.0 |
| direct_pii | 3.7% ± 0.0 | 3.7% ± 0.0 | 6.8% ± 0.0 | 71.4% ± 0.0 | n/a |
| finance | 3.7% ± 0.0 | 3.7% ± 0.0 | 19.5% ± 0.0 | 75.0% ± 0.0 | n/a |
| health | 11.1% ± 0.0 | 0.0% ± 0.0 | 40.8% ± 0.0 | 0.0% ± 0.0 | n/a |
| intent_leak_search | 0.0% ± 0.0 | 22.2% ± 0.0 | 62.5% ± 0.0 | 100.0% ± 0.0 | n/a |
| quasi_identifier | 55.6% ± 0.0 | 0.0% ± 0.0 | 3.4% ± 0.0 | n/a | n/a |
| secrets_in_code | 0.0% ± 0.0 | 7.4% ± 0.0 | 3.0% ± 0.0 | 100.0% ± 0.0 | n/a |
| vault_terms | 3.7% ± 0.0 | 0.0% ± 0.0 | 6.8% ± 0.0 | 0.0% ± 0.0 | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 11.2% ± 0.0 | 5.8% ± 0.0 | 12.7% ± 0.0 |
| ko | 11.0% ± 0.0 | 4.1% ± 0.0 | 18.8% ± 0.0 |

## Cases that leaked in any pass

24 case(s) leaked in every pass; 0 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| adv-ko-02 | adversarial | ko | 1/1 | `010-0911-0925`: 1, numeral_words; `공일공 공구일일 공구이오`: 1, exact; `박하은`: 1, exact |
| adv-ko-07 | adversarial | ko | 1/1 | `정민준`: 1, alnum |
| adv-ko-13 | adversarial | ko | 1/1 | `5127214713788210`: 1, digits |
| fin-en-05 | finance | en | 1/1 | `orbit cactus harbor hazel hazel tundra meadow dynamo ember anchor dynamo velvet`: 1, exact |
| hlt-en-04 | health | en | 1/1 | `Linden Vale Clinic`: 1, exact |
| hlt-en-08 | health | en | 1/1 | `1953-01-15`: 1, exact |
| hlt-en-11 | health | en | 1/1 | `Maplecrest General Hospital`: 1, exact |
| pii-ko-05 | direct_pii | ko | 1/1 | `서하은`: 1, exact; `장소율`: 1, exact |
| qid-en-04 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-05 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-08 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-09 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-10 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-11 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-12 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-02 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-03 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-04 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-07 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-08 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-10 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-11 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-14 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| vlt-en-12 | vault_terms | en | 1/1 | `Z2UI-3493`: 1, exact |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|
| ben-ko-08 | ko | 1/1 | 1/1 | - |
| ben-ko-13 | ko | 1/1 | 1/1 | - |
| ben-en-02 | en | 0/1 | 1/1 | `479001600` (1) |
| ben-ko-09 | ko | 0/1 | 1/1 | `장영실` (1) |
| ben-en-04 | en | 0/1 | 0/1 | `Marie Curie` (1) |
| ben-en-07 | en | 0/1 | 0/1 | `free-threaded` (1) |
| ben-ko-05 | ko | 0/1 | 0/1 | `최저임금` (1) |

## Value outcomes (summed over passes)

- `detected_removed`: 460
- `removed_unattributed`: 191
- `gate_saved`: 15
- `missed_leaked`: 12
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
