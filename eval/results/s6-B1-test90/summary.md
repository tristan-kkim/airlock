# Airlock eval summary

- Target: `http://127.0.0.1:8797` (airlock 79e9891 AIRLOCK_GLINER=on variant 1: agreement-only city,date_of_birth; Korean GLiNER-only names 3+ syllables)
- Passes: 1 · cases per pass: 90 · protection level: `balanced`
- Dataset sha256: `2549790dc5913bf1cac0d7f681427cf87b55af96a770b7f8678b83810bc82e70`
- Harness version: 1.0.0 · started 2026-09-13T19:46:56.931046+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 12.5% | 0.0 pp | 12.5% to 12.5% |
| Leak rate (individual values) | 2.5% | 0.0 pp | 2.5% to 2.5% |
| Leak rate (exact-string hits only) | 2.5% | 0.0 pp | 2.5% to 2.5% |
| Canary leak rate | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Quasi-identifier re-identification rate | 31.6% | 0.0 pp | 31.6% to 31.6% |
| Identity leak (any identity item or identifying quasi set) | 14.5% | 0.0 pp | 14.5% to 14.5% |
| Gate save rate (upper bound: request-level) | 70.0% | 0.0 pp | 70.0% to 70.0% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 8.3% | 0.0 pp | 8.3% to 8.3% |
| Block rate (all) | 11.1% | 0.0 pp | 11.1% to 11.1% |
| Block rate (non-benign) | 10.0% | 0.0 pp | 10.0% to 10.0% |
| Over-block on benign | 20.0% | 0.0 pp | 20.0% to 20.0% |
| Benign cases with any masking | 30.0% | 0.0 pp | 30.0% to 30.0% |
| Over-redaction (must_keep strings missing) | 14.1% | 0.0 pp | 14.1% to 14.1% |
| Over-redaction (cases with any missing) | 30.0% | 0.0 pp | 30.0% to 30.0% |
| Local overhead, mean (ms) | 4829 | 0.0 | 4829 to 4829 |
| Local overhead, p95 (ms) | 9997 | 0.0 | 9997 to 9997 |
| Client wall time, mean (ms) | 11370 | 0.0 | 11370 to 11370 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 30.0% ± 0.0 | 0.0% ± 0.0 | 22.2% ± 0.0 | 0.0% ± 0.0 | n/a |
| benign | n/a | 20.0% ± 0.0 | 11.8% ± 0.0 | n/a | 30.0% ± 0.0 |
| direct_pii | 0.0% ± 0.0 | 10.0% ± 0.0 | 8.0% ± 0.0 | 100.0% ± 0.0 | n/a |
| finance | 0.0% ± 0.0 | 10.0% ± 0.0 | 8.0% ± 0.0 | 100.0% ± 0.0 | n/a |
| health | 10.0% ± 0.0 | 0.0% ± 0.0 | 34.5% ± 0.0 | 0.0% ± 0.0 | n/a |
| intent_leak_search | 0.0% ± 0.0 | 50.0% ± 0.0 | 80.0% ± 0.0 | 100.0% ± 0.0 | n/a |
| quasi_identifier | 60.0% ± 0.0 | 0.0% ± 0.0 | 4.5% ± 0.0 | n/a | n/a |
| secrets_in_code | 0.0% ± 0.0 | 10.0% ± 0.0 | 4.2% ± 0.0 | 100.0% ± 0.0 | n/a |
| vault_terms | 0.0% ± 0.0 | 0.0% ± 0.0 | 3.8% ± 0.0 | n/a | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 7.5% ± 0.0 | 13.3% ± 0.0 | 13.4% ± 0.0 |
| ko | 17.5% ± 0.0 | 8.9% ± 0.0 | 14.9% ± 0.0 |

## Cases that leaked in any pass

10 case(s) leaked in every pass; 0 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| adv-ko-02 | adversarial | ko | 1/1 | `010-0911-0925`: 1, numeral_words; `공일공 공구일일 공구이오`: 1, exact; `박하은`: 1, exact |
| adv-ko-07 | adversarial | ko | 1/1 | `정민준`: 1, alnum |
| adv-ko-13 | adversarial | ko | 1/1 | `5127214713788210`: 1, digits |
| hlt-en-04 | health | en | 1/1 | `Linden Vale Clinic`: 1, exact |
| qid-en-09 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-11 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-02 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-04 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-07 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-10 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|
| ben-ko-08 | ko | 1/1 | 1/1 | - |
| ben-ko-13 | ko | 1/1 | 1/1 | - |
| ben-en-02 | en | 0/1 | 1/1 | `479001600` (1) |
| ben-en-04 | en | 0/1 | 0/1 | `Marie Curie` (1) |

## Value outcomes (summed over passes)

- `detected_removed`: 0
- `removed_unattributed`: 221
- `gate_saved`: 14
- `missed_leaked`: 6
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
