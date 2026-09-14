# Airlock eval summary

- Target: `http://127.0.0.1:8887` (airlock@e0ee6aa gliner=1 substitution=placeholder)
- Passes: 3 · cases per pass: 243 · protection level: `balanced`
- Dataset sha256: `cd40ce707652d30ffb2007c5ccaac62c61709d42382c4c623351b5114c850609`
- Harness version: 1.0.0 · started 2026-09-14T00:42:35.091078+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 7.9% | 0.0 pp | 7.9% to 7.9% |
| Leak rate (individual values) | 0.6% | 0.0 pp | 0.6% to 0.6% |
| Leak rate (exact-string hits only) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Canary leak rate | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Quasi-identifier re-identification rate | 26.0% | 0.0 pp | 26.0% to 26.0% |
| Identity leak (any identity item or identifying quasi set) | 9.7% | 0.0 pp | 9.7% to 9.7% |
| Gate save rate (upper bound: request-level) | 50.0% | 16.7 pp | 33.3% to 66.7% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 1.3% | 0.5 pp | 0.9% to 1.8% |
| Block rate (all) | 2.9% | 0.7 pp | 2.5% to 3.7% |
| Block rate (non-benign) | 2.3% | 0.8 pp | 1.9% to 3.2% |
| Over-block on benign | 7.4% | 0.0 pp | 7.4% to 7.4% |
| Benign cases with any masking | 11.1% | 0.0 pp | 11.1% to 11.1% |
| Over-redaction (must_keep strings missing) | 7.0% | 0.3 pp | 6.8% to 7.3% |
| Over-redaction (cases with any missing) | 14.4% | 0.7 pp | 13.9% to 15.2% |
| Local overhead, mean (ms) | 2161 | 1785.1 | 1121 to 4222 |
| Local overhead, p95 (ms) | 5734 | 2324.5 | 4312 to 8416 |
| Client wall time, mean (ms) | 5744 | 1918.0 | 4562 to 7957 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 14.8% ± 0.0 | 1.2% ± 2.1 | 8.5% ± 0.2 | 18.5% ± 32.1 | n/a |
| benign | n/a | 7.4% ± 0.0 | 6.5% ± 1.1 | n/a | 11.1% ± 0.0 |
| direct_pii | 0.0% ± 0.0 | 0.0% ± 0.0 | 1.3% ± 0.0 | n/a | n/a |
| finance | 0.0% ± 0.0 | 0.0% ± 0.0 | 6.2% ± 0.0 | n/a | n/a |
| health | 0.0% ± 0.0 | 0.0% ± 0.0 | 9.2% ± 0.0 | n/a | n/a |
| intent_leak_search | 0.0% ± 0.0 | 17.3% ± 4.3 | 58.8% ± 4.8 | 100.0% ± 0.0 | n/a |
| quasi_identifier | 48.1% ± 0.0 | 0.0% ± 0.0 | 3.4% ± 0.0 | n/a | n/a |
| secrets_in_code | 0.0% ± 0.0 | 0.0% ± 0.0 | 1.4% ± 0.0 | n/a | n/a |
| vault_terms | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 7.5% ± 0.0 | 3.9% ± 1.7 | 3.8% ± 0.7 |
| ko | 8.3% ± 0.0 | 1.9% ± 0.5 | 10.2% ± 0.2 |

## Cases that leaked in any pass

17 case(s) leaked in every pass; 0 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| adv-ko-01 | adversarial | ko | 3/3 | `장유나`: 3, whitespace |
| adv-ko-06 | adversarial | ko | 3/3 | `4774406885844904`: 3, digits |
| adv-ko-07 | adversarial | ko | 3/3 | `정민준`: 3, alnum |
| adv-ko-08 | adversarial | ko | 3/3 | `최주원`: 3, whitespace |
| qid-en-02 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-03 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-04 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-05 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-08 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-09 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-11 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-12 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-08 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-09 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-10 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-11 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-14 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|
| ben-ko-08 | ko | 3/3 | 3/3 | - |
| ben-ko-13 | ko | 3/3 | 3/3 | - |
| ben-ko-09 | ko | 0/3 | 3/3 | `장영실` (3) |
| ben-en-04 | en | 0/3 | 0/3 | `Marie Curie` (1) |
| ben-en-07 | en | 0/3 | 0/3 | `free-threaded` (3) |
| ben-ko-05 | ko | 0/3 | 0/3 | `최저임금` (3) |

## Value outcomes (summed over passes)

- `detected_removed`: 1541
- `removed_unattributed`: 467
- `gate_saved`: 14
- `missed_leaked`: 12
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
