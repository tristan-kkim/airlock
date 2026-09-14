# Airlock eval summary

- Target: `http://127.0.0.1:8887` (airlock@e0ee6aa gliner=1 substitution=surrogate)
- Passes: 3 · cases per pass: 243 · protection level: `balanced`
- Dataset sha256: `cd40ce707652d30ffb2007c5ccaac62c61709d42382c4c623351b5114c850609`
- Harness version: 1.0.0 · started 2026-09-14T01:52:30.720898+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 7.4% | 0.0 pp | 7.4% to 7.4% |
| Leak rate (individual values) | 0.4% | 0.0 pp | 0.4% to 0.4% |
| Leak rate (exact-string hits only) | 0.5% | 0.0 pp | 0.5% to 0.5% |
| Canary leak rate | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Quasi-identifier re-identification rate | 28.0% | 0.0 pp | 28.0% to 28.0% |
| Identity leak (any identity item or identifying quasi set) | 8.3% | 0.0 pp | 8.3% to 8.3% |
| Gate save rate (upper bound: request-level) | 75.7% | 9.8 pp | 70.0% to 87.0% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 2.1% | 1.1 pp | 1.5% to 3.4% |
| Block rate (all) | 3.2% | 1.2 pp | 2.5% to 4.5% |
| Block rate (non-benign) | 2.6% | 1.3 pp | 1.9% to 4.2% |
| Over-block on benign | 7.4% | 0.0 pp | 7.4% to 7.4% |
| Benign cases with any masking | 11.1% | 0.0 pp | 11.1% to 11.1% |
| Over-redaction (must_keep strings missing) | 6.4% | 0.2 pp | 6.2% to 6.6% |
| Over-redaction (cases with any missing) | 13.7% | 0.3 pp | 13.4% to 13.9% |
| Local overhead, mean (ms) | 2365 | 1745.6 | 1321 to 4381 |
| Local overhead, p95 (ms) | 6541 | 2298.4 | 4865 to 9161 |
| Client wall time, mean (ms) | 6522 | 1566.8 | 5394 to 8311 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 7.4% ± 0.0 | 4.9% ± 2.1 | 4.4% ± 0.1 | 67.3% ± 8.3 | n/a |
| benign | n/a | 7.4% ± 0.0 | 7.8% ± 2.0 | n/a | 11.1% ± 0.0 |
| direct_pii | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |
| finance | 0.0% ± 0.0 | 0.0% ± 0.0 | 5.0% ± 0.0 | n/a | n/a |
| health | 0.0% ± 0.0 | 1.2% ± 2.1 | 4.0% ± 0.1 | 100.0% ± 0.0 | n/a |
| intent_leak_search | 0.0% ± 0.0 | 12.3% ± 2.1 | 58.1% ± 0.9 | 100.0% ± 0.0 | n/a |
| quasi_identifier | 51.9% ± 0.0 | 0.0% ± 0.0 | 5.1% ± 0.0 | n/a | n/a |
| secrets_in_code | 0.0% ± 0.0 | 2.5% ± 4.3 | 2.9% ± 0.1 | 100.0% ± 0.0 | n/a |
| vault_terms | 0.0% ± 0.0 | 0.0% ± 0.0 | 1.4% ± 0.0 | n/a | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 7.5% ± 0.0 | 4.1% ± 1.4 | 4.5% ± 0.5 |
| ko | 7.3% ± 0.0 | 2.2% ± 0.9 | 8.3% ± 0.1 |

## Cases that leaked in any pass

16 case(s) leaked in every pass; 0 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| adv-ko-02 | adversarial | ko | 3/3 | `010-0911-0925`: 3, numeral_words; `공일공 공구일일 공구이오`: 3, exact |
| adv-ko-07 | adversarial | ko | 3/3 | `정민준`: 3, alnum |
| qid-en-02 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-04 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-05 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-06 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-08 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-09 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-11 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-12 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-02 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-04 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-08 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-09 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-11 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-14 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|
| ben-ko-08 | ko | 3/3 | 3/3 | - |
| ben-ko-13 | ko | 3/3 | 3/3 | - |
| ben-ko-09 | ko | 0/3 | 3/3 | `장영실` (3) |
| ben-en-04 | en | 0/3 | 0/3 | `Marie Curie` (2) |
| ben-en-07 | en | 0/3 | 0/3 | `free-threaded` (3) |
| ben-en-12 | en | 0/3 | 0/3 | `sidecar containers` (1) |
| ben-ko-05 | ko | 0/3 | 0/3 | `최저임금` (3) |

## Value outcomes (summed over passes)

- `detected_removed`: 1525
- `removed_unattributed`: 466
- `gate_saved`: 34
- `missed_leaked`: 9
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
