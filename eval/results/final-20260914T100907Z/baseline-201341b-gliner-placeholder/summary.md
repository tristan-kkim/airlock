# Airlock eval summary

- Target: `http://127.0.0.1:8887` (airlock@201341b gliner=1 substitution=placeholder)
- Passes: 3 · cases per pass: 243 · protection level: `balanced`
- Dataset sha256: `cd40ce707652d30ffb2007c5ccaac62c61709d42382c4c623351b5114c850609`
- Harness version: 1.0.0 · started 2026-09-14T10:10:43.765056+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 8.0% | 0.5 pp | 7.4% to 8.3% |
| Leak rate (individual values) | 0.5% | 0.1 pp | 0.4% to 0.6% |
| Leak rate (exact-string hits only) | 0.3% | 0.3 pp | 0.0% to 0.5% |
| Canary leak rate | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Quasi-identifier re-identification rate | 28.7% | 2.3 pp | 26.0% to 30.0% |
| Identity leak (any identity item or identifying quasi set) | 8.6% | 0.7 pp | 7.8% to 9.2% |
| Gate save rate (upper bound: request-level) | 64.5% | 15.0 pp | 50.0% to 80.0% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 1.6% | 0.7 pp | 0.9% to 2.2% |
| Block rate (all) | 3.3% | 0.0 pp | 3.3% to 3.3% |
| Block rate (non-benign) | 2.8% | 0.0 pp | 2.8% to 2.8% |
| Over-block on benign | 7.4% | 0.0 pp | 7.4% to 7.4% |
| Benign cases with any masking | 11.1% | 0.0 pp | 11.1% to 11.1% |
| Over-redaction (must_keep strings missing) | 7.1% | 1.3 pp | 6.3% to 8.6% |
| Over-redaction (cases with any missing) | 14.6% | 2.5 pp | 13.2% to 17.4% |
| Local overhead, mean (ms) | 4281 | 132.6 | 4129 to 4376 |
| Local overhead, p95 (ms) | 8771 | 388.8 | 8391 to 9168 |
| Client wall time, mean (ms) | 7915 | 118.9 | 7778 to 7992 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 9.9% ± 2.1 | 1.2% ± 2.1 | 7.8% ± 3.2 | 20.8% ± 36.1 | n/a |
| benign | n/a | 7.4% ± 0.0 | 7.2% ± 1.1 | n/a | 11.1% ± 0.0 |
| direct_pii | 0.0% ± 0.0 | 0.0% ± 0.0 | 1.8% ± 1.5 | n/a | n/a |
| finance | 1.2% ± 2.1 | 0.0% ± 0.0 | 5.0% ± 3.8 | 0.0% ± 0.0 | n/a |
| health | 0.0% ± 0.0 | 0.0% ± 0.0 | 8.3% ± 2.7 | n/a | n/a |
| intent_leak_search | 0.0% ± 0.0 | 18.5% ± 3.7 | 59.2% ± 6.7 | 100.0% ± 0.0 | n/a |
| quasi_identifier | 53.1% ± 4.3 | 0.0% ± 0.0 | 3.4% ± 1.7 | n/a | n/a |
| secrets_in_code | 0.0% ± 0.0 | 2.5% ± 2.1 | 2.4% ± 2.2 | 100.0% ± 0.0 | n/a |
| vault_terms | 0.0% ± 0.0 | 0.0% ± 0.0 | 1.4% ± 2.4 | n/a | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 6.2% ± 0.5 | 4.1% ± 0.0 | 4.3% ± 1.1 |
| ko | 9.8% ± 0.5 | 2.5% ± 0.0 | 10.0% ± 1.9 |

## Pass independence

- Byte-identical outbound payloads in all 3 passes: 130 of 231 cases (56.3%)
- Detect time p50 by pass: 3,463 / 3,409 / 3,375 ms
- Detector temperature: 0.6

## Cases that leaked in any pass

12 case(s) leaked in every pass; 11 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| adv-ko-07 | adversarial | ko | 3/3 | `정민준`: 3, alnum |
| qid-en-06 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-08 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-10 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-11 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-02 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-04 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-07 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-08 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-10 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-11 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-14 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| adv-ko-13 | adversarial | ko | 2/3 | `5127214713788210`: 2, digits |
| qid-en-04 | quasi_identifier | en | 2/3 | quasi-identifier group ≥k: 2 |
| qid-en-05 | quasi_identifier | en | 2/3 | quasi-identifier group ≥k: 2 |
| qid-en-09 | quasi_identifier | en | 2/3 | quasi-identifier group ≥k: 2 |
| qid-ko-09 | quasi_identifier | ko | 2/3 | quasi-identifier group ≥k: 2 |
| adv-ko-02 | adversarial | ko | 1/3 | `010-0911-0925`: 1, numeral_words; `공일공 공구일일 공구이오`: 1, exact |
| adv-ko-06 | adversarial | ko | 1/3 | `4774406885844904`: 1, digits |
| adv-ko-14 | adversarial | ko | 1/3 | `정주원`: 1, alnum |
| fin-ko-10 | finance | ko | 1/3 | `권소율`: 1, exact |
| qid-en-02 | quasi_identifier | en | 1/3 | quasi-identifier group ≥k: 1 |
| qid-en-03 | quasi_identifier | en | 1/3 | quasi-identifier group ≥k: 1 |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|
| ben-ko-08 | ko | 3/3 | 3/3 | - |
| ben-ko-13 | ko | 3/3 | 3/3 | - |
| ben-ko-09 | ko | 0/3 | 3/3 | `장영실` (3) |
| ben-en-04 | en | 0/3 | 0/3 | `Marie Curie` (2) |
| ben-en-07 | en | 0/3 | 0/3 | `free-threaded` (3) |
| ben-ko-05 | ko | 0/3 | 0/3 | `최저임금` (3) |

## Value outcomes (summed over passes)

- `detected_removed`: 1540
- `removed_unattributed`: 462
- `gate_saved`: 22
- `missed_leaked`: 10
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
