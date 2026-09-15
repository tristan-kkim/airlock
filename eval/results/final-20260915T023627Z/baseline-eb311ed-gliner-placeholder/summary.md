# Airlock eval summary

- Target: `http://127.0.0.1:8887` (airlock@eb311ed gliner=1 substitution=placeholder)
- Passes: 3 · cases per pass: 243 · protection level: `balanced`
- Dataset sha256: `cd40ce707652d30ffb2007c5ccaac62c61709d42382c4c623351b5114c850609`
- Harness version: 1.0.0 · started 2026-09-15T03:01:31.052031+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 2.9% | 0.3 pp | 2.8% to 3.2% |
| Leak rate (individual values) | 0.1% | 0.1 pp | 0.0% to 0.1% |
| Leak rate (exact-string hits only) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Canary leak rate | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Quasi-identifier re-identification rate | 11.3% | 2.3 pp | 10.0% to 14.0% |
| Identity leak (any identity item or identifying quasi set) | 3.1% | 0.3 pp | 2.9% to 3.4% |
| Gate save rate (upper bound: request-level) | 92.5% | 6.6 pp | 87.5% to 100.0% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 1.8% | 0.9 pp | 1.2% to 2.8% |
| Block rate (all) | 2.6% | 0.2 pp | 2.5% to 2.9% |
| Block rate (non-benign) | 2.9% | 0.3 pp | 2.8% to 3.2% |
| Over-block on benign | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Benign cases with any masking | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Over-redaction (must_keep strings missing) | 5.3% | 0.4 pp | 4.8% to 5.6% |
| Over-redaction (cases with any missing) | 11.6% | 0.7 pp | 11.0% to 12.3% |
| Local overhead, mean (ms) | 4403 | 311.8 | 4207 to 4762 |
| Local overhead, p95 (ms) | 9379 | 1145.2 | 8588 to 10692 |
| Client wall time, mean (ms) | 8197 | 301.0 | 7969 to 8538 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 2.5% ± 2.1 | 3.7% ± 0.0 | 2.9% ± 2.5 | 88.9% ± 9.6 | n/a |
| benign | n/a | 0.0% ± 0.0 | 7.3% ± 1.8 | n/a | 0.0% ± 0.0 |
| direct_pii | 0.0% ± 0.0 | 2.5% ± 4.3 | 0.4% ± 0.8 | 100.0% ± 0.0 | n/a |
| finance | 0.0% ± 0.0 | 1.2% ± 2.1 | 3.8% ± 2.1 | 100.0% ± 0.0 | n/a |
| health | 0.0% ± 0.0 | 0.0% ± 0.0 | 3.9% ± 1.3 | n/a | n/a |
| intent_leak_search | 1.2% ± 2.1 | 13.6% ± 5.7 | 59.5% ± 0.4 | 100.0% ± 0.0 | n/a |
| quasi_identifier | 19.8% ± 2.1 | 0.0% ± 0.0 | 1.1% ± 1.0 | n/a | n/a |
| secrets_in_code | 0.0% ± 0.0 | 2.5% ± 2.1 | 0.5% ± 0.8 | 100.0% ± 0.0 | n/a |
| vault_terms | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.5% ± 0.8 | n/a | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 3.4% ± 0.5 | 4.7% ± 0.5 | 3.1% ± 0.7 |
| ko | 2.4% ± 0.5 | 0.5% ± 0.9 | 7.5% ± 1.0 |

## Pass independence

- Byte-identical outbound payloads in all 3 passes: 138 of 232 cases (59.5%)
- Detect time p50 by pass: 3,632 / 3,608 / 3,378 ms
- Detector temperature: 0.6

## Cases that leaked in any pass

4 case(s) leaked in every pass; 6 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| qid-en-05 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-06 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-11 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-10 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-02 | quasi_identifier | ko | 2/3 | quasi-identifier group ≥k: 2 |
| adv-ko-08 | adversarial | ko | 1/3 | `731521-1385835`: 1, digits |
| adv-ko-14 | adversarial | ko | 1/3 | `taeyang1704@example.net`: 1, decoded:exact |
| int-en-07 | intent_leak_search | en | 1/3 | quasi-identifier group ≥k: 1 |
| qid-en-02 | quasi_identifier | en | 1/3 | quasi-identifier group ≥k: 1 |
| qid-ko-04 | quasi_identifier | ko | 1/3 | quasi-identifier group ≥k: 1 |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|
| ben-en-04 | en | 0/3 | 0/3 | `Marie Curie` (1) |
| ben-en-07 | en | 0/3 | 0/3 | `free-threaded` (3) |
| ben-ko-05 | ko | 0/3 | 0/3 | `최저임금` (3) |
| ben-ko-08 | ko | 0/3 | 0/3 | `서울 부산` (3) |
| ben-ko-13 | ko | 0/3 | 0/3 | `불국사` (1), `석굴암` (1) |

## Value outcomes (summed over passes)

- `detected_removed`: 1533
- `removed_unattributed`: 464
- `gate_saved`: 35
- `missed_leaked`: 2
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
