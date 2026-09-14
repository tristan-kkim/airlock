# Airlock eval summary

- Target: `http://127.0.0.1:8800` (airlock 4236df9 (main), AIRLOCK_GLINER=on, placeholder, dev split, stub upstream (scanner metrics only))
- Passes: 2 · cases per pass: 72 · protection level: `balanced`
- Dataset sha256: `96855eb04745e708a67efc966d6eb2d9d3226e8a4a9ff77f4a41691390c9c7ad`
- Harness version: 1.0.0 · started 2026-09-14T13:28:16.846228+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 7.8% | 0.0 pp | 7.8% to 7.8% |
| Leak rate (individual values) | 0.5% | 0.0 pp | 0.5% to 0.5% |
| Leak rate (exact-string hits only) | 0.8% | 1.1 pp | 0.0% to 1.6% |
| Canary leak rate | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Quasi-identifier re-identification rate | 28.6% | 0.0 pp | 28.6% to 28.6% |
| Identity leak (any identity item or identifying quasi set) | 8.9% | 1.1 pp | 8.1% to 9.7% |
| Gate save rate (upper bound: request-level) | 83.9% | 12.6 pp | 75.0% to 92.9% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 4.4% | 3.5 pp | 2.0% to 6.9% |
| Block rate (all) | 2.8% | 2.0 pp | 1.4% to 4.2% |
| Block rate (non-benign) | 3.1% | 2.2 pp | 1.6% to 4.7% |
| Over-block on benign | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Benign cases with any masking | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Over-redaction (must_keep strings missing) | 5.7% | 0.3 pp | 5.5% to 6.0% |
| Over-redaction (cases with any missing) | 13.6% | 0.7 pp | 13.0% to 14.1% |
| Local overhead, mean (ms) | 4089 | 251.8 | 3911 to 4267 |
| Local overhead, p95 (ms) | 7811 | 199.7 | 7669 to 7952 |
| Client wall time, mean (ms) | 4093 | 251.6 | 3915 to 4271 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 6.2% ± 8.8 | 6.2% ± 8.8 | 7.7% ± 0.8 | 83.3% ± 0.0 | n/a |
| benign | n/a | 0.0% ± 0.0 | 5.9% ± 0.0 | n/a | 0.0% ± 0.0 |
| direct_pii | 0.0% ± 0.0 | 12.5% ± 17.7 | 0.0% ± 0.0 | 100.0% ± 0.0 | n/a |
| finance | 6.2% ± 8.8 | 6.2% ± 8.8 | 4.3% ± 0.4 | 75.0% ± 0.0 | n/a |
| health | 0.0% ± 0.0 | 0.0% ± 0.0 | 2.5% ± 3.5 | n/a | n/a |
| intent_leak_search | 0.0% ± 0.0 | 0.0% ± 0.0 | 50.0% ± 6.4 | n/a | n/a |
| quasi_identifier | 50.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |
| secrets_in_code | 0.0% ± 0.0 | 0.0% ± 0.0 | 2.4% ± 3.4 | n/a | n/a |
| vault_terms | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 9.4% ± 0.0 | 1.4% ± 2.0 | 3.6% ± 0.1 |
| ko | 6.2% ± 0.0 | 4.2% ± 2.0 | 8.0% ± 0.7 |

## Pass independence

- Byte-identical outbound payloads in all 2 passes: 40 of 68 cases (58.8%)
- Detect time p50 by pass: 3,722 / 3,280 ms
- Detector temperature: 0.6

## Cases that leaked in any pass

3 case(s) leaked in every pass; 4 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| qid-en-06 | quasi_identifier | en | 2/2 | quasi-identifier group ≥k: 2 |
| qid-en-10 | quasi_identifier | en | 2/2 | quasi-identifier group ≥k: 2 |
| qid-ko-14 | quasi_identifier | ko | 2/2 | quasi-identifier group ≥k: 2 |
| adv-ko-08 | adversarial | ko | 1/2 | `최주원`: 1, whitespace |
| fin-ko-10 | finance | ko | 1/2 | `권소율`: 1, exact |
| qid-en-04 | quasi_identifier | en | 1/2 | quasi-identifier group ≥k: 1 |
| qid-en-05 | quasi_identifier | en | 1/2 | quasi-identifier group ≥k: 1 |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|
| ben-en-07 | en | 0/2 | 0/2 | `free-threaded` (2) |

## Value outcomes (summed over passes)

- `detected_removed`: 289
- `removed_unattributed`: 99
- `gate_saved`: 16
- `missed_leaked`: 2
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
