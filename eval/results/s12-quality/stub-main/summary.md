# Airlock eval summary

- Target: `http://127.0.0.1:8800` (airlock d97a815 (main), AIRLOCK_GLINER=on, placeholder, dev split, stub upstream (scanner metrics only))
- Passes: 2 · cases per pass: 72 · protection level: `balanced`
- Dataset sha256: `96855eb04745e708a67efc966d6eb2d9d3226e8a4a9ff77f4a41691390c9c7ad`
- Harness version: 1.0.0 · started 2026-09-15T02:06:24.495816+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 0.8% | 1.1 pp | 0.0% to 1.6% |
| Leak rate (individual values) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Leak rate (exact-string hits only) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Canary leak rate | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Quasi-identifier re-identification rate | 3.6% | 5.1 pp | 0.0% to 7.1% |
| Identity leak (any identity item or identifying quasi set) | 2.4% | 1.1 pp | 1.6% to 3.2% |
| Gate save rate (upper bound: request-level) | 100.0% | 0.0 pp | 100.0% to 100.0% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 0.7% | 1.0 pp | 0.0% to 1.5% |
| Block rate (all) | 0.7% | 1.0 pp | 0.0% to 1.4% |
| Block rate (non-benign) | 0.8% | 1.1 pp | 0.0% to 1.6% |
| Over-block on benign | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Benign cases with any masking | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Over-redaction (must_keep strings missing) | 5.9% | 0.0 pp | 5.8% to 5.9% |
| Over-redaction (cases with any missing) | 14.0% | 0.1 pp | 13.9% to 14.1% |
| Local overhead, mean (ms) | 3701 | 69.4 | 3652 to 3751 |
| Local overhead, p95 (ms) | 7626 | 356.9 | 7374 to 7878 |
| Client wall time, mean (ms) | 3706 | 69.2 | 3657 to 3755 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 0.0% ± 0.0 | 6.2% ± 8.8 | 0.0% ± 0.0 | 100.0% ± 0.0 | n/a |
| benign | n/a | 0.0% ± 0.0 | 5.9% ± 0.0 | n/a | 0.0% ± 0.0 |
| direct_pii | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |
| finance | 0.0% ± 0.0 | 0.0% ± 0.0 | 4.0% ± 0.0 | n/a | n/a |
| health | 0.0% ± 0.0 | 0.0% ± 0.0 | 2.5% ± 3.5 | n/a | n/a |
| intent_leak_search | 0.0% ± 0.0 | 0.0% ± 0.0 | 59.1% ± 6.4 | n/a | n/a |
| quasi_identifier | 6.2% ± 8.8 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |
| secrets_in_code | 0.0% ± 0.0 | 0.0% ± 0.0 | 4.8% ± 0.0 | n/a | n/a |
| vault_terms | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 1.6% ± 2.2 | 0.0% ± 0.0 | 5.3% ± 0.8 |
| ko | 0.0% ± 0.0 | 1.4% ± 2.0 | 6.5% ± 0.7 |

## Pass independence

- Byte-identical outbound payloads in all 2 passes: 40 of 71 cases (56.3%)
- Detect time p50 by pass: 3,223 / 3,347 ms
- Detector temperature: 0.6

## Cases that leaked in any pass

0 case(s) leaked in every pass; 1 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| qid-en-05 | quasi_identifier | en | 1/2 | quasi-identifier group ≥k: 1 |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|
| ben-en-07 | en | 0/2 | 0/2 | `free-threaded` (2) |

## Value outcomes (summed over passes)

- `detected_removed`: 0
- `removed_unattributed`: 403
- `gate_saved`: 3
- `missed_leaked`: 0
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
