# Airlock eval summary

- Target: `http://127.0.0.1:8800` (airlock 39281fb (feat/s10-hardening), AIRLOCK_GLINER=on, placeholder, dev split, stub upstream (scanner metrics only))
- Passes: 2 · cases per pass: 72 · protection level: `balanced`
- Dataset sha256: `96855eb04745e708a67efc966d6eb2d9d3226e8a4a9ff77f4a41691390c9c7ad`
- Harness version: 1.0.0 · started 2026-09-14T13:55:58.270915+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 2.3% | 1.1 pp | 1.6% to 3.1% |
| Leak rate (individual values) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Leak rate (exact-string hits only) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Canary leak rate | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Quasi-identifier re-identification rate | 10.7% | 5.1 pp | 7.1% to 14.3% |
| Identity leak (any identity item or identifying quasi set) | 2.4% | 1.1 pp | 1.6% to 3.2% |
| Gate save rate (upper bound: request-level) | n/a | n/a | n/a |
| Gate save rate (lower bound: hash-attributed) | n/a | n/a | n/a |
| Values that got past the detectors | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Block rate (all) | 0.7% | 1.0 pp | 0.0% to 1.4% |
| Block rate (non-benign) | 0.8% | 1.1 pp | 0.0% to 1.6% |
| Over-block on benign | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Benign cases with any masking | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Over-redaction (must_keep strings missing) | 5.6% | 0.4 pp | 5.3% to 5.8% |
| Over-redaction (cases with any missing) | 13.3% | 0.9 pp | 12.7% to 13.9% |
| Local overhead, mean (ms) | 4330 | 297.7 | 4119 to 4540 |
| Local overhead, p95 (ms) | 9731 | 827.3 | 9146 to 10316 |
| Client wall time, mean (ms) | 4334 | 297.7 | 4124 to 4545 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |
| benign | n/a | 0.0% ± 0.0 | 5.9% ± 0.0 | n/a | 0.0% ± 0.0 |
| direct_pii | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |
| finance | 0.0% ± 0.0 | 0.0% ± 0.0 | 4.0% ± 0.0 | n/a | n/a |
| health | 0.0% ± 0.0 | 0.0% ± 0.0 | 2.5% ± 3.5 | n/a | n/a |
| intent_leak_search | 0.0% ± 0.0 | 6.2% ± 8.8 | 59.6% ± 5.7 | n/a | n/a |
| quasi_identifier | 18.8% ± 8.8 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |
| secrets_in_code | 0.0% ± 0.0 | 0.0% ± 0.0 | 4.8% ± 0.0 | n/a | n/a |
| vault_terms | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 4.7% ± 2.2 | 1.4% ± 2.0 | 4.7% ± 1.6 |
| ko | 0.0% ± 0.0 | 0.0% ± 0.0 | 6.4% ± 0.8 |

## Pass independence

- Byte-identical outbound payloads in all 2 passes: 44 of 71 cases (62.0%)
- Detect time p50 by pass: 4,007 / 4,045 ms
- Detector temperature: 0.6

## Cases that leaked in any pass

1 case(s) leaked in every pass; 1 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| qid-en-06 | quasi_identifier | en | 2/2 | quasi-identifier group ≥k: 2 |
| qid-en-05 | quasi_identifier | en | 1/2 | quasi-identifier group ≥k: 1 |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|
| ben-en-07 | en | 0/2 | 0/2 | `free-threaded` (2) |

## Value outcomes (summed over passes)

- `detected_removed`: 306
- `removed_unattributed`: 100
- `gate_saved`: 0
- `missed_leaked`: 0
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
