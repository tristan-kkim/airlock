# Airlock eval summary

- Target: `http://127.0.0.1:8799` (airlock 91d21f3 (feat/distortion), AIRLOCK_GLINER=on, placeholder, dev split, stub upstream (scanner metrics only))
- Passes: 3 · cases per pass: 72 · protection level: `balanced`
- Dataset sha256: `96855eb04745e708a67efc966d6eb2d9d3226e8a4a9ff77f4a41691390c9c7ad`
- Harness version: 1.0.0 · started 2026-09-14T00:22:18.106302+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 4.7% | 0.0 pp | 4.7% to 4.7% |
| Leak rate (individual values) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Leak rate (exact-string hits only) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Canary leak rate | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Quasi-identifier re-identification rate | 21.4% | 0.0 pp | 21.4% to 21.4% |
| Identity leak (any identity item or identifying quasi set) | 8.1% | 0.0 pp | 8.1% to 8.1% |
| Gate save rate (upper bound: request-level) | 100.0% | 0.0 pp | 100.0% to 100.0% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 7.1% | 10.2 pp | 0.0% to 18.7% |
| Block rate (all) | 4.6% | 5.8 pp | 0.0% to 11.1% |
| Block rate (non-benign) | 5.2% | 6.5 pp | 0.0% to 12.5% |
| Over-block on benign | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Benign cases with any masking | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Over-redaction (must_keep strings missing) | 4.9% | 0.4 pp | 4.7% to 5.4% |
| Over-redaction (cases with any missing) | 11.2% | 0.2 pp | 10.9% to 11.4% |
| Local overhead, mean (ms) | 3507 | 3335.7 | 859 to 7254 |
| Local overhead, p95 (ms) | 15078 | 13995.8 | 2251 to 30005 |
| Client wall time, mean (ms) | 3511 | 3335.3 | 863 to 7257 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 0.0% ± 0.0 | 8.3% ± 7.2 | 7.9% ± 0.7 | 100.0% ± 0.0 | n/a |
| benign | n/a | 0.0% ± 0.0 | 5.9% ± 0.0 | n/a | 0.0% ± 0.0 |
| direct_pii | 0.0% ± 0.0 | 4.2% ± 7.2 | 0.0% ± 0.0 | 100.0% ± 0.0 | n/a |
| finance | 0.0% ± 0.0 | 8.3% ± 14.4 | 4.4% ± 0.7 | 100.0% ± 0.0 | n/a |
| health | 0.0% ± 0.0 | 4.2% ± 7.2 | 3.3% ± 2.9 | 100.0% ± 0.0 | n/a |
| intent_leak_search | 0.0% ± 0.0 | 4.2% ± 7.2 | 40.6% ± 4.6 | n/a | n/a |
| quasi_identifier | 37.5% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |
| secrets_in_code | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |
| vault_terms | 0.0% ± 0.0 | 12.5% ± 21.7 | 0.0% ± 0.0 | 100.0% ± 0.0 | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 6.2% ± 0.0 | 4.6% ± 5.8 | 2.5% ± 1.4 |
| ko | 3.1% ± 0.0 | 4.6% ± 5.8 | 7.3% ± 0.8 |

## Cases that leaked in any pass

3 case(s) leaked in every pass; 0 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| qid-en-04 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-10 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-14 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|
| ben-en-07 | en | 0/3 | 0/3 | `free-threaded` (3) |

## Value outcomes (summed over passes)

- `detected_removed`: 420
- `removed_unattributed`: 146
- `gate_saved`: 43
- `missed_leaked`: 0
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
