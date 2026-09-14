# Airlock eval summary

- Target: `http://127.0.0.1:8800` (airlock 39281fb (feat/s10-hardening), AIRLOCK_GLINER=on, placeholder, dev split)
- Passes: 1 · cases per pass: 72 · protection level: `balanced`
- Dataset sha256: `96855eb04745e708a67efc966d6eb2d9d3226e8a4a9ff77f4a41691390c9c7ad`
- Harness version: 1.0.0 · started 2026-09-14T14:17:36.440979+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 6.2% | 0.0 pp | 6.2% to 6.2% |
| Leak rate (individual values) | 0.5% | 0.0 pp | 0.5% to 0.5% |
| Leak rate (exact-string hits only) | 1.6% | 0.0 pp | 1.6% to 1.6% |
| Canary leak rate | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Quasi-identifier re-identification rate | 21.4% | 0.0 pp | 21.4% to 21.4% |
| Identity leak (any identity item or identifying quasi set) | 6.5% | 0.0 pp | 6.5% to 6.5% |
| Gate save rate (upper bound: request-level) | 75.0% | 0.0 pp | 75.0% to 75.0% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 2.0% | 0.0 pp | 2.0% to 2.0% |
| Block rate (all) | 1.4% | 0.0 pp | 1.4% to 1.4% |
| Block rate (non-benign) | 1.6% | 0.0 pp | 1.6% to 1.6% |
| Over-block on benign | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Benign cases with any masking | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Over-redaction (must_keep strings missing) | 7.1% | 0.0 pp | 7.1% to 7.1% |
| Over-redaction (cases with any missing) | 15.5% | 0.0 pp | 15.5% to 15.5% |
| Local overhead, mean (ms) | 5050 | 0.0 | 5050 to 5050 |
| Local overhead, p95 (ms) | 11454 | 0.0 | 11454 to 11454 |
| Client wall time, mean (ms) | 8850 | 0.0 | 8850 to 8850 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 0.0% ± 0.0 | 0.0% ± 0.0 | 7.1% ± 0.0 | n/a | n/a |
| benign | n/a | 0.0% ± 0.0 | 5.9% ± 0.0 | n/a | 0.0% ± 0.0 |
| direct_pii | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |
| finance | 12.5% ± 0.0 | 0.0% ± 0.0 | 8.0% ± 0.0 | 0.0% ± 0.0 | n/a |
| health | 0.0% ± 0.0 | 12.5% ± 0.0 | 0.0% ± 0.0 | 100.0% ± 0.0 | n/a |
| intent_leak_search | 0.0% ± 0.0 | 0.0% ± 0.0 | 72.7% ± 0.0 | n/a | n/a |
| quasi_identifier | 37.5% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |
| secrets_in_code | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |
| vault_terms | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 9.4% ± 0.0 | 0.0% ± 0.0 | 8.2% ± 0.0 |
| ko | 3.1% ± 0.0 | 2.8% ± 0.0 | 6.0% ± 0.0 |

## Cases that leaked in any pass

4 case(s) leaked in every pass; 0 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| fin-ko-10 | finance | ko | 1/1 | `권소율`: 1, exact |
| qid-en-04 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-05 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-06 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|
| ben-en-07 | en | 0/1 | 0/1 | `free-threaded` (1) |

## Value outcomes (summed over passes)

- `detected_removed`: 149
- `removed_unattributed`: 50
- `gate_saved`: 3
- `missed_leaked`: 1
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
