# Airlock eval summary

- Target: `http://127.0.0.1:8799` (airlock 2e92453 (main), AIRLOCK_GLINER=on, placeholder, dev split)
- Passes: 1 · cases per pass: 72 · protection level: `balanced`
- Dataset sha256: `96855eb04745e708a67efc966d6eb2d9d3226e8a4a9ff77f4a41691390c9c7ad`
- Harness version: 1.0.0 · started 2026-09-13T23:24:03.867719+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 4.7% | 0.0 pp | 4.7% to 4.7% |
| Leak rate (individual values) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Leak rate (exact-string hits only) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Canary leak rate | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Quasi-identifier re-identification rate | 21.4% | 0.0 pp | 21.4% to 21.4% |
| Identity leak (any identity item or identifying quasi set) | 6.5% | 0.0 pp | 6.5% to 6.5% |
| Gate save rate (upper bound: request-level) | 100.0% | 0.0 pp | 100.0% to 100.0% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 6.9% | 0.0 pp | 6.9% to 6.9% |
| Block rate (all) | 5.6% | 0.0 pp | 5.6% to 5.6% |
| Block rate (non-benign) | 6.2% | 0.0 pp | 6.2% to 6.2% |
| Over-block on benign | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Benign cases with any masking | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Over-redaction (must_keep strings missing) | 9.9% | 0.0 pp | 9.9% to 9.9% |
| Over-redaction (cases with any missing) | 22.1% | 0.0 pp | 22.1% to 22.1% |
| Local overhead, mean (ms) | 4985 | 0.0 | 4985 to 4985 |
| Local overhead, p95 (ms) | 9353 | 0.0 | 9353 to 9353 |
| Client wall time, mean (ms) | 8394 | 0.0 | 8394 to 8394 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 0.0% ± 0.0 | 0.0% ± 0.0 | 7.1% ± 0.0 | n/a | n/a |
| benign | n/a | 0.0% ± 0.0 | 5.9% ± 0.0 | n/a | 0.0% ± 0.0 |
| direct_pii | 0.0% ± 0.0 | 25.0% ± 0.0 | 0.0% ± 0.0 | 100.0% ± 0.0 | n/a |
| finance | 0.0% ± 0.0 | 12.5% ± 0.0 | 9.1% ± 0.0 | 100.0% ± 0.0 | n/a |
| health | 0.0% ± 0.0 | 0.0% ± 0.0 | 15.0% ± 0.0 | n/a | n/a |
| intent_leak_search | 0.0% ± 0.0 | 0.0% ± 0.0 | 63.6% ± 0.0 | n/a | n/a |
| quasi_identifier | 37.5% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |
| secrets_in_code | 0.0% ± 0.0 | 12.5% ± 0.0 | 10.5% ± 0.0 | 100.0% ± 0.0 | n/a |
| vault_terms | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 6.2% ± 0.0 | 5.6% ± 0.0 | 10.0% ± 0.0 |
| ko | 3.1% ± 0.0 | 5.6% ± 0.0 | 9.9% ± 0.0 |

## Cases that leaked in any pass

3 case(s) leaked in every pass; 0 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| qid-en-04 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-06 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-14 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|
| ben-en-07 | en | 0/1 | 0/1 | `free-threaded` (1) |

## Value outcomes (summed over passes)

- `detected_removed`: 128
- `removed_unattributed`: 61
- `gate_saved`: 14
- `missed_leaked`: 0
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
