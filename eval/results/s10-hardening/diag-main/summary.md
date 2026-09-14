# Airlock eval summary

- Target: `http://127.0.0.1:8800` (airlock 4236df9 (main), stub upstream, diag ids (local scan only))
- Passes: 2 · cases per pass: 9 · protection level: `balanced`
- Dataset sha256: `cd40ce707652d30ffb2007c5ccaac62c61709d42382c4c623351b5114c850609`
- Harness version: 1.0.0 · started 2026-09-14T14:38:12.162034+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 88.9% | 15.7 pp | 77.8% to 100.0% |
| Leak rate (individual values) | n/a | n/a | n/a |
| Leak rate (exact-string hits only) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Canary leak rate | n/a | n/a | n/a |
| Quasi-identifier re-identification rate | 88.9% | 15.7 pp | 77.8% to 100.0% |
| Identity leak (any identity item or identifying quasi set) | 88.9% | 15.7 pp | 77.8% to 100.0% |
| Gate save rate (upper bound: request-level) | n/a | n/a | n/a |
| Gate save rate (lower bound: hash-attributed) | n/a | n/a | n/a |
| Values that got past the detectors | n/a | n/a | n/a |
| Block rate (all) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Block rate (non-benign) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Over-block on benign | n/a | n/a | n/a |
| Benign cases with any masking | n/a | n/a | n/a |
| Over-redaction (must_keep strings missing) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Over-redaction (cases with any missing) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Local overhead, mean (ms) | 2206 | 1020.7 | 1485 to 2928 |
| Local overhead, p95 (ms) | 6219 | 3428.6 | 3795 to 8644 |
| Client wall time, mean (ms) | 2209 | 1021.2 | 1487 to 2932 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| quasi_identifier | 88.9% ± 15.7 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 87.5% ± 17.7 | 0.0% ± 0.0 | 0.0% ± 0.0 |
| ko | 90.0% ± 14.1 | 0.0% ± 0.0 | 0.0% ± 0.0 |

## Pass independence

- Byte-identical outbound payloads in all 2 passes: 6 of 9 cases (66.7%)
- Detect time p50 by pass: 2,186 / 500 ms
- Detector temperature: 0.6
- **Warning:** detect p50 fell from 2186 ms in pass 1 to 500 ms later; the passes are probably not independent (was the server reset before every pass?)

## Cases that leaked in any pass

7 case(s) leaked in every pass; 2 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| qid-en-08 | quasi_identifier | en | 2/2 | quasi-identifier group ≥k: 2 |
| qid-en-10 | quasi_identifier | en | 2/2 | quasi-identifier group ≥k: 2 |
| qid-en-11 | quasi_identifier | en | 2/2 | quasi-identifier group ≥k: 2 |
| qid-ko-08 | quasi_identifier | ko | 2/2 | quasi-identifier group ≥k: 2 |
| qid-ko-10 | quasi_identifier | ko | 2/2 | quasi-identifier group ≥k: 2 |
| qid-ko-11 | quasi_identifier | ko | 2/2 | quasi-identifier group ≥k: 2 |
| qid-ko-14 | quasi_identifier | ko | 2/2 | quasi-identifier group ≥k: 2 |
| qid-en-04 | quasi_identifier | en | 1/2 | quasi-identifier group ≥k: 1 |
| qid-ko-07 | quasi_identifier | ko | 1/2 | quasi-identifier group ≥k: 1 |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|

## Value outcomes (summed over passes)

- `detected_removed`: 0
- `removed_unattributed`: 0
- `gate_saved`: 0
- `missed_leaked`: 0
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
