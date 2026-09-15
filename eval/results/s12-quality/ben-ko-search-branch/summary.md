# Airlock eval summary

- Target: `http://127.0.0.1:8800` (airlock feat/s12-quality, stub upstream, benign Korean search cases (local scan only))
- Passes: 2 · cases per pass: 3 · protection level: `balanced`
- Dataset sha256: `cd40ce707652d30ffb2007c5ccaac62c61709d42382c4c623351b5114c850609`
- Harness version: 1.0.0 · started 2026-09-15T02:16:43.521111+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | n/a | n/a | n/a |
| Leak rate (individual values) | n/a | n/a | n/a |
| Leak rate (exact-string hits only) | n/a | n/a | n/a |
| Canary leak rate | n/a | n/a | n/a |
| Quasi-identifier re-identification rate | n/a | n/a | n/a |
| Identity leak (any identity item or identifying quasi set) | n/a | n/a | n/a |
| Gate save rate (upper bound: request-level) | n/a | n/a | n/a |
| Gate save rate (lower bound: hash-attributed) | n/a | n/a | n/a |
| Values that got past the detectors | n/a | n/a | n/a |
| Block rate (all) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Block rate (non-benign) | n/a | n/a | n/a |
| Over-block on benign | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Benign cases with any masking | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Over-redaction (must_keep strings missing) | 40.0% | 0.0 pp | 40.0% to 40.0% |
| Over-redaction (cases with any missing) | 66.7% | 0.0 pp | 66.7% to 66.7% |
| Local overhead, mean (ms) | 4284 | 4062.7 | 1412 to 7157 |
| Local overhead, p95 (ms) | 9888 | 10722.6 | 2306 to 17471 |
| Client wall time, mean (ms) | 4289 | 4063.9 | 1415 to 7162 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| benign | n/a | 0.0% ± 0.0 | 40.0% ± 0.0 | n/a | 0.0% ± 0.0 |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| ko | n/a | 0.0% ± 0.0 | 40.0% ± 0.0 |

## Pass independence

- Byte-identical outbound payloads in all 2 passes: 2 of 3 cases (66.7%)
- Detect time p50 by pass: 456 / 419 ms
- Detector temperature: 0.6

## Cases that leaked in any pass

0 case(s) leaked in every pass; 0 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|
| ben-ko-05 | ko | 0/2 | 0/2 | `최저임금` (2) |
| ben-ko-08 | ko | 0/2 | 0/2 | `서울 부산` (2) |

## Value outcomes (summed over passes)

- `detected_removed`: 0
- `removed_unattributed`: 0
- `gate_saved`: 0
- `missed_leaked`: 0
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
