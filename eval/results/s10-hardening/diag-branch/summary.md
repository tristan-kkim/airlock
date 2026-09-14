# Airlock eval summary

- Target: `http://127.0.0.1:8800` (airlock 39281fb (feat/s10-hardening), stub upstream, diag ids (local scan only))
- Passes: 2 · cases per pass: 9 · protection level: `balanced`
- Dataset sha256: `cd40ce707652d30ffb2007c5ccaac62c61709d42382c4c623351b5114c850609`
- Harness version: 1.0.0 · started 2026-09-14T14:38:53.596183+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 16.7% | 7.9 pp | 11.1% to 22.2% |
| Leak rate (individual values) | n/a | n/a | n/a |
| Leak rate (exact-string hits only) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Canary leak rate | n/a | n/a | n/a |
| Quasi-identifier re-identification rate | 16.7% | 7.9 pp | 11.1% to 22.2% |
| Identity leak (any identity item or identifying quasi set) | 16.7% | 7.9 pp | 11.1% to 22.2% |
| Gate save rate (upper bound: request-level) | n/a | n/a | n/a |
| Gate save rate (lower bound: hash-attributed) | n/a | n/a | n/a |
| Values that got past the detectors | n/a | n/a | n/a |
| Block rate (all) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Block rate (non-benign) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Over-block on benign | n/a | n/a | n/a |
| Benign cases with any masking | n/a | n/a | n/a |
| Over-redaction (must_keep strings missing) | 2.4% | 3.4 pp | 0.0% to 4.8% |
| Over-redaction (cases with any missing) | 5.6% | 7.9 pp | 0.0% to 11.1% |
| Local overhead, mean (ms) | 2269 | 1212.2 | 1412 to 3126 |
| Local overhead, p95 (ms) | 6497 | 3473.2 | 4041 to 8953 |
| Client wall time, mean (ms) | 2273 | 1212.7 | 1415 to 3130 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| quasi_identifier | 16.7% ± 7.9 | 0.0% ± 0.0 | 2.4% ± 3.4 | n/a | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 25.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 |
| ko | 10.0% ± 14.1 | 0.0% ± 0.0 | 3.8% ± 5.4 |

## Pass independence

- Byte-identical outbound payloads in all 2 passes: 6 of 9 cases (66.7%)
- Detect time p50 by pass: 2,181 / 501 ms
- Detector temperature: 0.6
- **Warning:** detect p50 fell from 2181 ms in pass 1 to 501 ms later; the passes are probably not independent (was the server reset before every pass?)

## Cases that leaked in any pass

1 case(s) leaked in every pass; 1 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| qid-en-11 | quasi_identifier | en | 2/2 | quasi-identifier group ≥k: 2 |
| qid-ko-10 | quasi_identifier | ko | 1/2 | quasi-identifier group ≥k: 1 |

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
