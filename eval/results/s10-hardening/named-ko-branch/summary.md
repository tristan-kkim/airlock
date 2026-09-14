# Airlock eval summary

- Target: `http://127.0.0.1:8800` (airlock 918b747 (feat/s10-hardening), stub upstream, named-ko ids (local scan only))
- Passes: 2 · cases per pass: 8 · protection level: `balanced`
- Dataset sha256: `cd40ce707652d30ffb2007c5ccaac62c61709d42382c4c623351b5114c850609`
- Harness version: 1.0.0 · started 2026-09-14T14:42:45.380454+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Leak rate (individual values) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Leak rate (exact-string hits only) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Canary leak rate | n/a | n/a | n/a |
| Quasi-identifier re-identification rate | n/a | n/a | n/a |
| Identity leak (any identity item or identifying quasi set) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Gate save rate (upper bound: request-level) | n/a | n/a | n/a |
| Gate save rate (lower bound: hash-attributed) | n/a | n/a | n/a |
| Values that got past the detectors | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Block rate (all) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Block rate (non-benign) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Over-block on benign | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Benign cases with any masking | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Over-redaction (must_keep strings missing) | 6.2% | 0.0 pp | 6.2% to 6.2% |
| Over-redaction (cases with any missing) | 12.5% | 0.0 pp | 12.5% to 12.5% |
| Local overhead, mean (ms) | 3124 | 907.6 | 2482 to 3766 |
| Local overhead, p95 (ms) | 6165 | 2303.2 | 4536 to 7793 |
| Client wall time, mean (ms) | 3128 | 907.9 | 2486 to 3770 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |
| benign | n/a | 0.0% ± 0.0 | 16.7% ± 0.0 | n/a | 0.0% ± 0.0 |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| ko | 0.0% ± 0.0 | 0.0% ± 0.0 | 6.2% ± 0.0 |

## Pass independence

- Byte-identical outbound payloads in all 2 passes: 7 of 8 cases (87.5%)
- Detect time p50 by pass: 3,125 / 1,834 ms
- Detector temperature: 0.6
- **Warning:** 87.5% of cases sent byte-identical payloads in all 2 passes although the detector samples at temperature 0.6; the passes are probably not independent (was the server reset before every pass?)

## Cases that leaked in any pass

0 case(s) leaked in every pass; 0 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|
| ben-ko-08 | ko | 0/2 | 0/2 | `서울 부산` (2) |

## Value outcomes (summed over passes)

- `detected_removed`: 8
- `removed_unattributed`: 14
- `gate_saved`: 0
- `missed_leaked`: 0
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
