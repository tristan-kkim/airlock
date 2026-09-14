# Airlock eval summary

- Target: `http://127.0.0.1:8800` (airlock 4236df9 (main), stub upstream, named-ko ids (local scan only))
- Passes: 2 · cases per pass: 8 · protection level: `balanced`
- Dataset sha256: `cd40ce707652d30ffb2007c5ccaac62c61709d42382c4c623351b5114c850609`
- Harness version: 1.0.0 · started 2026-09-14T14:39:36.037135+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 30.0% | 14.1 pp | 20.0% to 40.0% |
| Leak rate (individual values) | 13.6% | 6.4 pp | 9.1% to 18.2% |
| Leak rate (exact-string hits only) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Canary leak rate | n/a | n/a | n/a |
| Quasi-identifier re-identification rate | n/a | n/a | n/a |
| Identity leak (any identity item or identifying quasi set) | 30.0% | 14.1 pp | 20.0% to 40.0% |
| Gate save rate (upper bound: request-level) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 13.6% | 6.4 pp | 9.1% to 18.2% |
| Block rate (all) | 25.0% | 0.0 pp | 25.0% to 25.0% |
| Block rate (non-benign) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Over-block on benign | 66.7% | 0.0 pp | 66.7% to 66.7% |
| Benign cases with any masking | 100.0% | 0.0 pp | 100.0% to 100.0% |
| Over-redaction (must_keep strings missing) | 25.0% | 0.0 pp | 25.0% to 25.0% |
| Over-redaction (cases with any missing) | 50.0% | 0.0 pp | 50.0% to 50.0% |
| Local overhead, mean (ms) | 3991 | 656.4 | 3527 to 4455 |
| Local overhead, p95 (ms) | 6658 | 1971.0 | 5264 to 8052 |
| Client wall time, mean (ms) | 3994 | 656.4 | 3529 to 4458 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 30.0% ± 14.1 | 0.0% ± 0.0 | 20.0% ± 0.0 | 0.0% ± 0.0 | n/a |
| benign | n/a | 66.7% ± 0.0 | 50.0% ± 0.0 | n/a | 100.0% ± 0.0 |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| ko | 30.0% ± 14.1 | 25.0% ± 0.0 | 25.0% ± 0.0 |

## Pass independence

- Byte-identical outbound payloads in all 2 passes: 3 of 6 cases (50.0%)
- Detect time p50 by pass: 3,588 / 2,567 ms
- Detector temperature: 0.6

## Cases that leaked in any pass

1 case(s) leaked in every pass; 1 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| adv-ko-07 | adversarial | ko | 2/2 | `정민준`: 2, alnum |
| adv-ko-13 | adversarial | ko | 1/2 | `5127214713788210`: 1, digits |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|
| ben-ko-08 | ko | 2/2 | 2/2 | - |
| ben-ko-13 | ko | 2/2 | 2/2 | - |
| ben-ko-09 | ko | 0/2 | 2/2 | `장영실` (2) |

## Value outcomes (summed over passes)

- `detected_removed`: 6
- `removed_unattributed`: 13
- `gate_saved`: 0
- `missed_leaked`: 3
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
