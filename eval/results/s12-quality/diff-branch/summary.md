# Airlock eval summary

- Target: `http://127.0.0.1:8800` (airlock feat/s12-quality, stub upstream, the 4 dev cases that differed from main (local scan only))
- Passes: 4 · cases per pass: 4 · protection level: `balanced`
- Dataset sha256: `cd40ce707652d30ffb2007c5ccaac62c61709d42382c4c623351b5114c850609`
- Harness version: 1.0.0 · started 2026-09-15T02:28:16.405720+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 43.8% | 12.5 pp | 25.0% to 50.0% |
| Leak rate (individual values) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Leak rate (exact-string hits only) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Canary leak rate | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Quasi-identifier re-identification rate | 87.5% | 25.0 pp | 50.0% to 100.0% |
| Identity leak (any identity item or identifying quasi set) | 43.8% | 12.5 pp | 25.0% to 50.0% |
| Gate save rate (upper bound: request-level) | n/a | n/a | n/a |
| Gate save rate (lower bound: hash-attributed) | n/a | n/a | n/a |
| Values that got past the detectors | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Block rate (all) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Block rate (non-benign) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Over-block on benign | n/a | n/a | n/a |
| Benign cases with any masking | n/a | n/a | n/a |
| Over-redaction (must_keep strings missing) | 5.6% | 6.4 pp | 0.0% to 11.1% |
| Over-redaction (cases with any missing) | 12.5% | 14.4 pp | 0.0% to 25.0% |
| Local overhead, mean (ms) | 2577 | 774.4 | 1889 to 3678 |
| Local overhead, p95 (ms) | 4225 | 649.3 | 3742 to 5128 |
| Client wall time, mean (ms) | 2580 | 774.4 | 1893 to 3681 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 0.0% ± 0.0 | 0.0% ± 0.0 | 25.0% ± 50.0 | n/a | n/a |
| finance | 0.0% ± 0.0 | 0.0% ± 0.0 | 6.2% ± 12.5 | n/a | n/a |
| quasi_identifier | 87.5% ± 25.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 87.5% ± 25.0 | 0.0% ± 0.0 | 0.0% ± 0.0 |
| ko | 0.0% ± 0.0 | 0.0% ± 0.0 | 10.0% ± 11.5 |

## Pass independence

- Byte-identical outbound payloads in all 4 passes: 0 of 4 cases (0.0%)
- Detect time p50 by pass: 2,239 / 4,495 / 1,513 / 2,318 ms
- Detector temperature: 0.6

## Cases that leaked in any pass

1 case(s) leaked in every pass; 1 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| qid-en-06 | quasi_identifier | en | 4/4 | quasi-identifier group ≥k: 4 |
| qid-en-05 | quasi_identifier | en | 3/4 | quasi-identifier group ≥k: 3 |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|

## Value outcomes (summed over passes)

- `detected_removed`: 0
- `removed_unattributed`: 24
- `gate_saved`: 0
- `missed_leaked`: 0
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
