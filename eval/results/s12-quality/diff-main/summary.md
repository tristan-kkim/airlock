# Airlock eval summary

- Target: `http://127.0.0.1:8800` (airlock d97a815 (main), stub upstream, the 4 dev cases that differed from main (local scan only))
- Passes: 4 · cases per pass: 4 · protection level: `balanced`
- Dataset sha256: `cd40ce707652d30ffb2007c5ccaac62c61709d42382c4c623351b5114c850609`
- Harness version: 1.0.0 · started 2026-09-15T02:30:33.810400+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 56.2% | 12.5 pp | 50.0% to 75.0% |
| Leak rate (individual values) | 4.2% | 8.3 pp | 0.0% to 16.7% |
| Leak rate (exact-string hits only) | 6.2% | 12.5 pp | 0.0% to 25.0% |
| Canary leak rate | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Quasi-identifier re-identification rate | 100.0% | 0.0 pp | 100.0% to 100.0% |
| Identity leak (any identity item or identifying quasi set) | 56.2% | 12.5 pp | 50.0% to 75.0% |
| Gate save rate (upper bound: request-level) | 83.3% | 23.6 pp | 66.7% to 100.0% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 20.8% | 25.0 pp | 0.0% to 50.0% |
| Block rate (all) | 12.5% | 14.4 pp | 0.0% to 25.0% |
| Block rate (non-benign) | 12.5% | 14.4 pp | 0.0% to 25.0% |
| Over-block on benign | n/a | n/a | n/a |
| Benign cases with any masking | n/a | n/a | n/a |
| Over-redaction (must_keep strings missing) | 11.8% | 0.8 pp | 11.1% to 12.5% |
| Over-redaction (cases with any missing) | 29.2% | 4.8 pp | 25.0% to 33.3% |
| Local overhead, mean (ms) | 3815 | 1461.3 | 2071 to 5642 |
| Local overhead, p95 (ms) | 7797 | 2244.1 | 4585 to 9817 |
| Client wall time, mean (ms) | 3818 | 1461.7 | 2074 to 5646 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 0.0% ± 0.0 | 50.0% ± 57.7 | 0.0% ± 0.0 | 100.0% ± 0.0 | n/a |
| finance | 25.0% ± 50.0 | 0.0% ± 0.0 | 25.0% ± 0.0 | 0.0% ± 0.0 | n/a |
| quasi_identifier | 100.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 100.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 |
| ko | 12.5% ± 25.0 | 25.0% ± 28.9 | 22.5% ± 2.9 |

## Pass independence

- Byte-identical outbound payloads in all 4 passes: 2 of 3 cases (66.7%)
- Detect time p50 by pass: 5,964 / 2,173 / 1,346 / 941 ms
- Detector temperature: 0.6
- **Warning:** detect p50 fell from 5964 ms in pass 1 to 2173, 1346, 941 ms later; the passes are probably not independent (was the server reset before every pass?)

## Cases that leaked in any pass

2 case(s) leaked in every pass; 1 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| qid-en-05 | quasi_identifier | en | 4/4 | quasi-identifier group ≥k: 4 |
| qid-en-06 | quasi_identifier | en | 4/4 | quasi-identifier group ≥k: 4 |
| fin-ko-10 | finance | ko | 1/4 | `권소율`: 1, exact |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|

## Value outcomes (summed over passes)

- `detected_removed`: 0
- `removed_unattributed`: 19
- `gate_saved`: 4
- `missed_leaked`: 1
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
