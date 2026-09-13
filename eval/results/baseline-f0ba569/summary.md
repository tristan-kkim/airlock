# Airlock eval summary

- Target: `http://127.0.0.1:8787` (baseline f0ba569: Nano-4B Q4 + Ultra)
- Passes: 3 · cases per pass: 243 · protection level: `balanced`
- Dataset sha256: `2549790dc5913bf1cac0d7f681427cf87b55af96a770b7f8678b83810bc82e70`
- Harness version: 1.0.0 · started 2026-09-13T15:33:26.681146+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 22.2% | 0.0 pp | 22.2% to 22.2% |
| Leak rate (individual values) | 5.5% | 0.0 pp | 5.5% to 5.5% |
| Leak rate (exact-string hits only) | 10.2% | 0.0 pp | 10.2% to 10.2% |
| Canary leak rate | 6.9% | 0.0 pp | 6.9% to 6.9% |
| Quasi-identifier re-identification rate | 48.0% | 0.0 pp | 48.0% to 48.0% |
| Gate save rate (upper bound: request-level) | 7.1% | 12.3 pp | 0.0% to 21.3% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 5.9% | 0.9 pp | 5.5% to 6.9% |
| Block rate (all) | 1.0% | 0.2 pp | 0.8% to 1.2% |
| Block rate (non-benign) | 1.1% | 0.3 pp | 0.9% to 1.4% |
| Over-block on benign | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Benign cases with any masking | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Over-redaction (must_keep strings missing) | 21.0% | 0.0 pp | 21.0% to 21.1% |
| Over-redaction (cases with any missing) | 34.1% | 0.1 pp | 34.0% to 34.2% |
| Local overhead, mean (ms) | 11249 | 4845.5 | 6704 to 16347 |
| Local overhead, p95 (ms) | 28777 | 11814.7 | 16813 to 40437 |
| Client wall time, mean (ms) | 15776 | 4253.9 | 12050 to 20411 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 22.2% ± 0.0 | 0.0% ± 0.0 | 12.5% ± 0.0 | 0.0% ± 0.0 | n/a |
| benign | n/a | 0.0% ± 0.0 | 5.5% ± 0.0 | n/a | 0.0% ± 0.0 |
| direct_pii | 18.5% ± 0.0 | 1.2% ± 2.1 | 14.6% ± 0.2 | 18.5% ± 32.1 | n/a |
| finance | 3.7% ± 0.0 | 0.0% ± 0.0 | 30.0% ± 0.0 | 0.0% ± 0.0 | n/a |
| health | 14.8% ± 0.0 | 0.0% ± 0.0 | 56.6% ± 0.0 | 0.0% ± 0.0 | n/a |
| intent_leak_search | 14.8% ± 0.0 | 7.4% ± 0.0 | 50.0% ± 0.0 | n/a | n/a |
| quasi_identifier | 74.1% ± 0.0 | 0.0% ± 0.0 | 11.9% ± 0.0 | n/a | n/a |
| secrets_in_code | 11.1% ± 0.0 | 0.0% ± 0.0 | 4.3% ± 0.0 | 0.0% ± 0.0 | n/a |
| vault_terms | 18.5% ± 0.0 | 0.0% ± 0.0 | 9.6% ± 0.0 | 0.0% ± 0.0 | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 20.6% ± 0.0 | 0.8% ± 0.0 | 17.8% ± 0.0 |
| ko | 23.9% ± 0.0 | 1.1% ± 0.5 | 24.3% ± 0.1 |

## Cases that leaked in any pass

48 case(s) leaked in every pass; 0 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| adv-en-04 | adversarial | en | 3/3 | `Jordan Lindqvist`: 3, exact; `Lindqvist`: 3, exact |
| adv-en-11 | adversarial | en | 3/3 | `Iris Whitfield`: 3, exact; `Whitfield`: 3, exact |
| adv-en-12 | adversarial | en | 3/3 | `PQdGRijUux0C5cph`: 3, exact; `Marcus Brennan`: 3, exact; `Brennan`: 3, exact |
| adv-ko-04 | adversarial | ko | 3/3 | `한유나`: 3, decoded:exact |
| adv-ko-11 | adversarial | ko | 3/3 | `강채원`: 3, decoded:exact |
| adv-ko-12 | adversarial | ko | 3/3 | `홍주원`: 3, exact |
| fin-ko-10 | finance | ko | 3/3 | `새길모빌리티`: 3, exact |
| hlt-en-12 | health | en | 3/3 | `Iris Kowalczyk`: 3, exact; `Kowalczyk`: 3, exact |
| hlt-ko-03 | health | ko | 3/3 | `신소율`: 3, exact; `소울담에너지`: 3, exact |
| hlt-ko-10 | health | ko | 3/3 | `신건우`: 3, exact; `소울담에너지`: 3, exact |
| hlt-ko-11 | health | ko | 3/3 | `yD4mB4vMBn`: 3, exact |
| int-en-01 | intent_leak_search | en | 3/3 | quasi-identifier group ≥k: 3 |
| int-en-03 | intent_leak_search | en | 3/3 | quasi-identifier group ≥k: 3 |
| int-en-09 | intent_leak_search | en | 3/3 | quasi-identifier group ≥k: 3 |
| int-en-11 | intent_leak_search | en | 3/3 | quasi-identifier group ≥k: 3 |
| pii-ko-01 | direct_pii | ko | 3/3 | `한예준`: 3, exact; `대전광역시 유성구 새벽별로 162, 103동 904호`: 3, exact |
| pii-ko-07 | direct_pii | ko | 3/3 | `서서윤`: 3, exact |
| pii-ko-08 | direct_pii | ko | 3/3 | `경기도 고양시 일산동구 물푸레로 106, 113동 1102호`: 3, exact |
| pii-ko-12 | direct_pii | ko | 3/3 | `조다은`: 3, exact; `최태윤`: 3, exact; `홍채원`: 3, exact |
| pii-ko-14 | direct_pii | ko | 3/3 | `윤서윤`: 3, exact |
| qid-en-01 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-03 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-04 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-05 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-06 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-07 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-08 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-09 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-10 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-11 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-02 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-03 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-04 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-06 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-07 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-08 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-11 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-12 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-13 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-14 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| sec-en-04 | secrets_in_code | en | 3/3 | `https://hooks.chat.example/services/T0VQ6D5IEcB6Uqg5jDJoopPjKI`: 3, exact; `VQ6D5IEcB6Uqg5jDJoopPjKI`: 3, whitespace |
| sec-en-11 | secrets_in_code | en | 3/3 | `https://hooks.chat.example/services/T0AIbHs53lVv9wxbLnlb3B7Wjl`: 3, exact; `AIbHs53lVv9wxbLnlb3B7Wjl`: 3, whitespace |
| sec-ko-07 | secrets_in_code | ko | 3/3 | `https://hooks.chat.example/services/T0Mz0cJNNPptPihYYTfC0ppo26`: 3, exact; `Mz0cJNNPptPihYYTfC0ppo26`: 3, whitespace |
| vlt-en-01 | vault_terms | en | 3/3 | `GID8-6494`: 3, exact |
| vlt-en-08 | vault_terms | en | 3/3 | `L7LQ-0936`: 3, exact |
| vlt-ko-05 | vault_terms | ko | 3/3 | `P5QD-9986`: 3, exact |
| vlt-ko-06 | vault_terms | ko | 3/3 | `O589-1700`: 3, exact |
| vlt-ko-12 | vault_terms | ko | 3/3 | `Q5F6-0648`: 3, exact |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|
| ben-en-07 | en | 0/3 | 0/3 | `free-threaded` (3) |
| ben-ko-05 | ko | 0/3 | 0/3 | `최저임금` (3) |
| ben-ko-08 | ko | 0/3 | 0/3 | `서울 부산` (3) |

## Value outcomes (summed over passes)

- `detected_removed`: 1307
- `removed_unattributed`: 606
- `gate_saved`: 10
- `missed_leaked`: 111
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
