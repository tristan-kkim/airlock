# Airlock eval summary

- Target: `http://127.0.0.1:8797` (airlock 685d3c7 AIRLOCK_GLINER=off (HEAD detector))
- Passes: 1 · cases per pass: 243 · protection level: `balanced`
- Dataset sha256: `2549790dc5913bf1cac0d7f681427cf87b55af96a770b7f8678b83810bc82e70`
- Harness version: 1.0.0 · started 2026-09-13T17:49:17.655955+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 28.2% | 0.0 pp | 28.2% to 28.2% |
| Leak rate (individual values) | 10.2% | 0.0 pp | 10.2% to 10.2% |
| Leak rate (exact-string hits only) | 18.1% | 0.0 pp | 18.1% to 18.1% |
| Canary leak rate | 15.2% | 0.0 pp | 15.2% to 15.2% |
| Quasi-identifier re-identification rate | 42.0% | 0.0 pp | 42.0% to 42.0% |
| Gate save rate (upper bound: request-level) | 15.9% | 0.0 pp | 15.9% to 15.9% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 12.1% | 0.0 pp | 12.1% to 12.1% |
| Block rate (all) | 1.2% | 0.0 pp | 1.2% to 1.2% |
| Block rate (non-benign) | 1.4% | 0.0 pp | 1.4% to 1.4% |
| Over-block on benign | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Benign cases with any masking | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Over-redaction (must_keep strings missing) | 15.0% | 0.0 pp | 15.0% to 15.0% |
| Over-redaction (cases with any missing) | 27.9% | 0.0 pp | 27.9% to 27.9% |
| Local overhead, mean (ms) | 11028 | 0.0 | 11028 to 11028 |
| Local overhead, p95 (ms) | 24893 | 0.0 | 24893 to 24893 |
| Client wall time, mean (ms) | 15308 | 0.0 | 15308 to 15308 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 14.8% ± 0.0 | 0.0% ± 0.0 | 12.5% ± 0.0 | 0.0% ± 0.0 | n/a |
| benign | n/a | 0.0% ± 0.0 | 5.5% ± 0.0 | n/a | 0.0% ± 0.0 |
| direct_pii | 29.6% ± 0.0 | 0.0% ± 0.0 | 6.6% ± 0.0 | 0.0% ± 0.0 | n/a |
| finance | 22.2% ± 0.0 | 7.4% ± 0.0 | 20.0% ± 0.0 | 52.9% ± 0.0 | n/a |
| health | 22.2% ± 0.0 | 3.7% ± 0.0 | 34.2% ± 0.0 | 23.5% ± 0.0 | n/a |
| intent_leak_search | 22.2% ± 0.0 | 0.0% ± 0.0 | 50.0% ± 0.0 | 0.0% ± 0.0 | n/a |
| quasi_identifier | 59.3% ± 0.0 | 0.0% ± 0.0 | 10.2% ± 0.0 | n/a | n/a |
| secrets_in_code | 3.7% ± 0.0 | 0.0% ± 0.0 | 4.3% ± 0.0 | 0.0% ± 0.0 | n/a |
| vault_terms | 51.9% ± 0.0 | 0.0% ± 0.0 | 6.8% ± 0.0 | 0.0% ± 0.0 | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 30.8% ± 0.0 | 1.7% ± 0.0 | 9.9% ± 0.0 |
| ko | 25.7% ± 0.0 | 0.8% ± 0.0 | 20.1% ± 0.0 |

## Cases that leaked in any pass

61 case(s) leaked in every pass; 0 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| adv-en-12 | adversarial | en | 1/1 | `PQdGRijUux0C5cph`: 1, exact; `Marcus Brennan`: 1, exact; `Brennan`: 1, exact |
| adv-ko-04 | adversarial | ko | 1/1 | `한유나`: 1, decoded:exact; `TXL6C6EPNQP5`: 1, exact |
| adv-ko-07 | adversarial | ko | 1/1 | `정민준`: 1, alnum |
| adv-ko-11 | adversarial | ko | 1/1 | `강채원`: 1, decoded:exact; `TX8KP7QD8A31`: 1, exact |
| fin-en-04 | finance | en | 1/1 | `Marcus Vasquez-Hale`: 1, exact; `Vasquez-Hale`: 1, exact |
| fin-en-05 | finance | en | 1/1 | `orbit cactus harbor hazel hazel tundra meadow dynamo ember anchor dynamo velvet`: 1, exact |
| fin-en-10 | finance | en | 1/1 | `K8N1lKXDj3`: 1, exact |
| fin-ko-03 | finance | ko | 1/1 | `도래울건설`: 1, exact |
| fin-ko-07 | finance | ko | 1/1 | `dynamo pepper canyon orbit ember velvet anchor hazel hazel harbor meadow harbor`: 1, exact |
| fin-ko-10 | finance | ko | 1/1 | `권소율`: 1, exact; `새길모빌리티`: 1, exact |
| hlt-en-04 | health | en | 1/1 | `Linden Vale Clinic`: 1, exact |
| hlt-en-06 | health | en | 1/1 | `Henrik Brennan`: 1, exact; `Brennan`: 1, exact |
| hlt-en-08 | health | en | 1/1 | `Henrik Pembrooke`: 1, exact; `Pembrooke`: 1, exact |
| hlt-en-11 | health | en | 1/1 | `Declan Whitfield`: 1, exact; `Whitfield`: 1, exact; `Marcus Thornbury`: 1, exact; `Thornbury`: 1, exact; `Maplecrest General Hospital`: 1, exact |
| hlt-ko-05 | health | ko | 1/1 | `최라온`: 1, exact; `느티숲초등학교`: 1, exact |
| hlt-ko-12 | health | ko | 1/1 | `장시우`: 1, exact |
| int-en-01 | intent_leak_search | en | 1/1 | quasi-identifier group ≥k: 1 |
| int-en-02 | intent_leak_search | en | 1/1 | quasi-identifier group ≥k: 1 |
| int-en-09 | intent_leak_search | en | 1/1 | quasi-identifier group ≥k: 1 |
| int-en-10 | intent_leak_search | en | 1/1 | quasi-identifier group ≥k: 1 |
| int-en-11 | intent_leak_search | en | 1/1 | quasi-identifier group ≥k: 1 |
| int-ko-02 | intent_leak_search | ko | 1/1 | `QCP766`: 1, exact |
| pii-en-04 | direct_pii | en | 1/1 | `Kwame Brennan`: 1, exact; `Lucia Brennan`: 1, exact; `Henrik Thornbury`: 1, exact; `Brennan`: 1, exact; `Thornbury`: 1, exact; `(312) 555-0131`: 1, exact; `(617) 555-0133`: 1, exact; `(206) 555-0104`: 1, exact |
| pii-en-11 | direct_pii | en | 1/1 | `(206) 555-0152`: 1, exact; `(415) 555-0151`: 1, exact; `(415) 555-0127`: 1, exact |
| pii-ko-05 | direct_pii | ko | 1/1 | `홍유나`: 1, exact; `서하은`: 1, exact; `장소율`: 1, exact; `8Z45Q63AuC`: 1, exact |
| pii-ko-06 | direct_pii | ko | 1/1 | `801511-2457200`: 1, exact |
| pii-ko-10 | direct_pii | ko | 1/1 | `박은호`: 1, exact |
| pii-ko-12 | direct_pii | ko | 1/1 | `조다은`: 1, exact; `최태윤`: 1, exact; `홍채원`: 1, exact; `W8tTgv8ubZ`: 1, exact |
| pii-ko-13 | direct_pii | ko | 1/1 | `891307-1495084`: 1, exact |
| pii-ko-14 | direct_pii | ko | 1/1 | `윤서윤`: 1, exact |
| qid-en-01 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-04 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-05 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-06 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-08 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-10 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-11 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-en-13 | quasi_identifier | en | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-02 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-03 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-08 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-09 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-10 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-11 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-13 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| qid-ko-14 | quasi_identifier | ko | 1/1 | quasi-identifier group ≥k: 1 |
| sec-en-11 | secrets_in_code | en | 1/1 | `https://hooks.chat.example/services/T0AIbHs53lVv9wxbLnlb3B7Wjl`: 1, exact; `AIbHs53lVv9wxbLnlb3B7Wjl`: 1, whitespace |
| vlt-en-01 | vault_terms | en | 1/1 | `GID8-6494`: 1, exact |
| vlt-en-04 | vault_terms | en | 1/1 | `GD4V-4673`: 1, exact |
| vlt-en-05 | vault_terms | en | 1/1 | `NX9V-2018`: 1, exact |
| vlt-en-06 | vault_terms | en | 1/1 | `261Q-8710`: 1, exact |
| vlt-en-07 | vault_terms | en | 1/1 | `9UUT-9586`: 1, exact |
| vlt-en-09 | vault_terms | en | 1/1 | `YS41-0355`: 1, exact |
| vlt-en-10 | vault_terms | en | 1/1 | `0BEZ-4649`: 1, exact |
| vlt-en-12 | vault_terms | en | 1/1 | `Z2UI-3493`: 1, exact |
| vlt-en-14 | vault_terms | en | 1/1 | `UNW2-8504`: 1, exact |
| vlt-ko-01 | vault_terms | ko | 1/1 | `1MV2-9331`: 1, exact |
| vlt-ko-02 | vault_terms | ko | 1/1 | `M2RN-6553`: 1, exact |
| vlt-ko-03 | vault_terms | ko | 1/1 | `UF6C-2152`: 1, exact |
| vlt-ko-05 | vault_terms | ko | 1/1 | `P5QD-9986`: 1, exact |
| vlt-ko-06 | vault_terms | ko | 1/1 | `O589-1700`: 1, exact |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|
| ben-en-07 | en | 0/1 | 0/1 | `free-threaded` (1) |
| ben-ko-05 | ko | 0/1 | 0/1 | `최저임금` (1) |
| ben-ko-08 | ko | 0/1 | 0/1 | `서울 부산` (1) |

## Value outcomes (summed over passes)

- `detected_removed`: 435
- `removed_unattributed`: 161
- `gate_saved`: 13
- `missed_leaked`: 69
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
