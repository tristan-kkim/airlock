
## q4_v2_think_t1  (34 requests)
- JSON parse ok: 34/34

| type | ko full (partial) | en full (partial) | all full (partial) | n |
|---|---|---|---|---|
| PERSON | 90.9% (90.9%) | 100.0% (100.0%) | 94.7% (94.7%) | 19 |
| ORG | 50.0% (50.0%) | - | 50.0% (50.0%) | 2 |
| CONTACT | 100.0% (100.0%) | 100.0% (100.0%) | 100.0% (100.0%) | 8 |
| ID_NUMBER | 100.0% (100.0%) | 100.0% (100.0%) | 100.0% (100.0%) | 7 |
| FINANCIAL | 100.0% (100.0%) | 100.0% (100.0%) | 100.0% (100.0%) | 6 |
| SECRET | 100.0% (100.0%) | 100.0% (100.0%) | 100.0% (100.0%) | 10 |
| LOCATION | 100.0% (100.0%) | 100.0% (100.0%) | 100.0% (100.0%) | 3 |
| HEALTH | 100.0% (100.0%) | 100.0% (100.0%) | 100.0% (100.0%) | 8 |
| QUASI_IDENTIFIER | 0.0% (0.0%) | 100.0% (100.0%) | 57.1% (57.1%) | 7 |
| ALL | 86.1% (86.1%) | 100.0% (100.0%) | 92.9% (92.9%) | 70 |

- type label agreement on detected spans: 96.9% (63/65)
- QUASI_IDENTIFIER detected -> action=generalize with replacement: 3/4
- benign prompts with >=1 flagged span (FP rate): 0.0% (0/8)
- spurious spans on sensitive prompts: 0/74 predicted spans (0.0%)
- ungrounded spans (text not verbatim in prompt): 2/74 (2.7%)

| type | regex-only ko / en | model(re-anchored)+regex ko / en / all |
|---|---|---|
| PERSON | 0.0% / 0.0% | 90.9% / 100.0% / 94.7% |
| ORG | 0.0% / n/a | 50.0% / n/a / 50.0% |
| CONTACT | 100.0% / 100.0% | 100.0% / 100.0% / 100.0% |
| ID_NUMBER | 75.0% / 100.0% | 100.0% / 100.0% / 100.0% |
| FINANCIAL | 66.7% / 100.0% | 100.0% / 100.0% / 100.0% |
| SECRET | 100.0% / 83.3% | 100.0% / 100.0% / 100.0% |
| LOCATION | 0.0% / 0.0% | 100.0% / 100.0% / 100.0% |
| HEALTH | 0.0% / 0.0% | 100.0% / 100.0% / 100.0% |
| QUASI_IDENTIFIER | 0.0% / 0.0% | 66.7% / 100.0% / 85.7% |
| ALL | 36.1% / 44.1% | 91.7% / 100.0% / 95.7% |
- regex hits on benign prompts: 0
- sensitive prompts with every expected span fully covered: 84.6% (22/26)
- TTFT p50/p95: 0.26s / 0.42s
- total p50/p95/max: 14.10s / 28.27s / 32.47s
- prompt tokens mean 1039, completion tokens mean 498 (max 1052)
- decode tok/s median 32.9; prefill tok/s median 234
- prompt cache hit tokens (median): 969

### misses (all runs, full-coverage)
- ko07 QUASI_IDENTIFIER '유일한 여성 부사장' missed 1x
- ko08 QUASI_IDENTIFIER '한국어-포르투갈어 통역사' missed 1x
- ko16 QUASI_IDENTIFIER '유일한 외국인 개발자' missed 1x
- ko17 ORG '대원물산' missed 1x
- ko17 PERSON '류하린' missed 1x

### false-positive / spurious spans (all runs)

### ungrounded spans
- ko07 '독일의 유일한 여성 부사장' x1
- ko16 '그린루프의 유일한 외국인 개발자인 인도 출신 동료' x1
