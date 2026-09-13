
## q4_v2_t06_cacheram0  (34 requests)
- JSON parse ok: 34/34

| type | ko full (partial) | en full (partial) | all full (partial) | n |
|---|---|---|---|---|
| PERSON | 90.9% (90.9%) | 100.0% (100.0%) | 94.7% (94.7%) | 19 |
| ORG | 50.0% (50.0%) | - | 50.0% (50.0%) | 2 |
| CONTACT | 75.0% (75.0%) | 100.0% (100.0%) | 87.5% (87.5%) | 8 |
| ID_NUMBER | 100.0% (100.0%) | 100.0% (100.0%) | 100.0% (100.0%) | 7 |
| FINANCIAL | 66.7% (66.7%) | 100.0% (100.0%) | 83.3% (83.3%) | 6 |
| SECRET | 100.0% (100.0%) | 100.0% (100.0%) | 100.0% (100.0%) | 10 |
| LOCATION | 100.0% (100.0%) | 100.0% (100.0%) | 100.0% (100.0%) | 3 |
| HEALTH | 25.0% (25.0%) | 75.0% (75.0%) | 50.0% (50.0%) | 8 |
| QUASI_IDENTIFIER | 0.0% (0.0%) | 75.0% (75.0%) | 42.9% (42.9%) | 7 |
| ALL | 72.2% (72.2%) | 94.1% (94.1%) | 82.9% (82.9%) | 70 |

- type label agreement on detected spans: 96.6% (56/58)
- QUASI_IDENTIFIER detected -> action=generalize with replacement: 2/3
- benign prompts with >=1 flagged span (FP rate): 0.0% (0/8)
- spurious spans on sensitive prompts: 7/82 predicted spans (8.5%)
- ungrounded spans (text not verbatim in prompt): 3/82 (3.7%)

| type | regex-only ko / en | model(re-anchored)+regex ko / en / all |
|---|---|---|
| PERSON | 0.0% / 0.0% | 90.9% / 100.0% / 94.7% |
| ORG | 0.0% / n/a | 50.0% / n/a / 50.0% |
| CONTACT | 100.0% / 100.0% | 100.0% / 100.0% / 100.0% |
| ID_NUMBER | 75.0% / 100.0% | 100.0% / 100.0% / 100.0% |
| FINANCIAL | 66.7% / 100.0% | 66.7% / 100.0% / 83.3% |
| SECRET | 100.0% / 83.3% | 100.0% / 100.0% / 100.0% |
| LOCATION | 0.0% / 0.0% | 100.0% / 100.0% / 100.0% |
| HEALTH | 0.0% / 0.0% | 25.0% / 75.0% / 50.0% |
| QUASI_IDENTIFIER | 0.0% / 0.0% | 0.0% / 75.0% / 42.9% |
| ALL | 36.1% / 44.1% | 75.0% / 94.1% / 84.3% |
- regex hits on benign prompts: 0
- sensitive prompts with every expected span fully covered: 65.4% (17/26)
- TTFT p50/p95: 0.26s / 0.53s
- total p50/p95/max: 2.84s / 6.11s / 7.64s
- prompt tokens mean 1039, completion tokens mean 76 (max 227)
- decode tok/s median 32.8; prefill tok/s median 233
- prompt cache hit tokens (median): 969

### misses (all runs, full-coverage)
- en09 QUASI_IDENTIFIER 'sole pediatric cardiologist' missed 1x
- en16 HEALTH 'epilepsy' missed 1x
- ko06 HEALTH '우울증' missed 1x
- ko06 HEALTH '제2형 당뇨' missed 1x
- ko07 QUASI_IDENTIFIER '유일한 여성 부사장' missed 1x
- ko08 QUASI_IDENTIFIER '한국어-포르투갈어 통역사' missed 1x
- ko09 FINANCIAL '6,200만원' missed 1x
- ko10 PERSON '한지우' missed 1x
- ko16 QUASI_IDENTIFIER '유일한 외국인 개발자' missed 1x
- ko17 CONTACT '010-5528-9014' missed 1x
- ko17 HEALTH '공황장애' missed 1x
- ko17 ORG '대원물산' missed 1x

### false-positive / spurious spans (all runs)
- en05 ID_NUMBER '3306' x1
- en07 QUASI_IDENTIFIER 'cover his shifts' x1
- en08 ORG 'CEO' x1
- en08 SECRET 'board meetings' x1
- ko04 QUASI_IDENTIFIER 'DB 연결' x1
- ko08 QUASI_IDENTIFIER '유일하게' x1
- ko16 CONTACT '팀 송' x1

### ungrounded spans
- ko07 '재판부장' x1
- ko07 '피니테크 스타트업' x1
- ko17 '100-5528-9014' x1
