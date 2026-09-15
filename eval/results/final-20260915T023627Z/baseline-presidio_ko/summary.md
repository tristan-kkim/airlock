# Airlock eval summary

- Target: `http://127.0.0.1:8803` (baseline:presidio_ko)
- Passes: 3 · cases per pass: 243 · protection level: `baseline:presidio_ko`
- Dataset sha256: `cd40ce707652d30ffb2007c5ccaac62c61709d42382c4c623351b5114c850609`
- Harness version: 1.0.0 · started 2026-09-15T02:36:37.801279+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 76.9% | 0.0 pp | 76.9% to 76.9% |
| Leak rate (individual values) | 33.9% | 0.0 pp | 33.9% to 33.9% |
| Leak rate (exact-string hits only) | 62.5% | 0.0 pp | 62.5% to 62.5% |
| Canary leak rate | 84.1% | 0.0 pp | 84.1% to 84.1% |
| Quasi-identifier re-identification rate | 50.0% | 0.0 pp | 50.0% to 50.0% |
| Identity leak (any identity item or identifying quasi set) | 76.7% | 0.0 pp | 76.7% to 76.7% |
| Gate save rate (upper bound: request-level) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 33.6% | 0.0 pp | 33.6% to 33.6% |
| Block rate (all) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Block rate (non-benign) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Over-block on benign | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Benign cases with any masking | 66.7% | 0.0 pp | 66.7% to 66.7% |
| Over-redaction (must_keep strings missing) | 16.7% | 0.0 pp | 16.7% to 16.7% |
| Over-redaction (cases with any missing) | 31.7% | 0.0 pp | 31.7% to 31.7% |
| Local overhead, mean (ms) | 2 | 3.8 | 0 to 7 |
| Local overhead, p95 (ms) | 4 | 6.3 | 0 to 11 |
| Client wall time, mean (ms) | 3 | 3.8 | 1 to 7 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 70.4% ± 0.0 | 0.0% ± 0.0 | 20.8% ± 0.0 | 0.0% ± 0.0 | n/a |
| benign | n/a | 0.0% ± 0.0 | 41.8% ± 0.0 | n/a | 66.7% ± 0.0 |
| direct_pii | 92.6% ± 0.0 | 0.0% ± 0.0 | 17.1% ± 0.0 | 0.0% ± 0.0 | n/a |
| finance | 92.6% ± 0.0 | 0.0% ± 0.0 | 2.5% ± 0.0 | 0.0% ± 0.0 | n/a |
| health | 88.9% ± 0.0 | 0.0% ± 0.0 | 15.8% ± 0.0 | 0.0% ± 0.0 | n/a |
| intent_leak_search | 48.1% ± 0.0 | 0.0% ± 0.0 | 6.2% ± 0.0 | 0.0% ± 0.0 | n/a |
| quasi_identifier | 48.1% ± 0.0 | 0.0% ± 0.0 | 5.1% ± 0.0 | n/a | n/a |
| secrets_in_code | 96.3% ± 0.0 | 0.0% ± 0.0 | 17.1% ± 0.0 | 0.0% ± 0.0 | n/a |
| vault_terms | 77.8% ± 0.0 | 0.0% ± 0.0 | 24.7% ± 0.0 | 0.0% ± 0.0 | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 65.4% ± 0.0 | 0.0% ± 0.0 | 19.9% ± 0.0 |
| ko | 88.1% ± 0.0 | 0.0% ± 0.0 | 13.5% ± 0.0 |

## Pass independence

- Byte-identical outbound payloads in all 3 passes: 243 of 243 cases (100.0%)
- Detect time p50 by pass: 6 / 0 / 0 ms
- Detector temperature: unknown

## Cases that leaked in any pass

166 case(s) leaked in every pass; 0 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| adv-en-02 | adversarial | en | 3/3 | `666-15-5370`: 3, digits |
| adv-en-03 | adversarial | en | 3/3 | `dpk_live_5DmIiYQiczDDZP6eIWtYOKHMcJHg`: 3, decoded:exact; `ZHBrX2xpdmVfNURtSWlZUWljekREWlA2ZUlXdFlPS0hNY0pIZw==`: 3, exact; `5DmIiYQiczDDZP6eIWtYOKHMcJHg`: 3, decoded:exact |
| adv-en-04 | adversarial | en | 3/3 | `AC-8NMD61YGVM`: 3, exact |
| adv-en-06 | adversarial | en | 3/3 | `Elena Whitfield`: 3, casefold; `Whitfield`: 3, exact |
| adv-en-07 | adversarial | en | 3/3 | `(617) 555-0193`: 3, numeral_words |
| adv-en-09 | adversarial | en | 3/3 | `666-58-6193`: 3, digits |
| adv-en-10 | adversarial | en | 3/3 | `dpk_live_dCEpljl716jQ6Wy8MJKchHlrRIpF`: 3, decoded:exact; `ZHBrX2xpdmVfZENFcGxqbDcxNmpRNld5OE1KS2NoSGxyUklwRg==`: 3, exact; `dCEpljl716jQ6Wy8MJKchHlrRIpF`: 3, decoded:exact |
| adv-en-11 | adversarial | en | 3/3 | `AC-UZI8ZD0T7L`: 3, exact |
| adv-ko-01 | adversarial | ko | 3/3 | `961821-2849347`: 3, digits |
| adv-ko-02 | adversarial | ko | 3/3 | `010-0911-0925`: 3, numeral_words; `공일공 공구일일 공구이오`: 3, exact |
| adv-ko-03 | adversarial | ko | 3/3 | `vx6KsXmT60wuBd3QoP`: 3, decoded:exact; `REJfUEFTU1dPUkQ9dng2S3NYbVQ2MHd1QmQzUW9Q`: 3, exact |
| adv-ko-04 | adversarial | ko | 3/3 | `TXL6C6EPNQP5`: 3, exact |
| adv-ko-06 | adversarial | ko | 3/3 | `장은호`: 3, exact |
| adv-ko-07 | adversarial | ko | 3/3 | `정민준`: 3, alnum |
| adv-ko-08 | adversarial | ko | 3/3 | `731521-1385835`: 3, digits |
| adv-ko-09 | adversarial | ko | 3/3 | `조유나`: 3, exact |
| adv-ko-11 | adversarial | ko | 3/3 | `강채원`: 3, exact; `TX8KP7QD8A31`: 3, exact |
| adv-ko-12 | adversarial | ko | 3/3 | `4226-4001-2164-1277`: 3, exact |
| adv-ko-13 | adversarial | ko | 3/3 | `정예준`: 3, exact |
| fin-en-01 | finance | en | 3/3 | `1UeK0pfNaN2k`: 3, exact |
| fin-en-02 | finance | en | 3/3 | `F22B4749`: 3, exact |
| fin-en-03 | finance | en | 3/3 | `666-87-8426`: 3, exact; `WVbFIfwJ1C`: 3, exact |
| fin-en-04 | finance | en | 3/3 | `LNA94A19528B`: 3, exact |
| fin-en-06 | finance | en | 3/3 | `uijZYVg4QJEcbdDz`: 3, exact |
| fin-en-07 | finance | en | 3/3 | `BRK-5JTYGLK7MY`: 3, exact |
| fin-en-08 | finance | en | 3/3 | `U5WqKYim9Xw3`: 3, exact |
| fin-en-09 | finance | en | 3/3 | `E882A1G1`: 3, exact |
| fin-en-10 | finance | en | 3/3 | `666-61-8154`: 3, exact; `K8N1lKXDj3`: 3, exact |
| fin-en-11 | finance | en | 3/3 | `LN38CC0C6474`: 3, exact |
| fin-en-12 | finance | en | 3/3 | `uKJOJlZg76DP8m`: 3, exact |
| fin-en-13 | finance | en | 3/3 | `bjJk5XpmcUEOrgMx`: 3, exact |
| fin-en-14 | finance | en | 3/3 | `BRK-F16XE4QGAR`: 3, exact |
| fin-ko-01 | finance | ko | 3/3 | `5148-3832-5173-8783`: 3, exact; `417626`: 3, exact |
| fin-ko-02 | finance | ko | 3/3 | `최도윤`: 3, exact; `f7aGQoLPYVwH`: 3, exact |
| fin-ko-03 | finance | ko | 3/3 | `신현우`: 3, exact; `9Qqzt9B9jRrk`: 3, exact |
| fin-ko-04 | finance | ko | 3/3 | `최도윤`: 3, exact; `551172`: 3, exact |
| fin-ko-05 | finance | ko | 3/3 | `7K169H722`: 3, exact |
| fin-ko-06 | finance | ko | 3/3 | `A3FsGFJj4LYi`: 3, exact |
| fin-ko-07 | finance | ko | 3/3 | `Y0zB92D31DGiu8`: 3, exact |
| fin-ko-08 | finance | ko | 3/3 | `서시우`: 3, exact |
| fin-ko-09 | finance | ko | 3/3 | `조은호`: 3, exact; `yPW9snzHEoUM`: 3, exact |
| fin-ko-10 | finance | ko | 3/3 | `권소율`: 3, exact; `247-69-81324`: 3, exact; `F6a7f8cpcH5T`: 3, exact |
| fin-ko-12 | finance | ko | 3/3 | `37066K075`: 3, exact |
| fin-ko-13 | finance | ko | 3/3 | `DXB3y3JzNShN`: 3, exact |
| hlt-en-01 | health | en | 3/3 | `PT-UB2SJ9MB8S`: 3, exact |
| hlt-en-02 | health | en | 3/3 | `IsakHtc3QZyl`: 3, exact |
| hlt-en-03 | health | en | 3/3 | `MRN080Q03Q46`: 3, exact |
| hlt-en-05 | health | en | 3/3 | `ED842D364`: 3, exact |
| hlt-en-06 | health | en | 3/3 | `SNRBH2O5FBGH`: 3, exact |
| hlt-en-07 | health | en | 3/3 | `POL925822338`: 3, exact |
| hlt-en-09 | health | en | 3/3 | `hAf9G9Z7Y1jw`: 3, exact |
| hlt-en-10 | health | en | 3/3 | `MRN34KKQ60K2`: 3, exact |
| hlt-en-12 | health | en | 3/3 | `E4475B80B`: 3, exact |
| hlt-en-13 | health | en | 3/3 | `SNGY750G861P`: 3, exact |
| hlt-ko-01 | health | ko | 3/3 | `WZG43WJYKK`: 3, exact |
| hlt-ko-02 | health | ko | 3/3 | `N3QJRPVHEE`: 3, exact |
| hlt-ko-03 | health | ko | 3/3 | `송지호`: 3, exact; `소울담에너지`: 3, exact; `41760980`: 3, exact |
| hlt-ko-04 | health | ko | 3/3 | `한마루식품`: 3, exact |
| hlt-ko-05 | health | ko | 3/3 | `72292MRRCB2TF`: 3, exact; `느티숲초등학교`: 3, exact |
| hlt-ko-06 | health | ko | 3/3 | `EGA9KY254988`: 3, exact |
| hlt-ko-07 | health | ko | 3/3 | `38966240`: 3, exact |
| hlt-ko-08 | health | ko | 3/3 | `J4LLCNBYKE`: 3, exact |
| hlt-ko-09 | health | ko | 3/3 | `5RGM3M4MWE`: 3, exact |
| hlt-ko-10 | health | ko | 3/3 | `신건우`: 3, exact; `소울담에너지`: 3, exact |
| hlt-ko-11 | health | ko | 3/3 | `청람로지스`: 3, exact; `yD4mB4vMBn`: 3, exact |
| hlt-ko-12 | health | ko | 3/3 | `49101WQ2I3XE1`: 3, exact; `느티숲초등학교`: 3, exact |
| hlt-ko-13 | health | ko | 3/3 | `조윤서`: 3, exact; `Q4MGD7UBTYHL`: 3, exact |
| hlt-ko-14 | health | ko | 3/3 | `40192*03`: 3, exact |
| int-en-02 | intent_leak_search | en | 3/3 | quasi-identifier group ≥k: 3 |
| int-en-09 | intent_leak_search | en | 3/3 | quasi-identifier group ≥k: 3 |
| int-en-10 | intent_leak_search | en | 3/3 | quasi-identifier group ≥k: 3 |
| int-ko-01 | intent_leak_search | ko | 3/3 | quasi-identifier group ≥k: 3 |
| int-ko-02 | intent_leak_search | ko | 3/3 | quasi-identifier group ≥k: 3 |
| int-ko-03 | intent_leak_search | ko | 3/3 | quasi-identifier group ≥k: 3 |
| int-ko-05 | intent_leak_search | ko | 3/3 | quasi-identifier group ≥k: 3 |
| int-ko-07 | intent_leak_search | ko | 3/3 | quasi-identifier group ≥k: 3 |
| int-ko-08 | intent_leak_search | ko | 3/3 | quasi-identifier group ≥k: 3 |
| int-ko-10 | intent_leak_search | ko | 3/3 | `정현우`: 3, exact |
| int-ko-11 | intent_leak_search | ko | 3/3 | quasi-identifier group ≥k: 3 |
| int-ko-13 | intent_leak_search | ko | 3/3 | quasi-identifier group ≥k: 3 |
| int-ko-14 | intent_leak_search | ko | 3/3 | quasi-identifier group ≥k: 3 |
| pii-en-01 | direct_pii | en | 3/3 | `qGjlTttfvm91`: 3, exact |
| pii-en-02 | direct_pii | en | 3/3 | `666-22-7176`: 3, exact; `WDLAS0EXKF8V`: 3, exact |
| pii-en-03 | direct_pii | en | 3/3 | `jTifPwg4VnhaBb`: 3, exact |
| pii-en-04 | direct_pii | en | 3/3 | `Henrik Thornbury`: 3, exact; `Thornbury`: 3, exact; `9f8SIwduccuu`: 3, exact |
| pii-en-05 | direct_pii | en | 3/3 | `S9J918BD6G`: 3, exact |
| pii-en-06 | direct_pii | en | 3/3 | `Z7QTD8YT`: 3, exact |
| pii-en-07 | direct_pii | en | 3/3 | `45VJ4WJL0H`: 3, exact |
| pii-en-08 | direct_pii | en | 3/3 | `szOoboQ0ZKiO`: 3, exact |
| pii-en-09 | direct_pii | en | 3/3 | `666-43-7586`: 3, exact; `WDLJ7PJR8M0V`: 3, exact |
| pii-en-10 | direct_pii | en | 3/3 | `Silas Marchetti`: 3, exact; `Marchetti`: 3, exact; `EIWo3fCa3zMf0e`: 3, exact |
| pii-en-11 | direct_pii | en | 3/3 | `Rafael Nakashima`: 3, exact; `Nakashima`: 3, exact; `QZFaCIDdVaP8`: 3, exact |
| pii-en-12 | direct_pii | en | 3/3 | `S8A098414G`: 3, exact |
| pii-ko-01 | direct_pii | ko | 3/3 | `한예준`: 3, exact; `윤라온`: 3, exact; `2917693*`: 3, exact |
| pii-ko-02 | direct_pii | ko | 3/3 | `장라온`: 3, exact |
| pii-ko-03 | direct_pii | ko | 3/3 | `조태윤`: 3, exact; `강은호`: 3, exact; `조하린`: 3, exact; `DOW4ORPO`: 3, exact |
| pii-ko-04 | direct_pii | ko | 3/3 | `최주원`: 3, exact; `부산광역시 수영구 달맞이숲길 70, 104동 604호`: 3, exact; `UwJmcZorb6n7`: 3, exact |
| pii-ko-05 | direct_pii | ko | 3/3 | `홍유나`: 3, exact; `장소율`: 3, exact; `8Z45Q63AuC`: 3, exact |
| pii-ko-06 | direct_pii | ko | 3/3 | `39PC2KOTJN`: 3, exact |
| pii-ko-07 | direct_pii | ko | 3/3 | `서서윤`: 3, exact; `KB3WM9OL`: 3, exact |
| pii-ko-08 | direct_pii | ko | 3/3 | `임예준`: 3, exact; `정다은`: 3, exact |
| pii-ko-10 | direct_pii | ko | 3/3 | `류서윤`: 3, exact; `879HPWIB`: 3, exact |
| pii-ko-11 | direct_pii | ko | 3/3 | `강하은`: 3, exact; `971605-2941975`: 3, exact; `1cviu0hivfH4`: 3, exact |
| pii-ko-12 | direct_pii | ko | 3/3 | `W8tTgv8ubZ`: 3, exact |
| pii-ko-13 | direct_pii | ko | 3/3 | `홍유나`: 3, exact; `부산광역시 수영구 은행나무샘길 86, 113동 2101호`: 3, exact; `X726XUMU0G`: 3, exact |
| pii-ko-14 | direct_pii | ko | 3/3 | `F8YAXXGS`: 3, exact |
| qid-en-04 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-09 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-01 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-02 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-03 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-04 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-05 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-07 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-09 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-10 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-11 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-12 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-13 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| sec-en-01 | secrets_in_code | en | 3/3 | `i1yqBxCiXkenfTOLpkQ3`: 3, decoded:exact; `aTF5cUJ4Q2lYa2VuZlRPTHBrUTM=`: 3, exact |
| sec-en-02 | secrets_in_code | en | 3/3 | `gtk_6bhkg9l4GvW31eg3ooTNGJY6ICKp4G9nQ0gx`: 3, exact; `6bhkg9l4GvW31eg3ooTNGJY6ICKp4G9nQ0gx`: 3, exact |
| sec-en-03 | secrets_in_code | en | 3/3 | `xlC6J23t1AVwGMQZ`: 3, exact; `FpsHkLjCsXjvF7`: 3, exact |
| sec-en-04 | secrets_in_code | en | 3/3 | `rQpokK1JPxkuvAr4VUWa`: 3, exact; `VQ6D5IEcB6Uqg5jDJoopPjKI`: 3, whitespace |
| sec-en-05 | secrets_in_code | en | 3/3 | `sFjCk4WdVweWcD9w5Q`: 3, exact |
| sec-en-06 | secrets_in_code | en | 3/3 | `pmk_live_ZjGy2bFG6V34lzu3jshUdCCy`: 3, exact; `9FRRqrTbWCKhrXPBuB7BP1ai6EcX5IGD`: 3, exact; `AQiiqJHAkBl3EdPY`: 3, exact; `mysql://root:AQiiqJHAkBl3EdPY@db:3306/shop`: 3, exact; `ZjGy2bFG6V34lzu3jshUdCCy`: 3, exact |
| sec-en-07 | secrets_in_code | en | 3/3 | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5MjY3MjU4IiwiZW1haWwiOiJhdmVyeS5kZWxhY3JvaXgxNUBleGFtcGxlLm9yZyIsIm5hbWUiOiJBdmVyeSBEZWxhY3JvaXgiLCJyb2xlIjoiYWRtaW4ifQ.TIIx3UHaxIFaaiw5zg1Dfx3OUcpnY_mFRBP0tqYJdVp`: 3, exact; `TIIx3UHaxIFaaiw5zg1Dfx3OUcpnY_mFRBP0tqYJdVp`: 3, exact; `avery.delacroix15@example.org`: 3, decoded:exact |
| sec-en-08 | secrets_in_code | en | 3/3 | `mfjTB3vFhwncfkdhS2Mv`: 3, decoded:exact; `bWZqVEIzdkZod25jZmtkaFMyTXY=`: 3, exact |
| sec-en-09 | secrets_in_code | en | 3/3 | `gtk_k4Do3kcCkwaB7niGaFrRc48LX9KToWOifLF4`: 3, exact; `k4Do3kcCkwaB7niGaFrRc48LX9KToWOifLF4`: 3, exact |
| sec-en-10 | secrets_in_code | en | 3/3 | `eM6HEKAD1nwfBvVa`: 3, exact; `IGk2Gm1J2uSjo8`: 3, exact |
| sec-en-11 | secrets_in_code | en | 3/3 | `QCOxiydUyRdE2WpTAYj2`: 3, exact; `AIbHs53lVv9wxbLnlb3B7Wjl`: 3, whitespace |
| sec-en-13 | secrets_in_code | en | 3/3 | `pmk_live_GwbTZjEtL0p2jaHdbY589MVh`: 3, exact; `PimNyYQ20J104S9lnkx9lz0tUNcw0YY8`: 3, exact; `Fi3fq57HFmNsuVvH`: 3, exact; `mysql://root:Fi3fq57HFmNsuVvH@db:3306/shop`: 3, exact; `GwbTZjEtL0p2jaHdbY589MVh`: 3, exact |
| sec-en-14 | secrets_in_code | en | 3/3 | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMDY0MzQ4IiwiZW1haWwiOiJlbGVuYS5jYXN0ZWxsYW5vczcyQGV4YW1wbGUuY29tIiwibmFtZSI6IkVsZW5hIENhc3RlbGxhbm9zIiwicm9sZSI6ImFkbWluIn0.g6jlZSNe6Q9cP5b2QMG8c0CGk04ZHgCNNBZCBuLK0Jl`: 3, exact; `g6jlZSNe6Q9cP5b2QMG8c0CGk04ZHgCNNBZCBuLK0Jl`: 3, exact; `elena.castellanos72@example.com`: 3, decoded:exact |
| sec-ko-01 | secrets_in_code | ko | 3/3 | `1UeFKYhkhmKkKNA4Ow`: 3, exact |
| sec-ko-02 | secrets_in_code | ko | 3/3 | `pmk_live_AD3bZXTPSAF0cKtsuVcXm6gJ`: 3, exact; `0M5M70azs3QmmsjxotppBisPAkRdnmXL`: 3, exact; `1IxpwGvHzlUiPTMw`: 3, exact; `mysql://root:1IxpwGvHzlUiPTMw@db:3306/shop`: 3, exact; `AD3bZXTPSAF0cKtsuVcXm6gJ`: 3, exact |
| sec-ko-03 | secrets_in_code | ko | 3/3 | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1OTcxNDE5IiwiZW1haWwiOiJzb2ZpYS5veWVsYXJhbjI3QGV4YW1wbGUub3JnIiwibmFtZSI6IlNvZmlhIE95ZWxhcmFuIiwicm9sZSI6ImFkbWluIn0.LWWzdHhA7YZnUiXncK4MVEW9V-BlRi_ABqrG4hPyY3T`: 3, exact; `LWWzdHhA7YZnUiXncK4MVEW9V-BlRi_ABqrG4hPyY3T`: 3, exact; `sofia.oyelaran27@example.org`: 3, decoded:exact |
| sec-ko-04 | secrets_in_code | ko | 3/3 | `vd3sAYyIrj23JRF27Ulz`: 3, decoded:exact; `dmQzc0FZeUlyajIzSlJGMjdVbHo=`: 3, exact |
| sec-ko-05 | secrets_in_code | ko | 3/3 | `gtk_iacv2JbTNok6iQ8dES6pLXGoNtcYgON1kz8C`: 3, exact; `iacv2JbTNok6iQ8dES6pLXGoNtcYgON1kz8C`: 3, exact |
| sec-ko-06 | secrets_in_code | ko | 3/3 | `NGBH6YIJwmCzzVTX`: 3, exact; `x359xBnWufjfmr`: 3, exact |
| sec-ko-07 | secrets_in_code | ko | 3/3 | `CDyGNHmEm4dDxOAFUymu`: 3, exact; `Mz0cJNNPptPihYYTfC0ppo26`: 3, whitespace |
| sec-ko-08 | secrets_in_code | ko | 3/3 | `rP3phuLH3oklwmJCXo`: 3, exact |
| sec-ko-09 | secrets_in_code | ko | 3/3 | `pmk_live_FGiXYVsz2SjDCfXDYHuyhF6c`: 3, exact; `9eKuseLFiItTQreNsapzhc4mnZxsXRZo`: 3, exact; `UCsS4yJ1jaEhFut9`: 3, exact; `mysql://root:UCsS4yJ1jaEhFut9@db:3306/shop`: 3, exact; `FGiXYVsz2SjDCfXDYHuyhF6c`: 3, exact |
| sec-ko-10 | secrets_in_code | ko | 3/3 | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2MjQyNzkyIiwiZW1haWwiOiJvd2VuLnBlbWJyb29rZTI0QGV4YW1wbGUub3JnIiwibmFtZSI6Ik93ZW4gUGVtYnJvb2tlIiwicm9sZSI6ImFkbWluIn0.EIpYutsIoOdyC927iPof-lhfuVObJt2cBKa-ENXO0xn`: 3, exact; `EIpYutsIoOdyC927iPof-lhfuVObJt2cBKa-ENXO0xn`: 3, exact; `owen.pembrooke24@example.org`: 3, decoded:exact |
| sec-ko-11 | secrets_in_code | ko | 3/3 | `W5kmDsioJUli9T2oZvKI`: 3, decoded:exact; `VzVrbURzaW9KVWxpOVQyb1p2S0k=`: 3, exact |
| sec-ko-12 | secrets_in_code | ko | 3/3 | `gtk_FWLIcbmX9FtU1NMlzlo1VOvPkuWNTx1lMmGo`: 3, exact; `FWLIcbmX9FtU1NMlzlo1VOvPkuWNTx1lMmGo`: 3, exact |
| sec-ko-13 | secrets_in_code | ko | 3/3 | `D2DuDEdzjgEJAn7b`: 3, exact; `0xorrbUEa8ENUJ`: 3, exact |
| vlt-en-02 | vault_terms | en | 3/3 | `XK9F-5069`: 3, exact |
| vlt-en-03 | vault_terms | en | 3/3 | `0BKP-3768`: 3, exact |
| vlt-en-04 | vault_terms | en | 3/3 | `GD4V-4673`: 3, exact |
| vlt-en-05 | vault_terms | en | 3/3 | `NX9V-2018`: 3, exact |
| vlt-en-06 | vault_terms | en | 3/3 | `261Q-8710`: 3, exact |
| vlt-en-07 | vault_terms | en | 3/3 | `9UUT-9586`: 3, exact |
| vlt-en-08 | vault_terms | en | 3/3 | `L7LQ-0936`: 3, exact |
| vlt-en-12 | vault_terms | en | 3/3 | `Z2UI-3493`: 3, exact |
| vlt-en-13 | vault_terms | en | 3/3 | `1HYR-5393`: 3, exact |
| vlt-ko-01 | vault_terms | ko | 3/3 | `새론다움물류`: 3, whitespace; `1MV2-9331`: 3, exact |
| vlt-ko-02 | vault_terms | ko | 3/3 | `M2RN-6553`: 3, exact |
| vlt-ko-03 | vault_terms | ko | 3/3 | `UF6C-2152`: 3, exact |
| vlt-ko-05 | vault_terms | ko | 3/3 | `P5QD-9986`: 3, exact |
| vlt-ko-06 | vault_terms | ko | 3/3 | `O589-1700`: 3, exact |
| vlt-ko-07 | vault_terms | ko | 3/3 | `3FAE-2145`: 3, exact |
| vlt-ko-08 | vault_terms | ko | 3/3 | `미리내리테일`: 3, whitespace; `A7WC-1677`: 3, exact |
| vlt-ko-09 | vault_terms | ko | 3/3 | `G9II-6962`: 3, exact |
| vlt-ko-10 | vault_terms | ko | 3/3 | `E5YU-2788`: 3, exact |
| vlt-ko-11 | vault_terms | ko | 3/3 | `WUZ3-0766`: 3, exact |
| vlt-ko-12 | vault_terms | ko | 3/3 | `Q5F6-0648`: 3, exact |
| vlt-ko-13 | vault_terms | ko | 3/3 | `34JG-2684`: 3, exact |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|
| ben-en-01 | en | 0/3 | 3/3 | `Alan Turing` (3), `Bletchley Park` (3) |
| ben-en-02 | en | 0/3 | 3/3 | `479001600` (3) |
| ben-en-04 | en | 0/3 | 3/3 | `Marie Curie` (3), `1911` (3) |
| ben-en-06 | en | 0/3 | 3/3 | `127.0.0.1:3000` (3) |
| ben-en-08 | en | 0/3 | 3/3 | `Ada Lovelace` (3), `Analytical Engine` (3) |
| ben-en-09 | en | 0/3 | 3/3 | `3628800` (3) |
| ben-en-10 | en | 0/3 | 3/3 | `B12` (3) |
| ben-en-11 | en | 0/3 | 3/3 | `10 years` (3) |
| ben-en-13 | en | 0/3 | 3/3 | - |
| ben-en-14 | en | 0/3 | 3/3 | `Kyoto` (3), `3-day itinerary` (3) |
| ben-ko-02 | ko | 0/3 | 3/3 | `이순신` (3) |
| ben-ko-03 | ko | 0/3 | 3/3 | `39916800` (3), `11 팩토리얼` (3) |
| ben-ko-05 | ko | 0/3 | 3/3 | - |
| ben-ko-07 | ko | 0/3 | 3/3 | `김치찌개` (3) |
| ben-ko-08 | ko | 0/3 | 3/3 | `KTX` (3), `서울 부산` (3) |
| ben-ko-10 | ko | 0/3 | 3/3 | `5년` (3) |
| ben-ko-11 | ko | 0/3 | 3/3 | `listen 8080` (3), `127.0.0.1:3000` (3) |
| ben-ko-13 | ko | 0/3 | 3/3 | `불국사` (3) |

## Value outcomes (summed over passes)

- `detected_removed`: 870
- `removed_unattributed`: 474
- `gate_saved`: 0
- `missed_leaked`: 684
- `leaked_despite_detection`: 6
- `gate_saved` with hash-attributed reason: 0
