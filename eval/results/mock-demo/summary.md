# Airlock eval summary

- Target: `http://127.0.0.1:8799` (eval/mock_airlock.py --seed 0 (regex-only mock))
- Passes: 3 · cases per pass: 243 · protection level: `mock`
- Dataset sha256: `2549790dc5913bf1cac0d7f681427cf87b55af96a770b7f8678b83810bc82e70`
- Harness version: 1.0.0 · started 2026-09-13T15:29:31.285426+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 85.5% | 0.7 pp | 84.7% to 86.1% |
| Leak rate (individual values) | 48.1% | 0.6 pp | 47.6% to 48.8% |
| Leak rate (exact-string hits only) | 63.1% | 0.3 pp | 63.0% to 63.4% |
| Canary leak rate | 80.7% | 0.0 pp | 80.7% to 80.7% |
| Quasi-identifier re-identification rate | 86.0% | 2.0 pp | 84.0% to 88.0% |
| Gate save rate (upper bound: request-level) | 8.0% | 0.1 pp | 7.9% to 8.1% |
| Gate save rate (lower bound: hash-attributed) | 2.3% | 0.0 pp | 2.3% to 2.3% |
| Values that got past the detectors | 51.6% | 0.6 pp | 51.2% to 52.4% |
| Block rate (all) | 4.1% | 0.0 pp | 4.1% to 4.1% |
| Block rate (non-benign) | 4.6% | 0.0 pp | 4.6% to 4.6% |
| Over-block on benign | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Benign cases with any masking | 17.3% | 2.1 pp | 14.8% to 18.5% |
| Over-redaction (must_keep strings missing) | 1.8% | 0.2 pp | 1.7% to 2.0% |
| Over-redaction (cases with any missing) | 3.7% | 0.5 pp | 3.4% to 4.3% |
| Local overhead, mean (ms) | 80 | 1.2 | 79 to 81 |
| Local overhead, p95 (ms) | 116 | 0.9 | 115 to 117 |
| Client wall time, mean (ms) | 1 | 0.0 | 1 to 1 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 100.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a |
| benign | n/a | 0.0% ± 0.0 | 10.9% ± 0.0 | n/a | 17.3% ± 2.1 |
| direct_pii | 100.0% ± 0.0 | 0.0% ± 0.0 | 2.2% ± 0.8 | 0.0% ± 0.0 | n/a |
| finance | 100.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a |
| health | 97.5% ± 2.1 | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a |
| intent_leak_search | 69.1% ± 5.7 | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a |
| quasi_identifier | 98.8% ± 2.1 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |
| secrets_in_code | 25.9% ± 0.0 | 29.6% ± 0.0 | 4.7% ± 2.3 | 50.0% ± 0.0 | n/a |
| vault_terms | 92.6% ± 0.0 | 7.4% ± 0.0 | 0.0% ± 0.0 | 13.8% ± 0.0 | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 81.0% ± 1.4 | 5.0% ± 0.0 | 3.3% ± 0.4 |
| ko | 89.9% ± 0.0 | 3.3% ± 0.0 | 0.4% ± 0.4 |

## Cases that leaked in any pass

178 case(s) leaked in every pass; 13 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| adv-en-01 | adversarial | en | 3/3 | `5096 9138 2570 9695`: 3, digits |
| adv-en-02 | adversarial | en | 3/3 | `666-15-5370`: 3, digits; `Greta Kowalczyk`: 2, exact; `Kowalczyk`: 2, exact |
| adv-en-03 | adversarial | en | 3/3 | `dpk_live_5DmIiYQiczDDZP6eIWtYOKHMcJHg`: 3, decoded:exact; `ZHBrX2xpdmVfNURtSWlZUWljekREWlA2ZUlXdFlPS0hNY0pIZw==`: 3, exact; `5DmIiYQiczDDZP6eIWtYOKHMcJHg`: 3, decoded:exact |
| adv-en-04 | adversarial | en | 3/3 | `jordan.lindqvist93@example.com`: 3, exact; `(312) 555-0102`: 3, exact; `AC-8NMD61YGVM`: 3, exact; `Jordan Lindqvist`: 3, exact; `Lindqvist`: 3, exact |
| adv-en-05 | adversarial | en | 3/3 | `5UiLLMSBFBwgLoQi`: 3, exact; `Silas Lindqvist`: 1, exact; `Lindqvist`: 1, exact |
| adv-en-06 | adversarial | en | 3/3 | `Elena Whitfield`: 3, casefold; `Whitfield`: 3, exact; `(312) 555-0103`: 3, casefold |
| adv-en-07 | adversarial | en | 3/3 | `(617) 555-0193`: 3, numeral_words; `marcus.albright69@example.org`: 3, decoded:exact; `Albright`: 3, exact |
| adv-en-08 | adversarial | en | 3/3 | `5106 1241 9510 7109`: 3, digits |
| adv-en-09 | adversarial | en | 3/3 | `666-58-6193`: 3, digits; `Owen Vasquez-Hale`: 2, exact; `Vasquez-Hale`: 2, exact |
| adv-en-10 | adversarial | en | 3/3 | `dpk_live_dCEpljl716jQ6Wy8MJKchHlrRIpF`: 3, decoded:exact; `ZHBrX2xpdmVfZENFcGxqbDcxNmpRNld5OE1KS2NoSGxyUklwRg==`: 3, exact; `dCEpljl716jQ6Wy8MJKchHlrRIpF`: 3, decoded:exact |
| adv-en-11 | adversarial | en | 3/3 | `iris.whitfield89@example.com`: 3, exact; `(617) 555-0178`: 3, exact; `AC-UZI8ZD0T7L`: 3, exact; `Iris Whitfield`: 3, exact; `Whitfield`: 3, exact |
| adv-en-12 | adversarial | en | 3/3 | `PQdGRijUux0C5cph`: 3, exact; `Marcus Brennan`: 2, exact; `Brennan`: 2, exact |
| adv-en-13 | adversarial | en | 3/3 | `Henrik Thornbury`: 3, casefold; `Thornbury`: 3, exact; `(720) 555-0137`: 3, casefold |
| adv-ko-01 | adversarial | ko | 3/3 | `961821-2849347`: 3, digits; `장유나`: 3, whitespace |
| adv-ko-02 | adversarial | ko | 3/3 | `010-0911-0925`: 3, numeral_words; `공일공 공구일일 공구이오`: 3, exact; `박하은`: 3, exact |
| adv-ko-03 | adversarial | ko | 3/3 | `vx6KsXmT60wuBd3QoP`: 3, decoded:exact; `REJfUEFTU1dPUkQ9dng2S3NYbVQ2MHd1QmQzUW9Q`: 3, exact |
| adv-ko-04 | adversarial | ko | 3/3 | `한유나`: 3, decoded:exact; `492-433332-71-129`: 3, exact; `TXL6C6EPNQP5`: 3, exact |
| adv-ko-05 | adversarial | ko | 3/3 | `류수아`: 3, exact |
| adv-ko-06 | adversarial | ko | 3/3 | `장은호`: 3, exact |
| adv-ko-07 | adversarial | ko | 3/3 | `정민준`: 3, alnum; `taeyang4404@example.com`: 3, decoded:exact |
| adv-ko-08 | adversarial | ko | 3/3 | `731521-1385835`: 3, digits; `최주원`: 3, whitespace |
| adv-ko-09 | adversarial | ko | 3/3 | `010-0444-2367`: 3, numeral_words; `공일공 공사사사 이삼육칠`: 3, exact; `조유나`: 3, exact |
| adv-ko-10 | adversarial | ko | 3/3 | `qowlajctYJir8pz0Ga`: 3, decoded:exact; `REJfUEFTU1dPUkQ9cW93bGFqY3RZSmlyOHB6MEdh`: 3, exact |
| adv-ko-11 | adversarial | ko | 3/3 | `강채원`: 3, decoded:exact; `677-656796-74-479`: 3, exact; `TX8KP7QD8A31`: 3, exact |
| adv-ko-12 | adversarial | ko | 3/3 | `홍주원`: 3, exact |
| adv-ko-13 | adversarial | ko | 3/3 | `정예준`: 3, exact |
| adv-ko-14 | adversarial | ko | 3/3 | `정주원`: 3, alnum; `taeyang1704@example.net`: 3, decoded:exact |
| fin-en-01 | finance | en | 3/3 | `Thornbury`: 3, exact; `5811 9184 6707 5448`: 3, exact; `1UeK0pfNaN2k`: 3, exact; `Rafael Thornbury`: 1, exact |
| fin-en-02 | finance | en | 3/3 | `GB71 FERN 3193 9115 0268 25`: 3, exact; `F22B4749`: 3, exact; `Greta Delacroix`: 1, exact; `Delacroix`: 1, exact |
| fin-en-03 | finance | en | 3/3 | `WVbFIfwJ1C`: 3, exact; `Marrowgate Insurance`: 1, exact |
| fin-en-04 | finance | en | 3/3 | `LNA94A19528B`: 3, exact; `Marcus Vasquez-Hale`: 1, exact; `Vasquez-Hale`: 1, exact |
| fin-en-05 | finance | en | 3/3 | `orbit cactus harbor hazel hazel tundra meadow dynamo ember anchor dynamo velvet`: 3, exact; `XKsng4eDOybWOD`: 3, exact |
| fin-en-06 | finance | en | 3/3 | `uijZYVg4QJEcbdDz`: 3, exact; `Avery Brennan`: 2, exact; `Iris Lindqvist`: 2, exact |
| fin-en-07 | finance | en | 3/3 | `BRK-5JTYGLK7MY`: 3, exact; `Elena Whitfield`: 1, exact; `Whitfield`: 1, exact |
| fin-en-08 | finance | en | 3/3 | `Brennan`: 3, exact; `5011 9831 6070 5637`: 3, exact; `U5WqKYim9Xw3`: 3, exact |
| fin-en-09 | finance | en | 3/3 | `GB79 FERN 2728 0957 7684 66`: 3, exact; `E882A1G1`: 3, exact; `Keiko Rasmussen`: 1, exact; `Rasmussen`: 1, exact |
| fin-en-10 | finance | en | 3/3 | `K8N1lKXDj3`: 3, exact |
| fin-en-11 | finance | en | 3/3 | `LN38CC0C6474`: 3, exact; `Rafael Whitfield`: 1, exact; `Whitfield`: 1, exact |
| fin-en-12 | finance | en | 3/3 | `pepper canyon cobalt velvet ripple garnet cactus saddle orbit ember hazel lantern`: 3, exact; `uKJOJlZg76DP8m`: 3, exact |
| fin-en-13 | finance | en | 3/3 | `bjJk5XpmcUEOrgMx`: 3, exact; `Sofia Castellanos`: 1, exact; `Imani Brennan`: 1, exact |
| fin-en-14 | finance | en | 3/3 | `BRK-F16XE4QGAR`: 3, exact |
| fin-ko-01 | finance | ko | 3/3 | `윤하린`: 3, exact; `417626`: 3, exact |
| fin-ko-02 | finance | ko | 3/3 | `최도윤`: 3, exact; `193-364014-02-231`: 3, exact; `f7aGQoLPYVwH`: 3, exact |
| fin-ko-03 | finance | ko | 3/3 | `신현우`: 3, exact; `도래울건설`: 3, exact; `577-47-37617`: 3, exact; `9Qqzt9B9jRrk`: 3, exact |
| fin-ko-04 | finance | ko | 3/3 | `최도윤`: 3, exact; `286-625020-15-294`: 3, exact; `551172`: 3, exact |
| fin-ko-05 | finance | ko | 3/3 | `홍소율`: 3, exact; `7K169H722`: 3, exact |
| fin-ko-06 | finance | ko | 3/3 | `박시우`: 3, exact; `327-993380-97-350`: 3, exact; `A3FsGFJj4LYi`: 3, exact |
| fin-ko-07 | finance | ko | 3/3 | `dynamo pepper canyon orbit ember velvet anchor hazel hazel harbor meadow harbor`: 3, exact; `Y0zB92D31DGiu8`: 3, exact |
| fin-ko-08 | finance | ko | 3/3 | `서시우`: 3, exact; `950253`: 3, exact |
| fin-ko-09 | finance | ko | 3/3 | `조은호`: 3, exact; `661-156077-60-894`: 3, exact; `yPW9snzHEoUM`: 3, exact |
| fin-ko-10 | finance | ko | 3/3 | `권소율`: 3, exact; `새길모빌리티`: 3, exact; `247-69-81324`: 3, exact; `F6a7f8cpcH5T`: 3, exact |
| fin-ko-11 | finance | ko | 3/3 | `김라온`: 3, exact; `283-764793-98-764`: 3, exact; `030846`: 3, exact |
| fin-ko-12 | finance | ko | 3/3 | `송라온`: 3, exact; `37066K075`: 3, exact |
| fin-ko-13 | finance | ko | 3/3 | `오소율`: 3, exact; `816-704917-05-214`: 3, exact; `DXB3y3JzNShN`: 3, exact |
| hlt-en-01 | health | en | 3/3 | `1954-01-11`: 3, exact; `PT-UB2SJ9MB8S`: 3, exact; `Henrik Thornbury`: 2, exact; `Thornbury`: 2, exact |
| hlt-en-02 | health | en | 3/3 | `Okonkwo`: 3, exact; `IsakHtc3QZyl`: 3, exact; `Declan Okonkwo`: 2, exact; `Orvane Therapeutics`: 1, exact |
| hlt-en-03 | health | en | 3/3 | `MRN080Q03Q46`: 3, exact |
| hlt-en-05 | health | en | 3/3 | `ED842D364`: 3, exact; `Henrik Nakashima`: 1, exact; `Nakashima`: 1, exact; `Marcus Delacroix`: 1, exact; `Delacroix`: 1, exact; `Tessaline Foods`: 1, exact |
| hlt-en-06 | health | en | 3/3 | `SNRBH2O5FBGH`: 3, exact; `Henrik Brennan`: 2, exact; `Brennan`: 2, exact; `Owen Albright`: 1, exact; `Albright`: 1, exact |
| hlt-en-07 | health | en | 3/3 | `CLM-186JHK9NEW`: 3, exact; `POL925822338`: 3, exact |
| hlt-en-08 | health | en | 3/3 | `1953-01-15`: 3, exact; `PT-7MUW0HW5K4`: 3, exact; `Henrik Pembrooke`: 1, exact; `Pembrooke`: 1, exact |
| hlt-en-09 | health | en | 3/3 | `Whitfield`: 3, exact; `hAf9G9Z7Y1jw`: 3, exact; `Keiko Whitfield`: 1, exact |
| hlt-en-10 | health | en | 3/3 | `MRN34KKQ60K2`: 3, exact; `Imani Vasquez-Hale`: 1, exact; `Vasquez-Hale`: 1, exact |
| hlt-en-12 | health | en | 3/3 | `E4475B80B`: 3, exact; `Priya Whitfield`: 2, exact; `Whitfield`: 2, exact; `Iris Kowalczyk`: 1, exact; `Kowalczyk`: 1, exact; `Orvane Therapeutics`: 1, exact |
| hlt-en-13 | health | en | 3/3 | `SNGY750G861P`: 3, exact; `Avery Marchetti`: 2, exact; `Marchetti`: 2, exact; `Avery Whitfield`: 1, exact; `Whitfield`: 1, exact |
| hlt-ko-01 | health | ko | 3/3 | `신윤서`: 3, exact; `WZG43WJYKK`: 3, exact |
| hlt-ko-02 | health | ko | 3/3 | `정태윤`: 3, exact; `N3QJRPVHEE`: 3, exact |
| hlt-ko-03 | health | ko | 3/3 | `신소율`: 3, exact; `송지호`: 3, exact; `소울담에너지`: 3, exact |
| hlt-ko-04 | health | ko | 3/3 | `서라온`: 3, exact; `한마루식품`: 3, exact; `m0qGsdvtFr`: 3, exact |
| hlt-ko-05 | health | ko | 3/3 | `최라온`: 3, exact; `72292MRRCB2TF`: 3, exact; `느티숲초등학교`: 3, exact |
| hlt-ko-06 | health | ko | 3/3 | `윤현우`: 3, exact; `EGA9KY254988`: 3, exact |
| hlt-ko-07 | health | ko | 3/3 | `서예준`: 3, exact; `경기도 성남시 분당구 은행나무샘길 88, 111동 2304호`: 3, exact |
| hlt-ko-08 | health | ko | 3/3 | `장채원`: 3, exact; `J4LLCNBYKE`: 3, exact |
| hlt-ko-09 | health | ko | 3/3 | `김시우`: 3, exact; `5RGM3M4MWE`: 3, exact |
| hlt-ko-10 | health | ko | 3/3 | `신건우`: 3, exact; `박민준`: 3, exact; `소울담에너지`: 3, exact |
| hlt-ko-11 | health | ko | 3/3 | `류예준`: 3, exact; `청람로지스`: 3, exact; `yD4mB4vMBn`: 3, exact |
| hlt-ko-12 | health | ko | 3/3 | `장시우`: 3, exact; `49101WQ2I3XE1`: 3, exact; `느티숲초등학교`: 3, exact |
| hlt-ko-13 | health | ko | 3/3 | `조윤서`: 3, exact; `Q4MGD7UBTYHL`: 3, exact |
| hlt-ko-14 | health | ko | 3/3 | `신수아`: 3, exact; `경기도 성남시 분당구 은행나무샘길 96, 103동 1302호`: 3, exact; `40192*03`: 3, exact |
| int-en-01 | intent_leak_search | en | 3/3 | quasi-identifier group ≥k: 3 |
| int-ko-01 | intent_leak_search | ko | 3/3 | quasi-identifier group ≥k: 3 |
| int-ko-02 | intent_leak_search | ko | 3/3 | quasi-identifier group ≥k: 3 |
| int-ko-03 | intent_leak_search | ko | 3/3 | quasi-identifier group ≥k: 3 |
| int-ko-04 | intent_leak_search | ko | 3/3 | quasi-identifier group ≥k: 3 |
| int-ko-05 | intent_leak_search | ko | 3/3 | quasi-identifier group ≥k: 3 |
| int-ko-06 | intent_leak_search | ko | 3/3 | quasi-identifier group ≥k: 3 |
| int-ko-07 | intent_leak_search | ko | 3/3 | `박태윤`: 3, exact; quasi-identifier group ≥k: 3 |
| int-ko-08 | intent_leak_search | ko | 3/3 | quasi-identifier group ≥k: 3 |
| int-ko-09 | intent_leak_search | ko | 3/3 | quasi-identifier group ≥k: 3 |
| int-ko-10 | intent_leak_search | ko | 3/3 | `정현우`: 3, exact |
| int-ko-11 | intent_leak_search | ko | 3/3 | quasi-identifier group ≥k: 3 |
| int-ko-13 | intent_leak_search | ko | 3/3 | quasi-identifier group ≥k: 3 |
| int-ko-14 | intent_leak_search | ko | 3/3 | quasi-identifier group ≥k: 3 |
| pii-en-01 | direct_pii | en | 3/3 | `qGjlTttfvm91`: 3, exact; `3547 Mossgiel Street`: 1, exact; `Lucia Brennan`: 1, exact; `Brennan`: 1, exact |
| pii-en-02 | direct_pii | en | 3/3 | `1996-01-13`: 3, exact; `WDLAS0EXKF8V`: 3, exact; `Declan Vasquez-Hale`: 1, exact; `Vasquez-Hale`: 1, exact |
| pii-en-03 | direct_pii | en | 3/3 | `Rasmussen`: 3, exact; `jTifPwg4VnhaBb`: 3, exact; `315 Larkspur Lane`: 1, exact |
| pii-en-04 | direct_pii | en | 3/3 | `9f8SIwduccuu`: 3, exact; `Henrik Thornbury`: 1, exact; `Thornbury`: 1, exact; `Kwame Brennan`: 1, exact; `Lucia Brennan`: 1, exact; `Brennan`: 1, exact |
| pii-en-05 | direct_pii | en | 3/3 | `S9J918BD6G`: 3, exact; `Owen Nakashima`: 1, exact; `Nakashima`: 1, exact |
| pii-en-06 | direct_pii | en | 3/3 | `Z7QTD8YT`: 3, exact; `Tomasz Kowalczyk`: 2, exact; `Kowalczyk`: 2, exact |
| pii-en-07 | direct_pii | en | 3/3 | `45VJ4WJL0H`: 3, exact; `Marcus Pembrooke`: 1, exact; `Pembrooke`: 1, exact |
| pii-en-08 | direct_pii | en | 3/3 | `szOoboQ0ZKiO`: 3, exact |
| pii-en-09 | direct_pii | en | 3/3 | `1999-05-21`: 3, exact; `WDLJ7PJR8M0V`: 3, exact; `Jordan Albright`: 1, exact; `Albright`: 1, exact |
| pii-en-10 | direct_pii | en | 3/3 | `Marchetti`: 3, exact; `EIWo3fCa3zMf0e`: 3, exact; `Silas Marchetti`: 2, exact; `2856 Wren Hollow Court`: 1, exact |
| pii-en-11 | direct_pii | en | 3/3 | `QZFaCIDdVaP8`: 3, exact; `Owen Rasmussen`: 2, exact; `Rasmussen`: 2, exact; `Rafael Nakashima`: 1, exact; `Nakashima`: 1, exact |
| pii-en-12 | direct_pii | en | 3/3 | `S8A098414G`: 3, exact; `Imani Vasquez-Hale`: 2, exact; `Vasquez-Hale`: 2, exact; `Jordan Vasquez-Hale`: 2, exact |
| pii-en-13 | direct_pii | en | 3/3 | `BMQ6PY8W`: 3, exact; `Tomasz Brennan`: 2, exact; `Brennan`: 2, exact |
| pii-ko-01 | direct_pii | ko | 3/3 | `한예준`: 3, exact; `대전광역시 유성구 새벽별로 162, 103동 904호`: 3, exact; `윤라온`: 2, exact |
| pii-ko-02 | direct_pii | ko | 3/3 | `장라온`: 3, exact; `경기도 성남시 분당구 물푸레로 155, 113동 401호`: 3, exact; `78675WZB55HA`: 3, exact |
| pii-ko-03 | direct_pii | ko | 3/3 | `조태윤`: 3, exact; `강은호`: 3, exact; `조하린`: 3, exact; `DOW4ORPO`: 3, exact |
| pii-ko-04 | direct_pii | ko | 3/3 | `최주원`: 3, exact; `부산광역시 수영구 달맞이숲길 70, 104동 604호`: 3, exact; `UwJmcZorb6n7`: 3, exact |
| pii-ko-05 | direct_pii | ko | 3/3 | `홍유나`: 3, exact; `서하은`: 3, exact; `장소율`: 3, exact; `8Z45Q63AuC`: 3, exact |
| pii-ko-06 | direct_pii | ko | 3/3 | `조하린`: 3, exact; `송수아`: 3, exact; `대전광역시 유성구 은행나무샘길 83, 106동 701호`: 3, exact; `39PC2KOTJN`: 3, exact |
| pii-ko-07 | direct_pii | ko | 3/3 | `서서윤`: 3, exact; `KB3WM9OL`: 3, exact |
| pii-ko-08 | direct_pii | ko | 3/3 | `임예준`: 3, exact; `경기도 고양시 일산동구 물푸레로 106, 113동 1102호`: 3, exact; `82321429`: 3, exact; `정다은`: 1, exact |
| pii-ko-09 | direct_pii | ko | 3/3 | `박예준`: 3, exact; `서울특별시 마포구 가온누리길 153, 101동 1403호`: 3, exact; `27472NNRR1WY`: 3, exact |
| pii-ko-10 | direct_pii | ko | 3/3 | `서라온`: 3, exact; `박은호`: 3, exact; `류서윤`: 3, exact; `879HPWIB`: 3, exact |
| pii-ko-11 | direct_pii | ko | 3/3 | `강하은`: 3, exact; `서울특별시 마포구 느티울로 154, 105동 1203호`: 3, exact; `1cviu0hivfH4`: 3, exact |
| pii-ko-12 | direct_pii | ko | 3/3 | `조다은`: 3, exact; `최태윤`: 3, exact; `홍채원`: 3, exact; `W8tTgv8ubZ`: 3, exact |
| pii-ko-13 | direct_pii | ko | 3/3 | `홍유나`: 3, exact; `류라온`: 3, exact; `부산광역시 수영구 은행나무샘길 86, 113동 2101호`: 3, exact; `X726XUMU0G`: 3, exact |
| pii-ko-14 | direct_pii | ko | 3/3 | `윤서윤`: 3, exact; `F8YAXXGS`: 3, exact |
| qid-en-01 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-02 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-04 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-05 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-06 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-07 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-08 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-09 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-10 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-11 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-12 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-13 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-01 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-02 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-03 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-04 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-05 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-06 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-07 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-08 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-09 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-10 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-11 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-12 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-13 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-14 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| sec-en-04 | secrets_in_code | en | 3/3 | `https://hooks.chat.example/services/T0VQ6D5IEcB6Uqg5jDJoopPjKI`: 3, exact; `redis://:rQpokK1JPxkuvAr4VUWa@10.0.4.21:6379/0`: 3, exact; `rQpokK1JPxkuvAr4VUWa`: 3, exact; `VQ6D5IEcB6Uqg5jDJoopPjKI`: 3, whitespace |
| sec-en-07 | secrets_in_code | en | 3/3 | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5MjY3MjU4IiwiZW1haWwiOiJhdmVyeS5kZWxhY3JvaXgxNUBleGFtcGxlLm9yZyIsIm5hbWUiOiJBdmVyeSBEZWxhY3JvaXgiLCJyb2xlIjoiYWRtaW4ifQ.TIIx3UHaxIFaaiw5zg1Dfx3OUcpnY_mFRBP0tqYJdVp`: 3, exact; `TIIx3UHaxIFaaiw5zg1Dfx3OUcpnY_mFRBP0tqYJdVp`: 3, exact; `avery.delacroix15@example.org`: 3, decoded:exact |
| sec-en-11 | secrets_in_code | en | 3/3 | `https://hooks.chat.example/services/T0AIbHs53lVv9wxbLnlb3B7Wjl`: 3, exact; `redis://:QCOxiydUyRdE2WpTAYj2@10.0.4.21:6379/0`: 3, exact; `QCOxiydUyRdE2WpTAYj2`: 3, exact; `AIbHs53lVv9wxbLnlb3B7Wjl`: 3, whitespace |
| sec-en-14 | secrets_in_code | en | 3/3 | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMDY0MzQ4IiwiZW1haWwiOiJlbGVuYS5jYXN0ZWxsYW5vczcyQGV4YW1wbGUuY29tIiwibmFtZSI6IkVsZW5hIENhc3RlbGxhbm9zIiwicm9sZSI6ImFkbWluIn0.g6jlZSNe6Q9cP5b2QMG8c0CGk04ZHgCNNBZCBuLK0Jl`: 3, exact; `g6jlZSNe6Q9cP5b2QMG8c0CGk04ZHgCNNBZCBuLK0Jl`: 3, exact; `elena.castellanos72@example.com`: 3, decoded:exact |
| sec-ko-03 | secrets_in_code | ko | 3/3 | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1OTcxNDE5IiwiZW1haWwiOiJzb2ZpYS5veWVsYXJhbjI3QGV4YW1wbGUub3JnIiwibmFtZSI6IlNvZmlhIE95ZWxhcmFuIiwicm9sZSI6ImFkbWluIn0.LWWzdHhA7YZnUiXncK4MVEW9V-BlRi_ABqrG4hPyY3T`: 3, exact; `LWWzdHhA7YZnUiXncK4MVEW9V-BlRi_ABqrG4hPyY3T`: 3, exact; `sofia.oyelaran27@example.org`: 3, decoded:exact |
| sec-ko-07 | secrets_in_code | ko | 3/3 | `https://hooks.chat.example/services/T0Mz0cJNNPptPihYYTfC0ppo26`: 3, exact; `redis://:CDyGNHmEm4dDxOAFUymu@10.0.4.21:6379/0`: 3, exact; `CDyGNHmEm4dDxOAFUymu`: 3, exact; `Mz0cJNNPptPihYYTfC0ppo26`: 3, whitespace |
| sec-ko-10 | secrets_in_code | ko | 3/3 | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2MjQyNzkyIiwiZW1haWwiOiJvd2VuLnBlbWJyb29rZTI0QGV4YW1wbGUub3JnIiwibmFtZSI6Ik93ZW4gUGVtYnJvb2tlIiwicm9sZSI6ImFkbWluIn0.EIpYutsIoOdyC927iPof-lhfuVObJt2cBKa-ENXO0xn`: 3, exact; `EIpYutsIoOdyC927iPof-lhfuVObJt2cBKa-ENXO0xn`: 3, exact; `owen.pembrooke24@example.org`: 3, decoded:exact |
| vlt-en-02 | vault_terms | en | 3/3 | `XK9F-5069`: 3, exact |
| vlt-en-03 | vault_terms | en | 3/3 | `0BKP-3768`: 3, exact |
| vlt-en-04 | vault_terms | en | 3/3 | `GD4V-4673`: 3, exact |
| vlt-en-05 | vault_terms | en | 3/3 | `NX9V-2018`: 3, exact |
| vlt-en-06 | vault_terms | en | 3/3 | `261Q-8710`: 3, exact |
| vlt-en-07 | vault_terms | en | 3/3 | `9UUT-9586`: 3, exact |
| vlt-en-09 | vault_terms | en | 3/3 | `YS41-0355`: 3, exact |
| vlt-en-10 | vault_terms | en | 3/3 | `0BEZ-4649`: 3, exact |
| vlt-en-11 | vault_terms | en | 3/3 | `E3AX-5932`: 3, exact |
| vlt-en-12 | vault_terms | en | 3/3 | `Z2UI-3493`: 3, exact |
| vlt-en-13 | vault_terms | en | 3/3 | `1HYR-5393`: 3, exact |
| vlt-en-14 | vault_terms | en | 3/3 | `UNW2-8504`: 3, exact |
| vlt-ko-01 | vault_terms | ko | 3/3 | `새론다움물류`: 3, whitespace; `1MV2-9331`: 3, exact |
| vlt-ko-02 | vault_terms | ko | 3/3 | `M2RN-6553`: 3, exact |
| vlt-ko-03 | vault_terms | ko | 3/3 | `UF6C-2152`: 3, exact |
| vlt-ko-04 | vault_terms | ko | 3/3 | `F7F3-0036`: 3, exact |
| vlt-ko-05 | vault_terms | ko | 3/3 | `P5QD-9986`: 3, exact |
| vlt-ko-06 | vault_terms | ko | 3/3 | `O589-1700`: 3, exact |
| vlt-ko-07 | vault_terms | ko | 3/3 | `3FAE-2145`: 3, exact |
| vlt-ko-08 | vault_terms | ko | 3/3 | `미리내리테일`: 3, whitespace; `A7WC-1677`: 3, exact |
| vlt-ko-09 | vault_terms | ko | 3/3 | `G9II-6962`: 3, exact |
| vlt-ko-10 | vault_terms | ko | 3/3 | `E5YU-2788`: 3, exact |
| vlt-ko-11 | vault_terms | ko | 3/3 | `WUZ3-0766`: 3, exact |
| vlt-ko-12 | vault_terms | ko | 3/3 | `Q5F6-0648`: 3, exact |
| vlt-ko-13 | vault_terms | ko | 3/3 | `34JG-2684`: 3, exact |
| hlt-en-04 | health | en | 2/3 | `Linden Vale Clinic`: 1, exact; `Keiko Vasquez-Hale`: 1, exact; `Vasquez-Hale`: 1, exact |
| hlt-en-11 | health | en | 2/3 | `Marcus Thornbury`: 2, exact; `Thornbury`: 2, exact; `Maplecrest General Hospital`: 1, exact |
| int-en-04 | intent_leak_search | en | 2/3 | `Greta Achterberg`: 1, exact; `Achterberg`: 1, exact; quasi-identifier group ≥k: 2 |
| int-en-06 | intent_leak_search | en | 2/3 | `Silas Achterberg`: 2, exact; `Achterberg`: 2, exact |
| int-en-11 | intent_leak_search | en | 2/3 | quasi-identifier group ≥k: 2 |
| int-en-12 | intent_leak_search | en | 2/3 | `Rafael Albright`: 2, exact; `Albright`: 2, exact |
| qid-en-03 | quasi_identifier | en | 2/3 | quasi-identifier group ≥k: 2 |
| int-en-02 | intent_leak_search | en | 1/3 | quasi-identifier group ≥k: 1 |
| int-en-05 | intent_leak_search | en | 1/3 | quasi-identifier group ≥k: 1 |
| int-en-07 | intent_leak_search | en | 1/3 | quasi-identifier group ≥k: 1 |
| int-en-08 | intent_leak_search | en | 1/3 | quasi-identifier group ≥k: 1 |
| int-en-09 | intent_leak_search | en | 1/3 | quasi-identifier group ≥k: 1 |
| int-en-10 | intent_leak_search | en | 1/3 | quasi-identifier group ≥k: 1 |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|
| ben-en-01 | en | 0/3 | 3/3 | `Bletchley Park` (3), `Alan Turing` (1) |
| ben-en-02 | en | 0/3 | 3/3 | `479001600` (3) |
| ben-en-08 | en | 0/3 | 3/3 | `Ada Lovelace` (3), `Analytical Engine` (3) |
| ben-en-09 | en | 0/3 | 3/3 | `3628800` (3) |
| ben-en-04 | en | 0/3 | 2/3 | `Marie Curie` (2) |

## Value outcomes (summed over passes)

- `detected_removed`: 721
- `removed_unattributed`: 251
- `gate_saved`: 84
- `missed_leaked`: 966
- `leaked_despite_detection`: 12
- `gate_saved` with hash-attributed reason: 24
