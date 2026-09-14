# Airlock eval summary

- Target: `http://127.0.0.1:8801` (baseline:raw)
- Passes: 3 · cases per pass: 243 · protection level: `baseline:raw`
- Dataset sha256: `cd40ce707652d30ffb2007c5ccaac62c61709d42382c4c623351b5114c850609`
- Harness version: 1.0.0 · started 2026-09-14T10:09:10.253113+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 99.5% | 0.0 pp | 99.5% to 99.5% |
| Leak rate (individual values) | 99.3% | 0.0 pp | 99.3% to 99.3% |
| Leak rate (exact-string hits only) | 75.0% | 0.0 pp | 75.0% to 75.0% |
| Canary leak rate | 98.6% | 0.0 pp | 98.6% to 98.6% |
| Quasi-identifier re-identification rate | 98.0% | 0.0 pp | 98.0% to 98.0% |
| Identity leak (any identity item or identifying quasi set) | 98.5% | 0.0 pp | 98.5% to 98.5% |
| Gate save rate (upper bound: request-level) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 99.3% | 0.0 pp | 99.3% to 99.3% |
| Block rate (all) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Block rate (non-benign) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Over-block on benign | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Benign cases with any masking | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Over-redaction (must_keep strings missing) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Over-redaction (cases with any missing) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Local overhead, mean (ms) | 0 | 0.0 | 0 to 0 |
| Local overhead, p95 (ms) | 0 | 0.0 | 0 to 0 |
| Client wall time, mean (ms) | 1 | 0.0 | 1 to 1 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 100.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a |
| benign | n/a | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | 0.0% ± 0.0 |
| direct_pii | 100.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a |
| finance | 100.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a |
| health | 100.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a |
| intent_leak_search | 96.3% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a |
| quasi_identifier | 100.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a | n/a |
| secrets_in_code | 100.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a |
| vault_terms | 100.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 100.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 |
| ko | 99.1% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 |

## Pass independence

- Byte-identical outbound payloads in all 3 passes: 243 of 243 cases (100.0%)
- Detect time p50 by pass: 0 / 0 / 0 ms
- Detector temperature: unknown

## Cases that leaked in any pass

215 case(s) leaked in every pass; 0 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| adv-en-01 | adversarial | en | 3/3 | `5096 9138 2570 9695`: 3, digits |
| adv-en-02 | adversarial | en | 3/3 | `666-15-5370`: 3, digits; `Greta Kowalczyk`: 3, exact; `Kowalczyk`: 3, exact |
| adv-en-03 | adversarial | en | 3/3 | `dpk_live_5DmIiYQiczDDZP6eIWtYOKHMcJHg`: 3, decoded:exact; `ZHBrX2xpdmVfNURtSWlZUWljekREWlA2ZUlXdFlPS0hNY0pIZw==`: 3, exact; `5DmIiYQiczDDZP6eIWtYOKHMcJHg`: 3, decoded:exact |
| adv-en-04 | adversarial | en | 3/3 | `jordan.lindqvist93@example.com`: 3, exact; `(312) 555-0102`: 3, exact; `AC-8NMD61YGVM`: 3, exact; `Jordan Lindqvist`: 3, exact; `Lindqvist`: 3, exact |
| adv-en-05 | adversarial | en | 3/3 | `5UiLLMSBFBwgLoQi`: 3, exact; `Silas Lindqvist`: 3, exact; `Lindqvist`: 3, exact |
| adv-en-06 | adversarial | en | 3/3 | `Elena Whitfield`: 3, casefold; `Whitfield`: 3, exact; `(312) 555-0103`: 3, casefold |
| adv-en-07 | adversarial | en | 3/3 | `(617) 555-0193`: 3, numeral_words; `marcus.albright69@example.org`: 3, decoded:exact; `Albright`: 3, exact |
| adv-en-08 | adversarial | en | 3/3 | `5106 1241 9510 7109`: 3, digits |
| adv-en-09 | adversarial | en | 3/3 | `666-58-6193`: 3, digits; `Owen Vasquez-Hale`: 3, exact; `Vasquez-Hale`: 3, exact |
| adv-en-10 | adversarial | en | 3/3 | `dpk_live_dCEpljl716jQ6Wy8MJKchHlrRIpF`: 3, decoded:exact; `ZHBrX2xpdmVfZENFcGxqbDcxNmpRNld5OE1KS2NoSGxyUklwRg==`: 3, exact; `dCEpljl716jQ6Wy8MJKchHlrRIpF`: 3, decoded:exact |
| adv-en-11 | adversarial | en | 3/3 | `iris.whitfield89@example.com`: 3, exact; `(617) 555-0178`: 3, exact; `AC-UZI8ZD0T7L`: 3, exact; `Iris Whitfield`: 3, exact; `Whitfield`: 3, exact |
| adv-en-12 | adversarial | en | 3/3 | `PQdGRijUux0C5cph`: 3, exact; `Marcus Brennan`: 3, exact; `Brennan`: 3, exact |
| adv-en-13 | adversarial | en | 3/3 | `Henrik Thornbury`: 3, casefold; `Thornbury`: 3, exact; `(720) 555-0137`: 3, casefold |
| adv-ko-01 | adversarial | ko | 3/3 | `961821-2849347`: 3, digits; `장유나`: 3, whitespace |
| adv-ko-02 | adversarial | ko | 3/3 | `010-0911-0925`: 3, numeral_words; `공일공 공구일일 공구이오`: 3, exact; `박하은`: 3, exact |
| adv-ko-03 | adversarial | ko | 3/3 | `vx6KsXmT60wuBd3QoP`: 3, decoded:exact; `REJfUEFTU1dPUkQ9dng2S3NYbVQ2MHd1QmQzUW9Q`: 3, exact |
| adv-ko-04 | adversarial | ko | 3/3 | `한유나`: 3, exact; `492-433332-71-129`: 3, exact; `TXL6C6EPNQP5`: 3, exact |
| adv-ko-05 | adversarial | ko | 3/3 | `류수아`: 3, exact; `5618-3548-5979-9868`: 3, exact |
| adv-ko-06 | adversarial | ko | 3/3 | `4774406885844904`: 3, digits; `장은호`: 3, exact |
| adv-ko-07 | adversarial | ko | 3/3 | `정민준`: 3, alnum; `taeyang4404@example.com`: 3, decoded:exact |
| adv-ko-08 | adversarial | ko | 3/3 | `731521-1385835`: 3, digits; `최주원`: 3, whitespace |
| adv-ko-09 | adversarial | ko | 3/3 | `010-0444-2367`: 3, numeral_words; `공일공 공사사사 이삼육칠`: 3, exact; `조유나`: 3, exact |
| adv-ko-10 | adversarial | ko | 3/3 | `qowlajctYJir8pz0Ga`: 3, decoded:exact; `REJfUEFTU1dPUkQ9cW93bGFqY3RZSmlyOHB6MEdh`: 3, exact |
| adv-ko-11 | adversarial | ko | 3/3 | `강채원`: 3, exact; `677-656796-74-479`: 3, exact; `TX8KP7QD8A31`: 3, exact |
| adv-ko-12 | adversarial | ko | 3/3 | `홍주원`: 3, exact; `4226-4001-2164-1277`: 3, exact |
| adv-ko-13 | adversarial | ko | 3/3 | `5127214713788210`: 3, digits; `정예준`: 3, exact |
| adv-ko-14 | adversarial | ko | 3/3 | `정주원`: 3, alnum; `taeyang1704@example.net`: 3, decoded:exact |
| fin-en-01 | finance | en | 3/3 | `Rafael Thornbury`: 3, exact; `Thornbury`: 3, exact; `5811 9184 6707 5448`: 3, exact; `1UeK0pfNaN2k`: 3, exact |
| fin-en-02 | finance | en | 3/3 | `Greta Delacroix`: 3, exact; `Delacroix`: 3, exact; `GB71 FERN 3193 9115 0268 25`: 3, exact; `F22B4749`: 3, exact |
| fin-en-03 | finance | en | 3/3 | `Henrik Vasquez-Hale`: 3, exact; `Vasquez-Hale`: 3, exact; `666-87-8426`: 3, exact; `665732782`: 3, exact; `96858516866`: 3, exact; `WVbFIfwJ1C`: 3, exact; `Marrowgate Insurance`: 3, exact |
| fin-en-04 | finance | en | 3/3 | `Marcus Vasquez-Hale`: 3, exact; `Vasquez-Hale`: 3, exact; `LNA94A19528B`: 3, exact |
| fin-en-05 | finance | en | 3/3 | `orbit cactus harbor hazel hazel tundra meadow dynamo ember anchor dynamo velvet`: 3, exact; `XKsng4eDOybWOD`: 3, exact |
| fin-en-06 | finance | en | 3/3 | `Avery Brennan`: 3, exact; `Marcus Castellanos`: 3, exact; `Iris Lindqvist`: 3, exact; `8495776820`: 3, exact; `1490774579`: 3, exact; `9326226283`: 3, exact; `uijZYVg4QJEcbdDz`: 3, exact |
| fin-en-07 | finance | en | 3/3 | `Elena Whitfield`: 3, exact; `Whitfield`: 3, exact; `BRK-5JTYGLK7MY`: 3, exact |
| fin-en-08 | finance | en | 3/3 | `Rafael Brennan`: 3, exact; `Brennan`: 3, exact; `5011 9831 6070 5637`: 3, exact; `U5WqKYim9Xw3`: 3, exact |
| fin-en-09 | finance | en | 3/3 | `Keiko Rasmussen`: 3, exact; `Rasmussen`: 3, exact; `GB79 FERN 2728 0957 7684 66`: 3, exact; `E882A1G1`: 3, exact |
| fin-en-10 | finance | en | 3/3 | `Greta Pembrooke`: 3, exact; `Pembrooke`: 3, exact; `666-61-8154`: 3, exact; `434462310`: 3, exact; `11413888539`: 3, exact; `K8N1lKXDj3`: 3, exact; `Greyloft Studios`: 3, exact |
| fin-en-11 | finance | en | 3/3 | `Rafael Whitfield`: 3, exact; `Whitfield`: 3, exact; `LN38CC0C6474`: 3, exact |
| fin-en-12 | finance | en | 3/3 | `pepper canyon cobalt velvet ripple garnet cactus saddle orbit ember hazel lantern`: 3, exact; `uKJOJlZg76DP8m`: 3, exact |
| fin-en-13 | finance | en | 3/3 | `Sofia Castellanos`: 3, exact; `Imani Brennan`: 3, exact; `Marcus Brennan`: 3, exact; `7558525367`: 3, exact; `1706570561`: 3, exact; `1034077592`: 3, exact; `bjJk5XpmcUEOrgMx`: 3, exact |
| fin-en-14 | finance | en | 3/3 | `Keiko Kowalczyk`: 3, exact; `Kowalczyk`: 3, exact; `BRK-F16XE4QGAR`: 3, exact |
| fin-ko-01 | finance | ko | 3/3 | `윤하린`: 3, exact; `5148-3832-5173-8783`: 3, exact; `010-0763-4976`: 3, exact; `417626`: 3, exact |
| fin-ko-02 | finance | ko | 3/3 | `최도윤`: 3, exact; `721613-2272446`: 3, exact; `193-364014-02-231`: 3, exact; `f7aGQoLPYVwH`: 3, exact |
| fin-ko-03 | finance | ko | 3/3 | `신현우`: 3, exact; `도래울건설`: 3, exact; `577-47-37617`: 3, exact; `9Qqzt9B9jRrk`: 3, exact |
| fin-ko-04 | finance | ko | 3/3 | `최도윤`: 3, exact; `286-625020-15-294`: 3, exact; `551172`: 3, exact |
| fin-ko-05 | finance | ko | 3/3 | `홍소율`: 3, exact; `7K169H722`: 3, exact |
| fin-ko-06 | finance | ko | 3/3 | `박시우`: 3, exact; `327-993380-97-350`: 3, exact; `A3FsGFJj4LYi`: 3, exact |
| fin-ko-07 | finance | ko | 3/3 | `dynamo pepper canyon orbit ember velvet anchor hazel hazel harbor meadow harbor`: 3, exact; `Y0zB92D31DGiu8`: 3, exact |
| fin-ko-08 | finance | ko | 3/3 | `서시우`: 3, exact; `4961-5755-2441-5607`: 3, exact; `010-0269-0942`: 3, exact; `950253`: 3, exact |
| fin-ko-09 | finance | ko | 3/3 | `조은호`: 3, exact; `851904-2542055`: 3, exact; `661-156077-60-894`: 3, exact; `yPW9snzHEoUM`: 3, exact |
| fin-ko-10 | finance | ko | 3/3 | `권소율`: 3, exact; `새길모빌리티`: 3, exact; `247-69-81324`: 3, exact; `F6a7f8cpcH5T`: 3, exact |
| fin-ko-11 | finance | ko | 3/3 | `김라온`: 3, exact; `283-764793-98-764`: 3, exact; `030846`: 3, exact |
| fin-ko-12 | finance | ko | 3/3 | `송라온`: 3, exact; `37066K075`: 3, exact |
| fin-ko-13 | finance | ko | 3/3 | `오소율`: 3, exact; `816-704917-05-214`: 3, exact; `DXB3y3JzNShN`: 3, exact |
| hlt-en-01 | health | en | 3/3 | `Henrik Thornbury`: 3, exact; `Thornbury`: 3, exact; `1954-01-11`: 3, exact; `PT-UB2SJ9MB8S`: 3, exact |
| hlt-en-02 | health | en | 3/3 | `Declan Okonkwo`: 3, exact; `Okonkwo`: 3, exact; `Orvane Therapeutics`: 3, exact; `IsakHtc3QZyl`: 3, exact |
| hlt-en-03 | health | en | 3/3 | `Marcus Delacroix`: 3, exact; `Delacroix`: 3, exact; `MRN080Q03Q46`: 3, exact |
| hlt-en-04 | health | en | 3/3 | `Marcus Nakashima`: 3, exact; `Nakashima`: 3, exact; `Keiko Vasquez-Hale`: 3, exact; `Vasquez-Hale`: 3, exact; `Linden Vale Clinic`: 3, exact |
| hlt-en-05 | health | en | 3/3 | `Henrik Nakashima`: 3, exact; `Nakashima`: 3, exact; `Marcus Delacroix`: 3, exact; `Delacroix`: 3, exact; `Tessaline Foods`: 3, exact; `ED842D364`: 3, exact |
| hlt-en-06 | health | en | 3/3 | `Owen Albright`: 3, exact; `Albright`: 3, exact; `Henrik Brennan`: 3, exact; `Brennan`: 3, exact; `SNRBH2O5FBGH`: 3, exact |
| hlt-en-07 | health | en | 3/3 | `Imani Vasquez-Hale`: 3, exact; `Vasquez-Hale`: 3, exact; `CLM-186JHK9NEW`: 3, exact; `POL925822338`: 3, exact |
| hlt-en-08 | health | en | 3/3 | `Henrik Pembrooke`: 3, exact; `Pembrooke`: 3, exact; `1953-01-15`: 3, exact; `PT-7MUW0HW5K4`: 3, exact |
| hlt-en-09 | health | en | 3/3 | `Keiko Whitfield`: 3, exact; `Whitfield`: 3, exact; `Orvane Therapeutics`: 3, exact; `hAf9G9Z7Y1jw`: 3, exact |
| hlt-en-10 | health | en | 3/3 | `Imani Vasquez-Hale`: 3, exact; `Vasquez-Hale`: 3, exact; `MRN34KKQ60K2`: 3, exact |
| hlt-en-11 | health | en | 3/3 | `Declan Whitfield`: 3, exact; `Whitfield`: 3, exact; `Marcus Thornbury`: 3, exact; `Thornbury`: 3, exact; `Maplecrest General Hospital`: 3, exact |
| hlt-en-12 | health | en | 3/3 | `Iris Kowalczyk`: 3, exact; `Kowalczyk`: 3, exact; `Priya Whitfield`: 3, exact; `Whitfield`: 3, exact; `Orvane Therapeutics`: 3, exact; `E4475B80B`: 3, exact |
| hlt-en-13 | health | en | 3/3 | `Avery Whitfield`: 3, exact; `Whitfield`: 3, exact; `Avery Marchetti`: 3, exact; `Marchetti`: 3, exact; `SNGY750G861P`: 3, exact |
| hlt-ko-01 | health | ko | 3/3 | `신윤서`: 3, exact; `WZG43WJYKK`: 3, exact |
| hlt-ko-02 | health | ko | 3/3 | `정태윤`: 3, exact; `801325-1831897`: 3, exact; `N3QJRPVHEE`: 3, exact |
| hlt-ko-03 | health | ko | 3/3 | `신소율`: 3, exact; `송지호`: 3, exact; `소울담에너지`: 3, exact; `41760980`: 3, exact |
| hlt-ko-04 | health | ko | 3/3 | `서라온`: 3, exact; `한마루식품`: 3, exact; `m0qGsdvtFr`: 3, exact |
| hlt-ko-05 | health | ko | 3/3 | `최라온`: 3, exact; `72292MRRCB2TF`: 3, exact; `느티숲초등학교`: 3, exact |
| hlt-ko-06 | health | ko | 3/3 | `윤현우`: 3, exact; `010-0208-1160`: 3, exact; `EGA9KY254988`: 3, exact |
| hlt-ko-07 | health | ko | 3/3 | `서예준`: 3, exact; `경기도 성남시 분당구 은행나무샘길 88, 111동 2304호`: 3, exact; `38966240`: 3, exact |
| hlt-ko-08 | health | ko | 3/3 | `장채원`: 3, exact; `J4LLCNBYKE`: 3, exact |
| hlt-ko-09 | health | ko | 3/3 | `김시우`: 3, exact; `641418-2323295`: 3, exact; `5RGM3M4MWE`: 3, exact |
| hlt-ko-10 | health | ko | 3/3 | `신건우`: 3, exact; `박민준`: 3, exact; `소울담에너지`: 3, exact; `91560118`: 3, exact |
| hlt-ko-11 | health | ko | 3/3 | `류예준`: 3, exact; `청람로지스`: 3, exact; `yD4mB4vMBn`: 3, exact |
| hlt-ko-12 | health | ko | 3/3 | `장시우`: 3, exact; `49101WQ2I3XE1`: 3, exact; `느티숲초등학교`: 3, exact |
| hlt-ko-13 | health | ko | 3/3 | `조윤서`: 3, exact; `010-0854-7660`: 3, exact; `Q4MGD7UBTYHL`: 3, exact |
| hlt-ko-14 | health | ko | 3/3 | `신수아`: 3, exact; `경기도 성남시 분당구 은행나무샘길 96, 103동 1302호`: 3, exact; `40192*03`: 3, exact |
| int-en-01 | intent_leak_search | en | 3/3 | quasi-identifier group ≥k: 3 |
| int-en-02 | intent_leak_search | en | 3/3 | quasi-identifier group ≥k: 3 |
| int-en-03 | intent_leak_search | en | 3/3 | quasi-identifier group ≥k: 3 |
| int-en-04 | intent_leak_search | en | 3/3 | `Greta Achterberg`: 3, exact; `Achterberg`: 3, exact; quasi-identifier group ≥k: 3 |
| int-en-05 | intent_leak_search | en | 3/3 | quasi-identifier group ≥k: 3 |
| int-en-06 | intent_leak_search | en | 3/3 | `Silas Achterberg`: 3, exact; `Achterberg`: 3, exact |
| int-en-07 | intent_leak_search | en | 3/3 | quasi-identifier group ≥k: 3 |
| int-en-08 | intent_leak_search | en | 3/3 | quasi-identifier group ≥k: 3 |
| int-en-09 | intent_leak_search | en | 3/3 | quasi-identifier group ≥k: 3 |
| int-en-10 | intent_leak_search | en | 3/3 | quasi-identifier group ≥k: 3 |
| int-en-11 | intent_leak_search | en | 3/3 | quasi-identifier group ≥k: 3 |
| int-en-12 | intent_leak_search | en | 3/3 | `Rafael Albright`: 3, exact; `Albright`: 3, exact |
| int-en-13 | intent_leak_search | en | 3/3 | `2436 Quarry Hill Road`: 3, exact |
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
| pii-en-01 | direct_pii | en | 3/3 | `Henrik Pembrooke`: 3, exact; `Pembrooke`: 3, exact; `Lucia Brennan`: 3, exact; `Brennan`: 3, exact; `lucia.brennan52@example.com`: 3, exact; `(720) 555-0140`: 3, exact; `3547 Mossgiel Street`: 3, exact; `qGjlTttfvm91`: 3, exact |
| pii-en-02 | direct_pii | en | 3/3 | `Declan Vasquez-Hale`: 3, exact; `Vasquez-Hale`: 3, exact; `666-22-7176`: 3, exact; `1996-01-13`: 3, exact; `WDLAS0EXKF8V`: 3, exact |
| pii-en-03 | direct_pii | en | 3/3 | `Mateo Rasmussen`: 3, exact; `Rasmussen`: 3, exact; `mateo.rasmussen34@example.org`: 3, exact; `(415) 555-0133`: 3, exact; `315 Larkspur Lane`: 3, exact; `jTifPwg4VnhaBb`: 3, exact |
| pii-en-04 | direct_pii | en | 3/3 | `Kwame Brennan`: 3, exact; `Lucia Brennan`: 3, exact; `Henrik Thornbury`: 3, exact; `Brennan`: 3, exact; `Thornbury`: 3, exact; `(312) 555-0131`: 3, exact; `(617) 555-0133`: 3, exact; `(206) 555-0104`: 3, exact; `9f8SIwduccuu`: 3, exact |
| pii-en-05 | direct_pii | en | 3/3 | `Jordan Rasmussen`: 3, exact; `Rasmussen`: 3, exact; `S9J918BD6G`: 3, exact; `jordan.rasmussen19@example.org`: 3, exact; `Owen Nakashima`: 3, exact; `Nakashima`: 3, exact |
| pii-en-06 | direct_pii | en | 3/3 | `Tomasz Kowalczyk`: 3, exact; `Kowalczyk`: 3, exact; `Z7QTD8YT`: 3, exact; `(206) 555-0118`: 3, exact; `tomasz.kowalczyk64@example.org`: 3, exact |
| pii-en-07 | direct_pii | en | 3/3 | `Marcus Pembrooke`: 3, exact; `Pembrooke`: 3, exact; `marcus.pembrooke56@example.net`: 3, exact; `(415) 555-0139`: 3, exact; `4079 Quarry Hill Road`: 3, exact; `45VJ4WJL0H`: 3, exact |
| pii-en-08 | direct_pii | en | 3/3 | `Priya Marchetti`: 3, exact; `Marchetti`: 3, exact; `Imani Brennan`: 3, exact; `Brennan`: 3, exact; `imani.brennan16@example.com`: 3, exact; `(617) 555-0162`: 3, exact; `1838 Bramblewood Drive`: 3, exact; `szOoboQ0ZKiO`: 3, exact |
| pii-en-09 | direct_pii | en | 3/3 | `Jordan Albright`: 3, exact; `Albright`: 3, exact; `666-43-7586`: 3, exact; `1999-05-21`: 3, exact; `WDLJ7PJR8M0V`: 3, exact |
| pii-en-10 | direct_pii | en | 3/3 | `Silas Marchetti`: 3, exact; `Marchetti`: 3, exact; `silas.marchetti44@example.com`: 3, exact; `(503) 555-0177`: 3, exact; `2856 Wren Hollow Court`: 3, exact; `EIWo3fCa3zMf0e`: 3, exact |
| pii-en-11 | direct_pii | en | 3/3 | `Rafael Nakashima`: 3, exact; `Owen Rasmussen`: 3, exact; `Imani Brennan`: 3, exact; `Nakashima`: 3, exact; `Rasmussen`: 3, exact; `Brennan`: 3, exact; `(206) 555-0152`: 3, exact; `(415) 555-0151`: 3, exact; `(415) 555-0127`: 3, exact; `QZFaCIDdVaP8`: 3, exact |
| pii-en-12 | direct_pii | en | 3/3 | `Imani Vasquez-Hale`: 3, exact; `Vasquez-Hale`: 3, exact; `S8A098414G`: 3, exact; `imani.vasquezhale72@example.org`: 3, exact; `Jordan Vasquez-Hale`: 3, exact |
| pii-en-13 | direct_pii | en | 3/3 | `Tomasz Brennan`: 3, exact; `Brennan`: 3, exact; `BMQ6PY8W`: 3, exact; `(206) 555-0112`: 3, exact; `tomasz.brennan13@example.org`: 3, exact |
| pii-ko-01 | direct_pii | ko | 3/3 | `한예준`: 3, exact; `윤라온`: 3, exact; `010-0455-8128`: 3, exact; `대전광역시 유성구 새벽별로 162, 103동 904호`: 3, exact; `2917693*`: 3, exact |
| pii-ko-02 | direct_pii | ko | 3/3 | `장라온`: 3, exact; `010-0692-0309`: 3, exact; `경기도 성남시 분당구 물푸레로 155, 113동 401호`: 3, exact; `78675WZB55HA`: 3, exact |
| pii-ko-03 | direct_pii | ko | 3/3 | `조태윤`: 3, exact; `강은호`: 3, exact; `조하린`: 3, exact; `010-0302-0037`: 3, exact; `DOW4ORPO`: 3, exact |
| pii-ko-04 | direct_pii | ko | 3/3 | `최주원`: 3, exact; `781310-1705516`: 3, exact; `bom1586@example.org`: 3, exact; `010-0514-4690`: 3, exact; `부산광역시 수영구 달맞이숲길 70, 104동 604호`: 3, exact; `UwJmcZorb6n7`: 3, exact |
| pii-ko-05 | direct_pii | ko | 3/3 | `홍유나`: 3, exact; `010-0740-1610`: 3, exact; `sion0593@example.net`: 3, exact; `서하은`: 3, exact; `010-0395-1291`: 3, exact; `hana2773@example.com`: 3, exact; `장소율`: 3, exact; `010-0836-0401`: 3, exact; `taeyang8883@example.org`: 3, exact; `8Z45Q63AuC`: 3, exact |
| pii-ko-06 | direct_pii | ko | 3/3 | `조하린`: 3, exact; `801511-2457200`: 3, exact; `송수아`: 3, exact; `010-0928-5097`: 3, exact; `대전광역시 유성구 은행나무샘길 83, 106동 701호`: 3, exact; `39PC2KOTJN`: 3, exact |
| pii-ko-07 | direct_pii | ko | 3/3 | `서서윤`: 3, exact; `KB3WM9OL`: 3, exact; `010-0654-9940`: 3, exact; `yerin9163@example.org`: 3, exact |
| pii-ko-08 | direct_pii | ko | 3/3 | `임예준`: 3, exact; `정다은`: 3, exact; `010-0355-4397`: 3, exact; `경기도 고양시 일산동구 물푸레로 106, 113동 1102호`: 3, exact; `82321429`: 3, exact |
| pii-ko-09 | direct_pii | ko | 3/3 | `박예준`: 3, exact; `010-0364-0794`: 3, exact; `서울특별시 마포구 가온누리길 153, 101동 1403호`: 3, exact; `27472NNRR1WY`: 3, exact |
| pii-ko-10 | direct_pii | ko | 3/3 | `서라온`: 3, exact; `박은호`: 3, exact; `류서윤`: 3, exact; `010-0244-4735`: 3, exact; `879HPWIB`: 3, exact |
| pii-ko-11 | direct_pii | ko | 3/3 | `강하은`: 3, exact; `971605-2941975`: 3, exact; `dohyun1122@example.com`: 3, exact; `010-0845-2517`: 3, exact; `서울특별시 마포구 느티울로 154, 105동 1203호`: 3, exact; `1cviu0hivfH4`: 3, exact |
| pii-ko-12 | direct_pii | ko | 3/3 | `조다은`: 3, exact; `010-0502-0772`: 3, exact; `yerin9809@example.org`: 3, exact; `최태윤`: 3, exact; `010-0838-0836`: 3, exact; `dohyun4862@example.net`: 3, exact; `홍채원`: 3, exact; `010-0632-1163`: 3, exact; `taeyang1575@example.com`: 3, exact; `W8tTgv8ubZ`: 3, exact |
| pii-ko-13 | direct_pii | ko | 3/3 | `홍유나`: 3, exact; `891307-1495084`: 3, exact; `류라온`: 3, exact; `010-0829-2250`: 3, exact; `부산광역시 수영구 은행나무샘길 86, 113동 2101호`: 3, exact; `X726XUMU0G`: 3, exact |
| pii-ko-14 | direct_pii | ko | 3/3 | `윤서윤`: 3, exact; `F8YAXXGS`: 3, exact; `010-0110-0038`: 3, exact; `jiwoo9765@example.net`: 3, exact |
| qid-en-01 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-02 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-en-03 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
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
| sec-en-01 | secrets_in_code | en | 3/3 | `i1yqBxCiXkenfTOLpkQ3`: 3, decoded:exact; `aTF5cUJ4Q2lYa2VuZlRPTHBrUTM=`: 3, exact |
| sec-en-02 | secrets_in_code | en | 3/3 | `gtk_6bhkg9l4GvW31eg3ooTNGJY6ICKp4G9nQ0gx`: 3, exact; `6bhkg9l4GvW31eg3ooTNGJY6ICKp4G9nQ0gx`: 3, exact |
| sec-en-03 | secrets_in_code | en | 3/3 | `xlC6J23t1AVwGMQZ`: 3, exact; `FpsHkLjCsXjvF7`: 3, exact |
| sec-en-04 | secrets_in_code | en | 3/3 | `https://hooks.chat.example/services/T0VQ6D5IEcB6Uqg5jDJoopPjKI`: 3, exact; `redis://:rQpokK1JPxkuvAr4VUWa@10.0.4.21:6379/0`: 3, exact; `rQpokK1JPxkuvAr4VUWa`: 3, exact; `VQ6D5IEcB6Uqg5jDJoopPjKI`: 3, whitespace |
| sec-en-05 | secrets_in_code | en | 3/3 | `sFjCk4WdVweWcD9w5Q`: 3, exact; `postgresql://svc_billing:sFjCk4WdVweWcD9w5Q@10.19.5.32:5432/billing?sslmode=require`: 3, exact |
| sec-en-06 | secrets_in_code | en | 3/3 | `pmk_live_ZjGy2bFG6V34lzu3jshUdCCy`: 3, exact; `9FRRqrTbWCKhrXPBuB7BP1ai6EcX5IGD`: 3, exact; `AQiiqJHAkBl3EdPY`: 3, exact; `mysql://root:AQiiqJHAkBl3EdPY@db:3306/shop`: 3, exact; `ZjGy2bFG6V34lzu3jshUdCCy`: 3, exact |
| sec-en-07 | secrets_in_code | en | 3/3 | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5MjY3MjU4IiwiZW1haWwiOiJhdmVyeS5kZWxhY3JvaXgxNUBleGFtcGxlLm9yZyIsIm5hbWUiOiJBdmVyeSBEZWxhY3JvaXgiLCJyb2xlIjoiYWRtaW4ifQ.TIIx3UHaxIFaaiw5zg1Dfx3OUcpnY_mFRBP0tqYJdVp`: 3, exact; `TIIx3UHaxIFaaiw5zg1Dfx3OUcpnY_mFRBP0tqYJdVp`: 3, exact; `avery.delacroix15@example.org`: 3, decoded:exact |
| sec-en-08 | secrets_in_code | en | 3/3 | `mfjTB3vFhwncfkdhS2Mv`: 3, decoded:exact; `bWZqVEIzdkZod25jZmtkaFMyTXY=`: 3, exact |
| sec-en-09 | secrets_in_code | en | 3/3 | `gtk_k4Do3kcCkwaB7niGaFrRc48LX9KToWOifLF4`: 3, exact; `k4Do3kcCkwaB7niGaFrRc48LX9KToWOifLF4`: 3, exact |
| sec-en-10 | secrets_in_code | en | 3/3 | `eM6HEKAD1nwfBvVa`: 3, exact; `IGk2Gm1J2uSjo8`: 3, exact |
| sec-en-11 | secrets_in_code | en | 3/3 | `https://hooks.chat.example/services/T0AIbHs53lVv9wxbLnlb3B7Wjl`: 3, exact; `redis://:QCOxiydUyRdE2WpTAYj2@10.0.4.21:6379/0`: 3, exact; `QCOxiydUyRdE2WpTAYj2`: 3, exact; `AIbHs53lVv9wxbLnlb3B7Wjl`: 3, whitespace |
| sec-en-12 | secrets_in_code | en | 3/3 | `jKnpFlOkzGaH79JecC`: 3, exact; `postgresql://svc_billing:jKnpFlOkzGaH79JecC@10.51.3.17:5432/billing?sslmode=require`: 3, exact |
| sec-en-13 | secrets_in_code | en | 3/3 | `pmk_live_GwbTZjEtL0p2jaHdbY589MVh`: 3, exact; `PimNyYQ20J104S9lnkx9lz0tUNcw0YY8`: 3, exact; `Fi3fq57HFmNsuVvH`: 3, exact; `mysql://root:Fi3fq57HFmNsuVvH@db:3306/shop`: 3, exact; `GwbTZjEtL0p2jaHdbY589MVh`: 3, exact |
| sec-en-14 | secrets_in_code | en | 3/3 | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMDY0MzQ4IiwiZW1haWwiOiJlbGVuYS5jYXN0ZWxsYW5vczcyQGV4YW1wbGUuY29tIiwibmFtZSI6IkVsZW5hIENhc3RlbGxhbm9zIiwicm9sZSI6ImFkbWluIn0.g6jlZSNe6Q9cP5b2QMG8c0CGk04ZHgCNNBZCBuLK0Jl`: 3, exact; `g6jlZSNe6Q9cP5b2QMG8c0CGk04ZHgCNNBZCBuLK0Jl`: 3, exact; `elena.castellanos72@example.com`: 3, decoded:exact |
| sec-ko-01 | secrets_in_code | ko | 3/3 | `1UeFKYhkhmKkKNA4Ow`: 3, exact; `postgresql://svc_billing:1UeFKYhkhmKkKNA4Ow@10.13.7.47:5432/billing?sslmode=require`: 3, exact |
| sec-ko-02 | secrets_in_code | ko | 3/3 | `pmk_live_AD3bZXTPSAF0cKtsuVcXm6gJ`: 3, exact; `0M5M70azs3QmmsjxotppBisPAkRdnmXL`: 3, exact; `1IxpwGvHzlUiPTMw`: 3, exact; `mysql://root:1IxpwGvHzlUiPTMw@db:3306/shop`: 3, exact; `AD3bZXTPSAF0cKtsuVcXm6gJ`: 3, exact |
| sec-ko-03 | secrets_in_code | ko | 3/3 | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1OTcxNDE5IiwiZW1haWwiOiJzb2ZpYS5veWVsYXJhbjI3QGV4YW1wbGUub3JnIiwibmFtZSI6IlNvZmlhIE95ZWxhcmFuIiwicm9sZSI6ImFkbWluIn0.LWWzdHhA7YZnUiXncK4MVEW9V-BlRi_ABqrG4hPyY3T`: 3, exact; `LWWzdHhA7YZnUiXncK4MVEW9V-BlRi_ABqrG4hPyY3T`: 3, exact; `sofia.oyelaran27@example.org`: 3, decoded:exact |
| sec-ko-04 | secrets_in_code | ko | 3/3 | `vd3sAYyIrj23JRF27Ulz`: 3, decoded:exact; `dmQzc0FZeUlyajIzSlJGMjdVbHo=`: 3, exact |
| sec-ko-05 | secrets_in_code | ko | 3/3 | `gtk_iacv2JbTNok6iQ8dES6pLXGoNtcYgON1kz8C`: 3, exact; `iacv2JbTNok6iQ8dES6pLXGoNtcYgON1kz8C`: 3, exact |
| sec-ko-06 | secrets_in_code | ko | 3/3 | `NGBH6YIJwmCzzVTX`: 3, exact; `x359xBnWufjfmr`: 3, exact |
| sec-ko-07 | secrets_in_code | ko | 3/3 | `https://hooks.chat.example/services/T0Mz0cJNNPptPihYYTfC0ppo26`: 3, exact; `redis://:CDyGNHmEm4dDxOAFUymu@10.0.4.21:6379/0`: 3, exact; `CDyGNHmEm4dDxOAFUymu`: 3, exact; `Mz0cJNNPptPihYYTfC0ppo26`: 3, whitespace |
| sec-ko-08 | secrets_in_code | ko | 3/3 | `rP3phuLH3oklwmJCXo`: 3, exact; `postgresql://svc_billing:rP3phuLH3oklwmJCXo@10.50.3.235:5432/billing?sslmode=require`: 3, exact |
| sec-ko-09 | secrets_in_code | ko | 3/3 | `pmk_live_FGiXYVsz2SjDCfXDYHuyhF6c`: 3, exact; `9eKuseLFiItTQreNsapzhc4mnZxsXRZo`: 3, exact; `UCsS4yJ1jaEhFut9`: 3, exact; `mysql://root:UCsS4yJ1jaEhFut9@db:3306/shop`: 3, exact; `FGiXYVsz2SjDCfXDYHuyhF6c`: 3, exact |
| sec-ko-10 | secrets_in_code | ko | 3/3 | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2MjQyNzkyIiwiZW1haWwiOiJvd2VuLnBlbWJyb29rZTI0QGV4YW1wbGUub3JnIiwibmFtZSI6Ik93ZW4gUGVtYnJvb2tlIiwicm9sZSI6ImFkbWluIn0.EIpYutsIoOdyC927iPof-lhfuVObJt2cBKa-ENXO0xn`: 3, exact; `EIpYutsIoOdyC927iPof-lhfuVObJt2cBKa-ENXO0xn`: 3, exact; `owen.pembrooke24@example.org`: 3, decoded:exact |
| sec-ko-11 | secrets_in_code | ko | 3/3 | `W5kmDsioJUli9T2oZvKI`: 3, decoded:exact; `VzVrbURzaW9KVWxpOVQyb1p2S0k=`: 3, exact |
| sec-ko-12 | secrets_in_code | ko | 3/3 | `gtk_FWLIcbmX9FtU1NMlzlo1VOvPkuWNTx1lMmGo`: 3, exact; `FWLIcbmX9FtU1NMlzlo1VOvPkuWNTx1lMmGo`: 3, exact |
| sec-ko-13 | secrets_in_code | ko | 3/3 | `D2DuDEdzjgEJAn7b`: 3, exact; `0xorrbUEa8ENUJ`: 3, exact |
| vlt-en-01 | vault_terms | en | 3/3 | `Marisol Szymborski`: 3, exact; `Sableridge Media`: 3, exact; `Sableridge`: 3, exact; `Wolvercote Energy`: 3, exact; `Project Saltmarsh`: 3, exact; `GID8-6494`: 3, exact |
| vlt-en-02 | vault_terms | en | 3/3 | `Rowena Faircloth`: 3, exact; `Leopold Trevanion`: 3, exact; `Wolvercote`: 3, exact; `Larchfield Dynamics`: 3, exact; `Project Halcyon`: 3, exact; `XK9F-5069`: 3, exact |
| vlt-en-03 | vault_terms | en | 3/3 | `Thaddeus Bellweather`: 3, exact; `Kestrelmoor Partners`: 3, exact; `Kestrelmoor`: 3, exact; `Glimmerstone Retail`: 3, exact; `0BKP-3768`: 3, exact |
| vlt-en-04 | vault_terms | en | 3/3 | `Evander Quistgaard`: 3, exact; `Leopold Ashgrove`: 3, exact; `Wolvercote Energy`: 3, exact; `Wolvercote`: 3, exact; `Umberlane Health`: 3, exact; `Project Halcyon`: 3, exact; `GD4V-4673`: 3, exact |
| vlt-en-05 | vault_terms | en | 3/3 | `Evander Bellweather`: 3, exact; `Glimmerstone Retail`: 3, exact; `Glimmerstone`: 3, exact; `Kestrelmoor Partners`: 3, exact; `Project Nightjar`: 3, exact; `NX9V-2018`: 3, exact |
| vlt-en-06 | vault_terms | en | 3/3 | `Leopold Faircloth`: 3, exact; `Leopold Szymborski`: 3, exact; `Glimmerstone Retail`: 3, exact; `Glimmerstone`: 3, exact; `Harrowgate Biosystems`: 3, exact; `261Q-8710`: 3, exact |
| vlt-en-07 | vault_terms | en | 3/3 | `Marisol Ashgrove`: 3, exact; `Wilhelmina Szymborski`: 3, exact; `Glimmerstone Retail`: 3, exact; `Glimmerstone`: 3, exact; `Pinecroft Freight`: 3, exact; `9UUT-9586`: 3, exact |
| vlt-en-08 | vault_terms | en | 3/3 | `Philippa Bellweather`: 3, exact; `Harrowgate Biosystems`: 3, exact; `Harrowgate`: 3, exact; `Pinecroft Freight`: 3, exact; `Project Nightjar`: 3, exact; `L7LQ-0936`: 3, exact |
| vlt-en-09 | vault_terms | en | 3/3 | `Ignatius Ashgrove`: 3, exact; `Rowena Quistgaard`: 3, exact; `Larchfield`: 3, exact; `Kestrelmoor Partners`: 3, exact; `Project Wrenfall`: 3, exact; `YS41-0355`: 3, exact |
| vlt-en-10 | vault_terms | en | 3/3 | `Evander Szymborski`: 3, exact; `Kestrelmoor Partners`: 3, exact; `Kestrelmoor`: 3, exact; `Umberlane Health`: 3, exact; `0BEZ-4649`: 3, exact |
| vlt-en-11 | vault_terms | en | 3/3 | `Ignatius Trevanion`: 3, exact; `Philippa Ashgrove`: 3, exact; `Larchfield Dynamics`: 3, exact; `Larchfield`: 3, exact; `Harrowgate Biosystems`: 3, exact; `Project Nightjar`: 3, exact; `E3AX-5932`: 3, exact |
| vlt-en-12 | vault_terms | en | 3/3 | `Ignatius Quistgaard`: 3, exact; `Sableridge Media`: 3, exact; `Sableridge`: 3, exact; `Kestrelmoor Partners`: 3, exact; `Project Halcyon`: 3, exact; `Z2UI-3493`: 3, exact |
| vlt-en-13 | vault_terms | en | 3/3 | `Leopold Trevanion`: 3, exact; `Wilhelmina Trevanion`: 3, exact; `Larchfield Dynamics`: 3, exact; `Larchfield`: 3, exact; `Wolvercote Energy`: 3, exact; `1HYR-5393`: 3, exact |
| vlt-en-14 | vault_terms | en | 3/3 | `Rowena Quistgaard`: 3, exact; `Evander Trevanion`: 3, exact; `Wolvercote Energy`: 3, exact; `Wolvercote`: 3, exact; `Pinecroft Freight`: 3, exact; `UNW2-8504`: 3, exact |
| vlt-ko-01 | vault_terms | ko | 3/3 | `탁라온`: 3, exact; `미리내리테일`: 3, exact; `새론다움물류`: 3, exact; `프로젝트 물수제비`: 3, exact; `1MV2-9331`: 3, exact |
| vlt-ko-02 | vault_terms | ko | 3/3 | `선우다온`: 3, exact; `제갈윤슬`: 3, exact; `물빛나래테크`: 3, exact; `누리결파트너스`: 3, exact; `프로젝트 은하수다리`: 3, exact; `M2RN-6553`: 3, exact |
| vlt-ko-03 | vault_terms | ko | 3/3 | `탁라온`: 3, exact; `누리결파트너스`: 3, exact; `물빛나래테크`: 3, exact; `UF6C-2152`: 3, exact |
| vlt-ko-04 | vault_terms | ko | 3/3 | `서문가을`: 3, exact; `남궁하람`: 3, exact; `새론다움물류`: 3, exact; `도담결에너지`: 3, exact; `프로젝트 물수제비`: 3, exact; `F7F3-0036`: 3, exact |
| vlt-ko-05 | vault_terms | ko | 3/3 | `황보이든`: 3, exact; `물빛나래테크`: 3, exact; `가온솔메디컬`: 3, exact; `프로젝트 물수제비`: 3, exact; `P5QD-9986`: 3, exact |
| vlt-ko-06 | vault_terms | ko | 3/3 | `황보이든`: 3, exact; `서문가을`: 3, exact; `가온솔메디컬`: 3, exact; `미리내리테일`: 3, exact; `O589-1700`: 3, exact |
| vlt-ko-07 | vault_terms | ko | 3/3 | `사공나래`: 3, exact; `황보이든`: 3, exact; `미리내리테일`: 3, exact; `새론다움물류`: 3, exact; `3FAE-2145`: 3, exact |
| vlt-ko-08 | vault_terms | ko | 3/3 | `남궁하람`: 3, exact; `물빛나래테크`: 3, exact; `미리내리테일`: 3, exact; `프로젝트 반딧불`: 3, exact; `A7WC-1677`: 3, exact |
| vlt-ko-09 | vault_terms | ko | 3/3 | `황보이든`: 3, exact; `남궁하람`: 3, exact; `가온솔메디컬`: 3, exact; `물빛나래테크`: 3, exact; `프로젝트 초승달`: 3, exact; `G9II-6962`: 3, exact |
| vlt-ko-10 | vault_terms | ko | 3/3 | `탁라온`: 3, exact; `물빛나래테크`: 3, exact; `새론다움물류`: 3, exact; `E5YU-2788`: 3, exact |
| vlt-ko-11 | vault_terms | ko | 3/3 | `남궁하람`: 3, exact; `독고새론`: 3, exact; `해솔마루바이오`: 3, exact; `가온솔메디컬`: 3, exact; `프로젝트 초승달`: 3, exact; `WUZ3-0766`: 3, exact |
| vlt-ko-12 | vault_terms | ko | 3/3 | `남궁하람`: 3, exact; `새론다움물류`: 3, exact; `해솔마루바이오`: 3, exact; `프로젝트 물수제비`: 3, exact; `Q5F6-0648`: 3, exact |
| vlt-ko-13 | vault_terms | ko | 3/3 | `황보이든`: 3, exact; `제갈윤슬`: 3, exact; `누리결파트너스`: 3, exact; `도담결에너지`: 3, exact; `34JG-2684`: 3, exact |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|

## Value outcomes (summed over passes)

- `detected_removed`: 0
- `removed_unattributed`: 15
- `gate_saved`: 0
- `missed_leaked`: 2019
- `leaked_despite_detection`: 0
- `gate_saved` with hash-attributed reason: 0
