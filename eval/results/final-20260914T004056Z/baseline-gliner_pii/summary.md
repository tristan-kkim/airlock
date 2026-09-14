# Airlock eval summary

- Target: `http://127.0.0.1:8804` (baseline:gliner_pii)
- Passes: 3 · cases per pass: 243 · protection level: `baseline:gliner_pii`
- Dataset sha256: `cd40ce707652d30ffb2007c5ccaac62c61709d42382c4c623351b5114c850609`
- Harness version: 1.0.0 · started 2026-09-14T00:41:20.155561+00:00

All rates are computed per pass, then summarized across passes as mean, sample standard deviation and range (min to max). Definitions: `eval/README.md`.

## Headline

| Metric | Mean | Std | Range |
|---|---:|---:|---:|
| Leak rate (cases) | 19.0% | 0.0 pp | 19.0% to 19.0% |
| Leak rate (individual values) | 7.8% | 0.0 pp | 7.8% to 7.8% |
| Leak rate (exact-string hits only) | 12.0% | 0.0 pp | 12.0% to 12.0% |
| Canary leak rate | 12.4% | 0.0 pp | 12.4% to 12.4% |
| Quasi-identifier re-identification rate | 10.0% | 0.0 pp | 10.0% to 10.0% |
| Identity leak (any identity item or identifying quasi set) | 18.9% | 0.0 pp | 18.9% to 18.9% |
| Gate save rate (upper bound: request-level) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Gate save rate (lower bound: hash-attributed) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Values that got past the detectors | 7.4% | 0.0 pp | 7.4% to 7.4% |
| Block rate (all) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Block rate (non-benign) | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Over-block on benign | 0.0% | 0.0 pp | 0.0% to 0.0% |
| Benign cases with any masking | 59.3% | 0.0 pp | 59.3% to 59.3% |
| Over-redaction (must_keep strings missing) | 14.1% | 0.0 pp | 14.1% to 14.1% |
| Over-redaction (cases with any missing) | 27.6% | 0.0 pp | 27.6% to 27.6% |
| Local overhead, mean (ms) | 93 | 161.4 | 0 to 280 |
| Local overhead, p95 (ms) | 166 | 287.0 | 0 to 497 |
| Client wall time, mean (ms) | 94 | 161.6 | 1 to 281 |
| Errors per pass | 0 | 0.0 | 0 to 0 |

## By category

| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |
|---|---:|---:|---:|---:|---:|
| adversarial | 37.0% ± 0.0 | 0.0% ± 0.0 | 12.5% ± 0.0 | 0.0% ± 0.0 | n/a |
| benign | n/a | 0.0% ± 0.0 | 32.7% ± 0.0 | n/a | 59.3% ± 0.0 |
| direct_pii | 25.9% ± 0.0 | 0.0% ± 0.0 | 19.7% ± 0.0 | 0.0% ± 0.0 | n/a |
| finance | 14.8% ± 0.0 | 0.0% ± 0.0 | 13.8% ± 0.0 | 0.0% ± 0.0 | n/a |
| health | 3.7% ± 0.0 | 0.0% ± 0.0 | 15.8% ± 0.0 | 0.0% ± 0.0 | n/a |
| intent_leak_search | 11.1% ± 0.0 | 0.0% ± 0.0 | 18.8% ± 0.0 | n/a | n/a |
| quasi_identifier | 7.4% ± 0.0 | 0.0% ± 0.0 | 8.5% ± 0.0 | n/a | n/a |
| secrets_in_code | 48.1% ± 0.0 | 0.0% ± 0.0 | 2.9% ± 0.0 | 0.0% ± 0.0 | n/a |
| vault_terms | 3.7% ± 0.0 | 0.0% ± 0.0 | 6.8% ± 0.0 | 0.0% ± 0.0 | n/a |

## By language

| Lang | Leak rate | Block rate | Over-redaction |
|---|---:|---:|---:|
| en | 16.8% ± 0.0 | 0.0% ± 0.0 | 10.5% ± 0.0 |
| ko | 21.1% ± 0.0 | 0.0% ± 0.0 | 17.7% ± 0.0 |

## Cases that leaked in any pass

41 case(s) leaked in every pass; 0 leaked in some passes only.

| Case | Category | Lang | Leaked passes | What reached the cloud (value: passes, match variants) |
|---|---|---|---:|---|
| adv-en-03 | adversarial | en | 3/3 | `dpk_live_5DmIiYQiczDDZP6eIWtYOKHMcJHg`: 3, decoded:exact; `ZHBrX2xpdmVfNURtSWlZUWljekREWlA2ZUlXdFlPS0hNY0pIZw==`: 3, exact; `5DmIiYQiczDDZP6eIWtYOKHMcJHg`: 3, decoded:exact |
| adv-en-06 | adversarial | en | 3/3 | `(312) 555-0103`: 3, casefold |
| adv-en-07 | adversarial | en | 3/3 | `(617) 555-0193`: 3, numeral_words |
| adv-en-10 | adversarial | en | 3/3 | `dpk_live_dCEpljl716jQ6Wy8MJKchHlrRIpF`: 3, decoded:exact; `ZHBrX2xpdmVfZENFcGxqbDcxNmpRNld5OE1KS2NoSGxyUklwRg==`: 3, exact; `dCEpljl716jQ6Wy8MJKchHlrRIpF`: 3, decoded:exact |
| adv-en-13 | adversarial | en | 3/3 | `(720) 555-0137`: 3, casefold |
| adv-ko-01 | adversarial | ko | 3/3 | `961821-2849347`: 3, digits |
| adv-ko-02 | adversarial | ko | 3/3 | `010-0911-0925`: 3, numeral_words; `공일공 공구일일 공구이오`: 3, exact |
| adv-ko-06 | adversarial | ko | 3/3 | `4774406885844904`: 3, digits |
| adv-ko-08 | adversarial | ko | 3/3 | `731521-1385835`: 3, digits |
| adv-ko-13 | adversarial | ko | 3/3 | `5127214713788210`: 3, digits |
| fin-en-02 | finance | en | 3/3 | `GB71 FERN 3193 9115 0268 25`: 3, exact |
| fin-en-09 | finance | en | 3/3 | `GB79 FERN 2728 0957 7684 66`: 3, exact; `E882A1G1`: 3, exact |
| fin-ko-06 | finance | ko | 3/3 | `327-993380-97-350`: 3, exact |
| fin-ko-10 | finance | ko | 3/3 | `권소율`: 3, exact |
| hlt-ko-03 | health | ko | 3/3 | `신소율`: 3, exact; `41760980`: 3, exact |
| int-ko-02 | intent_leak_search | ko | 3/3 | quasi-identifier group ≥k: 3 |
| int-ko-05 | intent_leak_search | ko | 3/3 | quasi-identifier group ≥k: 3 |
| int-ko-14 | intent_leak_search | ko | 3/3 | quasi-identifier group ≥k: 3 |
| pii-en-03 | direct_pii | en | 3/3 | `Rasmussen`: 3, whitespace |
| pii-en-07 | direct_pii | en | 3/3 | `Pembrooke`: 3, whitespace |
| pii-en-10 | direct_pii | en | 3/3 | `Marchetti`: 3, whitespace |
| pii-ko-01 | direct_pii | ko | 3/3 | `윤라온`: 3, exact |
| pii-ko-05 | direct_pii | ko | 3/3 | `010-0395-1291`: 3, exact; `장소율`: 3, exact; `010-0836-0401`: 3, exact |
| pii-ko-08 | direct_pii | ko | 3/3 | `정다은`: 3, exact |
| pii-ko-12 | direct_pii | ko | 3/3 | `010-0838-0836`: 3, exact |
| qid-en-06 | quasi_identifier | en | 3/3 | quasi-identifier group ≥k: 3 |
| qid-ko-06 | quasi_identifier | ko | 3/3 | quasi-identifier group ≥k: 3 |
| sec-en-02 | secrets_in_code | en | 3/3 | `gtk_6bhkg9l4GvW31eg3ooTNGJY6ICKp4G9nQ0gx`: 3, exact; `6bhkg9l4GvW31eg3ooTNGJY6ICKp4G9nQ0gx`: 3, exact |
| sec-en-04 | secrets_in_code | en | 3/3 | `rQpokK1JPxkuvAr4VUWa`: 3, exact |
| sec-en-05 | secrets_in_code | en | 3/3 | `sFjCk4WdVweWcD9w5Q`: 3, exact |
| sec-en-06 | secrets_in_code | en | 3/3 | `AQiiqJHAkBl3EdPY`: 3, exact; `mysql://root:AQiiqJHAkBl3EdPY@db:3306/shop`: 3, exact |
| sec-en-11 | secrets_in_code | en | 3/3 | `QCOxiydUyRdE2WpTAYj2`: 3, exact |
| sec-en-12 | secrets_in_code | en | 3/3 | `jKnpFlOkzGaH79JecC`: 3, exact |
| sec-en-13 | secrets_in_code | en | 3/3 | `Fi3fq57HFmNsuVvH`: 3, exact; `mysql://root:Fi3fq57HFmNsuVvH@db:3306/shop`: 3, exact |
| sec-ko-01 | secrets_in_code | ko | 3/3 | `1UeFKYhkhmKkKNA4Ow`: 3, exact |
| sec-ko-02 | secrets_in_code | ko | 3/3 | `1IxpwGvHzlUiPTMw`: 3, exact; `mysql://root:1IxpwGvHzlUiPTMw@db:3306/shop`: 3, exact |
| sec-ko-05 | secrets_in_code | ko | 3/3 | `gtk_iacv2JbTNok6iQ8dES6pLXGoNtcYgON1kz8C`: 3, exact; `iacv2JbTNok6iQ8dES6pLXGoNtcYgON1kz8C`: 3, exact |
| sec-ko-07 | secrets_in_code | ko | 3/3 | `https://hooks.chat.example/services/T0Mz0cJNNPptPihYYTfC0ppo26`: 3, exact; `CDyGNHmEm4dDxOAFUymu`: 3, exact; `Mz0cJNNPptPihYYTfC0ppo26`: 3, whitespace |
| sec-ko-08 | secrets_in_code | ko | 3/3 | `rP3phuLH3oklwmJCXo`: 3, exact |
| sec-ko-09 | secrets_in_code | ko | 3/3 | `UCsS4yJ1jaEhFut9`: 3, exact; `mysql://root:UCsS4yJ1jaEhFut9@db:3306/shop`: 3, exact |
| vlt-ko-06 | vault_terms | ko | 3/3 | `O589-1700`: 3, exact |

## Benign cases with over-blocking or masking

| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |
|---|---|---:|---:|---|
| ben-en-01 | en | 0/3 | 3/3 | `Alan Turing` (3), `Bletchley Park` (3) |
| ben-en-02 | en | 0/3 | 3/3 | `479001600` (3) |
| ben-en-04 | en | 0/3 | 3/3 | `Marie Curie` (3), `1911` (3) |
| ben-en-08 | en | 0/3 | 3/3 | `Ada Lovelace` (3) |
| ben-en-09 | en | 0/3 | 3/3 | `3628800` (3) |
| ben-en-10 | en | 0/3 | 3/3 | `iron-deficiency anemia` (3), `B12` (3) |
| ben-en-13 | en | 0/3 | 3/3 | - |
| ben-en-14 | en | 0/3 | 3/3 | `Kyoto` (3) |
| ben-ko-01 | ko | 0/3 | 3/3 | `세종대왕` (3) |
| ben-ko-02 | ko | 0/3 | 3/3 | `이순신` (3) |
| ben-ko-05 | ko | 0/3 | 3/3 | - |
| ben-ko-07 | ko | 0/3 | 3/3 | `김치찌개` (3) |
| ben-ko-08 | ko | 0/3 | 3/3 | `서울 부산` (3) |
| ben-ko-09 | ko | 0/3 | 3/3 | `장영실` (3) |
| ben-ko-12 | ko | 0/3 | 3/3 | `역류성 식도염` (3) |
| ben-ko-13 | ko | 0/3 | 3/3 | `불국사` (3), `석굴암` (3) |

## Value outcomes (summed over passes)

- `detected_removed`: 1242
- `removed_unattributed`: 633
- `gate_saved`: 0
- `missed_leaked`: 150
- `leaked_despite_detection`: 9
- `gate_saved` with hash-attributed reason: 0
