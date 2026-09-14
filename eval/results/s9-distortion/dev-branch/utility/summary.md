# Answer utility: airlock 91d21f3 (feat/distortion), AIRLOCK_GLINER=on, placeholder, dev split

- answer source: `recorded`; judge `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning `none`), blind, seeded order; distortion confirmation `nvidia/Nemotron-3-Ultra-550b-a55b`
- judged passes: 1; tokens used so far: prompt 175,207, completion 18,361

| Metric | All | ko | en |
|---|---:|---:|---:|
| System answer usefulness (1-5) | 4.42 ± 0.00 | 4.25 ± 0.00 | 4.61 ± 0.00 |
| Reference answer usefulness (1-5) | 4.12 ± 0.00 | 4.44 ± 0.00 | 3.75 ± 0.00 |
| Utility ratio vs reference | 1.07 ± 0.00 | 0.96 ± 0.00 | 1.23 ± 0.00 |
| Factual distortion (system) | 6.7% ± 0.0 | 9.4% ± 0.0 | 3.6% ± 0.0 |
| Factual distortion (reference) | 13.3% ± 0.0 | 15.6% ± 0.0 | 10.7% ± 0.0 |
| System scored >= reference | 70.0% ± 0.0 | 56.2% ± 0.0 | 85.7% ± 0.0 |
| Judged cases per pass | 60.00 ± 0.00 | 32.00 ± 0.00 | 28.00 ± 0.00 |
| Blocked (not judged) per pass | 2.00 ± 0.00 | 0.00 ± 0.00 | 2.00 ± 0.00 |
| Unjudged (errors, empty reference) per pass | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.00 ± 0.00 |

## By category

| Category | Utility ratio | Distortion | Judged |
|---|---:|---:|---:|
| adversarial | 1.14 ± 0.00 | 0.0% ± 0.0 | 6.00 ± 0.00 |
| benign | 0.93 ± 0.00 | 16.7% ± 0.0 | 6.00 ± 0.00 |
| direct_pii | 0.88 ± 0.00 | 0.0% ± 0.0 | 8.00 ± 0.00 |
| finance | 1.20 ± 0.00 | 12.5% ± 0.0 | 8.00 ± 0.00 |
| health | 1.06 ± 0.00 | 12.5% ± 0.0 | 8.00 ± 0.00 |
| quasi_identifier | 1.48 ± 0.00 | 0.0% ± 0.0 | 8.00 ± 0.00 |
| secrets_in_code | 0.97 ± 0.00 | 12.5% ± 0.0 | 8.00 ± 0.00 |
| vault_terms | 1.06 ± 0.00 | 0.0% ± 0.0 | 8.00 ± 0.00 |

## Distorted system answers

| Case | Pass | Judge's evidence |
|---|---:|---|
| ben-ko-02 | 1 | Answer 2 states the battle date as '1592년 음력 7월 8~9일' (1592, 7th lunar month 8-9th day). The correct date for the Battle of Myeongnyang is 1597 (정유재란), not 1592 (임진왜란). This is a material factual error regarding the war and year. |
| fin-ko-13 | 1 | Answer 2 states: '거주지: 압류된 계좌' and '근무처/소속: 가온신협'. The user provided '압류된 계좌 가온신협 816-704917-05-214' as a seized account at Gaon Credit Union, not as the debtor's residence or workplace. |
| hlt-ko-11 | 1 | Answer 1 states the department as '청람로지스 품질 부서' while the user specified '청람로지스 품질관리팀'. |
| sec-en-06 | 1 | Answer 2 states: 'env_file in Docker Compose loads variables for variable substitution inside the Compose file itself — it does not automatically pass them to the container's environment.' This is incorrect when env_file is placed at the top level of the compose file (as noted in Answer 1 Option D). |
