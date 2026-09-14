# Answer utility: airlock 39281fb (feat/s10-hardening), AIRLOCK_GLINER=on, placeholder, dev split

- answer source: `recorded`; judge `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning `none`), blind, seeded order; distortion confirmation `nvidia/Nemotron-3-Ultra-550b-a55b`
- judged passes: 1; tokens used so far: prompt 155,569, completion 13,410

| Metric | All | ko | en |
|---|---:|---:|---:|
| System answer usefulness (1-5) | 4.15 ± 0.00 | 4.16 ± 0.00 | 4.14 ± 0.00 |
| Reference answer usefulness (1-5) | 3.97 ± 0.00 | 4.42 ± 0.00 | 3.46 ± 0.00 |
| Utility ratio vs reference | 1.05 ± 0.00 | 0.94 ± 0.00 | 1.20 ± 0.00 |
| Factual distortion (system) | 11.9% ± 0.0 | 9.7% ± 0.0 | 14.3% ± 0.0 |
| Factual distortion (reference) | 10.2% ± 0.0 | 12.9% ± 0.0 | 7.1% ± 0.0 |
| System scored >= reference | 67.8% ± 0.0 | 58.1% ± 0.0 | 78.6% ± 0.0 |
| Judged cases per pass | 59.00 ± 0.00 | 31.00 ± 0.00 | 28.00 ± 0.00 |
| Blocked (not judged) per pass | 1.00 ± 0.00 | 1.00 ± 0.00 | 0.00 ± 0.00 |
| Unjudged (errors, empty reference) per pass | 2.00 ± 0.00 | 0.00 ± 0.00 | 2.00 ± 0.00 |

## By category

| Category | Utility ratio | Distortion | Judged |
|---|---:|---:|---:|
| adversarial | 0.95 ± 0.00 | 0.0% ± 0.0 | 6.00 ± 0.00 |
| benign | 1.07 ± 0.00 | 0.0% ± 0.0 | 6.00 ± 0.00 |
| direct_pii | 0.97 ± 0.00 | 0.0% ± 0.0 | 8.00 ± 0.00 |
| finance | 1.06 ± 0.00 | 12.5% ± 0.0 | 8.00 ± 0.00 |
| health | 1.79 ± 0.00 | 0.0% ± 0.0 | 7.00 ± 0.00 |
| quasi_identifier | 1.12 ± 0.00 | 12.5% ± 0.0 | 8.00 ± 0.00 |
| secrets_in_code | 0.79 ± 0.00 | 50.0% ± 0.0 | 8.00 ± 0.00 |
| vault_terms | 0.97 ± 0.00 | 12.5% ± 0.0 | 8.00 ± 0.00 |

## Distorted system answers

| Case | Pass | Judge's evidence |
|---|---:|---|
| fin-en-02 | 1 | Answer 2 states the payment reference as 'DEPOSIT FlAT 4' with a lowercase 'l' in 'FlAT', but the user's request shows the reference as 'DEPOSIT FLAT 4' with all uppercase letters. |
| qid-ko-01 | 1 | Answer 2 states '신분·연령·부서 등 식별 정보는 전혀 적지 마십시오' (do not write any identifying information such as identity, age, department) and provides a template with '(서명·주민번호·사번·연락처 일체 기재 금지)' (signature, resident number, employee number, contact info all prohibited). The user explicitly gave their department ( |
| sec-en-06 | 1 | Answer 1 claims 'env_file requires Docker Compose file format version 2.1+' and that adding a version line fixes the issue. This is incorrect: env_file was introduced in Compose Specification 2.2 (Docker Compose v2.24.0+), not 2.1. Version 2.1 does not support env_file at all. The answer also states |
| sec-en-11 | 1 | The answer states 'Redis default is **6379**' and 'your config uses **6379**', but the standard Redis default port is 6379. This is a factual error about the default port number. |
| sec-en-13 | 1 | Answer 2 states 'env_file requires Docker Compose v2.24+ (released July 2024)'. The user's docker-compose.yml lacks a version declaration, which causes legacy docker-compose (v1) to default to version 1/2 where env_file is unsupported. The actual requirement is Compose file format version 3.7+, not  |
| sec-ko-04 | 1 | Answer 1 states: '이 에러의 주요 원인은 Secret의 data 필드 값이 base64 인코딩되어 있지 않기 때문입니다.' and 'DB_USER 값 YSBkYXRhYmFzZSB1c2Vy는 "a database user"를 base64 인코딩한 것입니다.' The user's YAML shows DB_USER: b3JkZXJzX3J3 which decodes to 'orders_rw' (matching the log), and DB_PASSWORD: dmQzc0FZeUlyajIzSlJGMjdVbHo= which dec |
| vlt-ko-07 | 1 | Answer 2 states '새론다움물류의 사공나래입니다' (I am Sagong Narae of Saerondaum Logistics) and signs off as '새론다움물류 사공나래 드림'. The user request says '사공나래 명의로' (in the name of Sagong Narae) and identifies Sagong Narae as the sender from 미리내리테일 (Mirinaeri Retail), while the recipient is 새론다움물류 (Saerondaum Logistic |
