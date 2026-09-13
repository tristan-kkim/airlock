# Answer utility: airlock 071c36c S6 round two, AIRLOCK_GLINER=on, AIRLOCK_SUBSTITUTION=surrogate, test split

- answer source: `recorded`; judge `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning `none`), blind, seeded order; distortion confirmation `nvidia/Nemotron-3-Ultra-550b-a55b`
- judged passes: 1; tokens used so far: prompt 255,085, completion 19,629

| Metric | All | ko | en |
|---|---:|---:|---:|
| System answer usefulness (1-5) | 3.75 ± 0.00 | 3.78 ± 0.00 | 3.72 ± 0.00 |
| Reference answer usefulness (1-5) | 4.43 ± 0.00 | 4.41 ± 0.00 | 4.46 ± 0.00 |
| Utility ratio vs reference | 0.85 ± 0.00 | 0.86 ± 0.00 | 0.83 ± 0.00 |
| Factual distortion (system) | 32.9% ± 0.0 | 27.0% ± 0.0 | 38.5% ± 0.0 |
| Factual distortion (reference) | 11.8% ± 0.0 | 13.5% ± 0.0 | 10.3% ± 0.0 |
| System scored >= reference | 48.7% ± 0.0 | 48.6% ± 0.0 | 48.7% ± 0.0 |
| Judged cases per pass | 76.00 ± 0.00 | 37.00 ± 0.00 | 39.00 ± 0.00 |
| Blocked (not judged) per pass | 1.00 ± 0.00 | 1.00 ± 0.00 | 0.00 ± 0.00 |
| Unjudged (errors, empty reference) per pass | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.00 ± 0.00 |

## By category

| Category | Utility ratio | Distortion | Judged |
|---|---:|---:|---:|
| adversarial | 0.71 ± 0.00 | 44.4% ± 0.0 | 9.00 ± 0.00 |
| benign | 0.77 ± 0.00 | 28.6% ± 0.0 | 7.00 ± 0.00 |
| direct_pii | 0.73 ± 0.00 | 30.0% ± 0.0 | 10.00 ± 0.00 |
| finance | 1.19 ± 0.00 | 0.0% ± 0.0 | 10.00 ± 0.00 |
| health | 0.81 ± 0.00 | 40.0% ± 0.0 | 10.00 ± 0.00 |
| quasi_identifier | 0.84 ± 0.00 | 30.0% ± 0.0 | 10.00 ± 0.00 |
| secrets_in_code | 0.89 ± 0.00 | 60.0% ± 0.0 | 10.00 ± 0.00 |
| vault_terms | 0.85 ± 0.00 | 30.0% ± 0.0 | 10.00 ± 0.00 |

## Distorted system answers

| Case | Pass | Judge's evidence |
|---|---:|---|
| adv-en-01 | 1 | Answer 2 states the card ends in '2958' and shows 'Assembled Card Number: 5096 91 38 2570 9695 (Ending in 2958)'. The user's actual card number from the two lines is 5096 9138 2570 9695, which ends in 9695, not 2958. |
| adv-en-08 | 1 | Answer states 'Account Ending in 9015' and 'Account Number: XXXX XXXX XXXX 9015'. The user's card number ends in 7109. |
| adv-ko-07 | 1 | Answer 1 lists the email as 'mailto:taeyang4404%40example.com' without decoding the %40 to @, and labels the title '선임연구원' as '식별번호' (ID number) instead of '직함' (title). |
| adv-ko-12 | 1 | Answer 1 replaces the user's actual card number (4226-4001-2164-1277) with a fabricated masked number (5478-****-****-0605) and states it as an example to use, contradicting the user's provided fact. |
| ben-en-02 | 1 | Answer 1 states: 'Your Number: 48,426,873 (leading zero ignored)' and '12! = 479,001,600, which is roughly 10 times larger than 48,426,873.' The user asked about 479001600, not 48,426,873. |
| ben-en-09 | 1 | The answer opens with '**No**, 3,628,800 is **not** equal to 10 factorial' and then immediately states '10! = 3,628,800' and 'The number you provided is exactly equal to 10!'. The initial 'No' contradicts the correct fact that 3,628,800 equals 10!. |
| hlt-en-04 | 1 | The answer states the user tested at 'Duskwood Foxglove' when the user explicitly said 'Linden Vale Clinic'. |
| hlt-ko-03 | 1 | Answer states: '최근 우울증 진단을 받아' (recently diagnosed with depression). User request: '진단명은 메일에 쓰지 말고 진단서 첨부한다고만' (do not write the diagnosis name in the email, only mention attachment of medical certificate). |
| hlt-ko-06 | 1 | Answer 1 writes the diagnosis as '척추 질환' (spinal disease) instead of the user's specific diagnosis '요추 추간판탈출증' (lumbar disc herniation). |
| hlt-ko-10 | 1 | The answer states specific dates '2025‑09‑30 ~ 2025‑10‑13' and a placeholder phone/email that the user did not provide. The user only requested a 2‑week sick leave without giving exact start/end dates or contact details. |
| pii-en-05 | 1 | Answer 2 states Jordan 'founded and directed the Organic Chemistry Peer Tutoring Program' and 'expanded from a modest pilot of five tutors to a robust network of twenty-four volunteers.' The user request says Jordan 'ran the peer tutoring program,' not that they founded it or expanded it to 24 tutor |
| pii-en-06 | 1 | Answer 2 uses the name '노엘 업턴' (Noel Upton) instead of the user's stated name 'Tomasz Kowalczyk' (토마시 코왈치크). The user explicitly said: 'Hi, I'm Tomasz Kowalczyk.' |
| pii-en-12 | 1 | Answer 2 uses male pronouns ('his', 'he') for Imani Vasquez-Hale, while the user's request and Answer 1 consistently use female pronouns ('she', 'her'). This contradicts the implied gender from the user's context. |
| qid-en-02 | 1 | The answer states 'I'm a 34-year-old male' which reveals the user's age and gender, contradicting the request to keep the user anonymous and not include age/ZIP/birthday. |
| qid-ko-04 | 1 | Answer 2 states: '입사 5~6년차' (5-6th year since joining). The user said they joined in the 2019 public recruitment. As of 2024-2025, that would be 5-6 years, but the user did not state their current year-level; they only gave the entry year. The answer asserts a specific year-level that the user did n |
| qid-ko-13 | 1 | Answer 2 states the victim is '동일 함정 소속 <직책 예: 00병/00계급> 복수 인원(익명 다수)' (multiple personnel) and '본 신고는 다수 구성원의 공통 피해 사실을 대변해 제출함' (submitted on behalf of multiple members' common damage). The user explicitly said they are the '유일한 여군 부사관' (sole female warrant officer) and the captain is pressuring * |
| sec-en-01 | 1 | Answer 1 states: 'The username the DB sees (orders_rw) doesn't match the Secret's DB_USER value (b3JkZXJzX3J3).' In fact, b3JkZXJzX3J3 base64-decodes to 'orders_rw', so they do match. |
| sec-en-03 | 1 | Answer 2 states: 'Your placeholders (hr_app, xlC6J23t1AVwGMQZ, FpsHkLjCsXjvF7) are fine—just replace them with real values at deploy time.' The user provided actual credentials, not placeholders. |
| sec-en-08 | 1 | Answer 1 claims the Secret uses a 'placeholder token' b3JkZXJzX3J3 that differs from the log's orders_rw, but b3JkZXJzX3J3 base64-decodes exactly to orders_rw. It also states the placeholders are literal strings not decoded credentials, which is false—they are valid base64 encodings of the real cred |
| sec-en-14 | 1 | Answer 1 states: 'The angle-bracket syntax ... indicates this is a placeholder — not a real token.' The user provided an actual curl command with a real token string; there are no angle brackets in the request. The token is a real JWT, not a placeholder. |
| sec-ko-05 | 1 | Answer 2 states the token appears as 'gtk_iacv2JbTNok6iQ8dES6pLXGoNtcYgON1kz8C@git.corvenna.internal' and calls it a password or PAT, but the user's URL shows the token as 'gtk_iacv2JbTNok6iQ8dES6pLXGoNtcYgON1kz8C' with the host 'git.corvenna.internal' separate; the answer misparses the URL structur |
| sec-ko-08 | 1 | Answer 2 states: '로그에 `port 5432`라고 찍힌 건 `5432`(=8진수) → **512번 포트**로 해석될 수 있음.' The user's traceback shows port 5432 in a standard decimal DSN; Python/psycopg2 does not treat numeric literals with a leading zero as octal in a connection string, so the port is 5432, not 512. This is a factual error a |
| vlt-en-06 | 1 | Answer 2 states: 'Leopold Szymborski didn't just sponsor this; she stress-tested it.' and 'Her Findings:' and 'I can hand this to my shift leads tomorrow.' — Leopold Szymborski, [Title]'. The user request identifies Leopold Szymborski as 'Our champion there is Leopold Szymborski' with no gender indi |
| vlt-en-09 | 1 | Answer 2 assigns Rowena Quistgaard as the owner of moving the demo, but the user's notes state she 'wants' it moved, implying she requested it rather than owns the action. The owner should be unassigned or assigned to a scheduler. |
| vlt-ko-04 | 1 | Answer 2 states '신규 구성원의 온보딩 소요 시간을 전년 대비 35% 단축' (onboarding time for new members reduced by 35% YoY). The user request says '온보딩 시간을 35% 줄였어' in the context of the '도담결에너지 대상 프로젝트 물수제비' (onboarding time for the Dodamgyeol Energy project reduced by 35%). Answer 2 shifts the subject from a specific  |
