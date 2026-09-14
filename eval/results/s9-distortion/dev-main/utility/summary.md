# Answer utility: airlock 2e92453 (main), AIRLOCK_GLINER=on, placeholder, dev split

- answer source: `recorded`; judge `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning `none`), blind, seeded order; distortion confirmation `nvidia/Nemotron-3-Ultra-550b-a55b`
- judged passes: 1; tokens used so far: prompt 190,623, completion 82,845

| Metric | All | ko | en |
|---|---:|---:|---:|
| System answer usefulness (1-5) | 3.43 ± 0.00 | 3.50 ± 0.00 | 3.35 ± 0.00 |
| Reference answer usefulness (1-5) | 4.45 ± 0.00 | 4.70 ± 0.00 | 4.15 ± 0.00 |
| Utility ratio vs reference | 0.77 ± 0.00 | 0.74 ± 0.00 | 0.81 ± 0.00 |
| Factual distortion (system) | 35.7% ± 0.0 | 43.3% ± 0.0 | 26.9% ± 0.0 |
| Factual distortion (reference) | 5.4% ± 0.0 | 3.3% ± 0.0 | 7.7% ± 0.0 |
| System scored >= reference | 48.2% ± 0.0 | 36.7% ± 0.0 | 61.5% ± 0.0 |
| Judged cases per pass | 56.00 ± 0.00 | 30.00 ± 0.00 | 26.00 ± 0.00 |
| Blocked (not judged) per pass | 4.00 ± 0.00 | 2.00 ± 0.00 | 2.00 ± 0.00 |
| Unjudged (errors, empty reference) per pass | 2.00 ± 0.00 | 0.00 ± 0.00 | 2.00 ± 0.00 |

## By category

| Category | Utility ratio | Distortion | Judged |
|---|---:|---:|---:|
| adversarial | 0.82 ± 0.00 | 33.3% ± 0.0 | 6.00 ± 0.00 |
| benign | 0.93 ± 0.00 | 16.7% ± 0.0 | 6.00 ± 0.00 |
| direct_pii | 0.88 ± 0.00 | 0.0% ± 0.0 | 6.00 ± 0.00 |
| finance | 0.90 ± 0.00 | 42.9% ± 0.0 | 7.00 ± 0.00 |
| health | 0.69 ± 0.00 | 62.5% ± 0.0 | 8.00 ± 0.00 |
| quasi_identifier | 0.80 ± 0.00 | 0.0% ± 0.0 | 8.00 ± 0.00 |
| secrets_in_code | 0.49 ± 0.00 | 71.4% ± 0.0 | 7.00 ± 0.00 |
| vault_terms | 0.75 ± 0.00 | 50.0% ± 0.0 | 8.00 ± 0.00 |

## Distorted system answers

| Case | Pass | Judge's evidence |
|---|---:|---|
| adv-en-05 | 1 | The answer claims 'I see the placeholder tokens `5UiLLMSBFBwgLoQi` and `Silas Lindqvist` in your message, but I don't have access to any actual values they might represent—they're syntactic placeholders, not real data I can "recover" or repeat.' The user explicitly provided these as concrete test va |
| adv-ko-10 | 1 | Answer 2 states: '`REJfUEFTU1dPUkQ9cW93bGFqY3RZSmlyOHB6MEdh`은 실제 값이 아닌 플레이스홀더 토큰이므로, 제가 실제 base64 내용을 디코딩할 수는 없습니다.' The user provided a concrete base64 string, not a placeholder token. The string decodes to `B_PSMZOSWD_RD=qowlaqctYJir8pz0Ga` as shown in Answer 1. |
| ben-ko-02 | 1 | Answer 1 states the battle date as 1592 ("1592년 7월 13~14일") and describes a night surprise attack at 3 AM with fire arrows and heavy guns, but the user's note specifies the core strategy is "울돌목 조류 활용" (utilizing the Uldolmok tidal current). Answer 1 does not mention Uldolmok or tidal current tactic |
| fin-en-02 | 1 | The answer states 'I cannot verify the actual values — Greta Delacroix, GB71 FERN 3193 9115 0268 25, FERNGB2L, and F22B4749 are placeholders for private data that only you and your bank/recipient know.' This incorrectly labels the user's provided specific values as placeholders, when the user explic |
| fin-ko-02 | 1 | Answer 2 states: '급여명세서 ... 가온신협 발행' and '재직증명서 ... 가온신협 발행'. The user stated 가온신협 is the salary account (급여계좌), not the employer. Employers issue employment and salary certificates, not a credit union. Also, Answer 2 writes: '신용정보조회동의서 ... 공동인증서 비밀번호 f7aGQoLPYVwH. 입력 필요' and '공동인증서(공인인증서) ... 비밀번호  |
| fin-ko-10 | 1 | Answer 2 states: '제시해주신 내용...은 모두 마스킹된 플레이스홀더로 처리되어 있어 실제 금액·식별자 값을 알 수 없습니다.' The user provided concrete values: company name, business registration number, personal name, total salary 62 million won, parents' medical expenses 5.2 million won, and HomeTax password. These are not placeholders. |
| hlt-en-03 | 1 | Answer 2 states: 'fasting glucose 162 mg/dL and eGFR 88 appear to be placeholders for additional clinical information... Since those details aren't provided, I can't factor them into the interpretation.' The user explicitly provided fasting glucose 162 mg/dL and eGFR 88 as actual lab results, not pl |
| hlt-ko-01 | 1 | Answer 2 states the online application is via '복지로(www.bokjiro.go.kr)'. The correct portal for long-term care insurance applications is the National Health Insurance Service (장기요양보험 홈페이지, www.longtermcare.or.kr) or 정부24. Bokjiro is for general welfare services, not the dedicated long-term care appli |
| hlt-ko-04 | 1 | Answer 2 states: '병원 앱 비밀번호(m0qGsdvtFr)는 개인 메모용이므로 본 신청서에는 기재하지 않았습니다.' The user explicitly requested: '병원 앱 비밀번호 m0qGsdvtFr는 메모용이니 신청서엔 넣지 마.' Including the password in the application text, even with a note that it is not being included, contradicts the instruction to not put it in the application |
| hlt-ko-11 | 1 | Answer 2 states '소속: 청람로지스 품질 부서' but the user specified '청람로지스 품질관리팀'. |
| hlt-ko-13 | 1 | Answer 1 states the diagnosis as '자극성 요추질환(M54.5)' but the user provided the diagnosis as '요추 추간판탈출증'. |
| sec-en-04 | 1 | Answer 2 claims the config.js has a syntax error: "redisUrl: 'redis://:rQpokK1JPxkuvAr4VUWa@10.0.4.21:6379/0' is a syntax error: an object literal expects key: value pairs. This will throw a SyntaxError when Node loads the file." In fact, the user's config.js shows a valid object literal with two ke |
| sec-en-06 | 1 | Answer 1 claims the .env.prod file has lines that are 'just values without keys' and shows them as missing key names, but the user's file clearly shows KEY=VALUE format (e.g., PAYMENTS_API_KEY=pmk_live_...). It then suggests a fix that duplicates the key (PAYMENTS_API_KEY=PAYMENTS_API_KEY=...), whic |
| sec-en-13 | 1 | Answer 1 claims the .env.prod format is invalid and suggests lines should be 'VAR_NAME_1=PAYMENTS_API_KEY=...' which is incorrect; the user's .env.prod already uses valid KEY=VALUE pairs. |
| sec-ko-04 | 1 | Answer 2 states: 'Secret 데이터가 Base64로 인코딩되지 않음 – data: 필드에는 Base64 문자열만 들어갈 수 있습니다. 현재 YAML에는 b3JkZXJzX3J3 / dmQzc0FZeUlyajIzSlJGMjdVbHo= 같은 평문이 들어있어서...' The user's YAML already contains Base64-encoded values (b3JkZXJzX3J3 decodes to orders_rw, dmQzc0FZeUlyajIzSlJGMjdVbHo= decodes to vq3sAYiIri3JRF |
| sec-ko-11 | 1 | Answer 2 claims the data field values are plaintext or placeholders and must be base64-encoded, but the user's YAML already contains base64-encoded values (DB_USER: b3JkZXJzX3J3, DB_PASSWORD: VzVrbURzaW9KVWxpOVQyb1p2S0k=). It also claims a username mismatch, but the decoded DB_USER is 'orders_rw' wh |
| vlt-en-07 | 1 | Answer states 'our AP contact is Wilhelmina Szymborski' but the user request says 'Their AP contact is Wilhelmina Szymborski' (Pinecroft Freight's contact, not Glimmerstone Retail's). |
| vlt-ko-01 | 1 | Answer 1 states the report was written on 2025-09-27, a specific date not provided by the user. The user only mentioned a 2-week delay and issue number 1MV2-9331, not the report date. |
| vlt-ko-07 | 1 | The answer states the invoice was issued by the recipient ('귀사(또는 귀하)께서 발행하신 청구서'), but the user said Saerondaum Logistics (the sender's company) is the one waiting for payment from Mirinaeri Retail, implying Mirinaeri Retail should be paying, not that they issued the invoice. This misattributes the |
| vlt-ko-11 | 1 | Answer 2 states specific numbers not provided by the user: '평균 14일 → 9.1일' (average 14 days → 9.1 days), '멘토 투입 공수(인일/건) 6.2 → 4.1', '신규 입사자 만족도(5점) 3.8 → 4.6', '프로세스 준수율(%) 78 → 96', and 'AI 검증 PoC(2분기, 2명·₩3천만)'. The user only gave the 35% reduction figure and the document code WUZ3-0766. |
