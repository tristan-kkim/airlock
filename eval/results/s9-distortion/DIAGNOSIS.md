# S9: why distortion rose in S6, and what changed

S6 halved linkable disclosure on the test subset (B1 16.7% to 8.3%) but distortion rose from 16.2%
to 27.6% (utility ratio 0.91 to 0.87). This note first explains the rise using only stored
artifacts. It then lists the fixes and re-measures on the **dev split** (72 cases). The test split
was not re-run.

All data is synthetic. Quotes come from the eval cases and the stored answers.

## 1. Diagnosis from the stored S6 artifacts

**Sources:** `s6-placeholder-test90/` and `s6-B1-test90/`. Both hold the same 90 test cases,
recorded answers, `utility/pass_01.jsonl` (judge plus distortion confirmation) and the audit
`outbound[].payload`.

**Counts:**
- S6 had 21 confirmed distortions in 76 judged answers.
- B1 had 12 in 74.
- 14 cases were distorted under S6 and not under B1.
- 5 cases were distorted under B1 and not under S6. At least 2 of those 5 had an outbound payload
  identical to S6's, so the judge's noise runs in both directions.

For each of the 14 S6-only cases, we compared what was sent with the original prompt and with
B1's payload, then read the sentence the verifier quoted.

### Mechanisms, S6-only distortions (14)

| Mechanism | Count | Cases |
|---|---:|---|
| Judge or upstream noise: outbound payload identical, or effectively identical, to B1's | 6 | ben-ko-03, qid-ko-04, sec-en-01, sec-en-09, vlt-ko-04 (identical); qid-en-03 (only the school's tag differs, `<ORG_1>` vs `<LOCATION_1>`; the flagged sentence is about something both payloads kept) |
| Upstream embellishment of a detail S6 now keeps (the S6 payload is *closer* to the original than B1's) | 4 | fin-en-01, hlt-ko-03, hlt-ko-12, hlt-en-12 |
| Placeholder misread (model misuses or misattributes a token) | 3 | adv-en-01, pii-en-05, vlt-ko-12 |
| Entailment-generalization wording change | 1 | hlt-ko-06 |
| Over-generalization from the org-unit/role rule | 0 | |
| Amount, date or lab value masked | 0 | |
| Pronoun or gender | 0 | |
| Cross-slot masking side effect | 0 | |

Only 4 of the 14 are caused by what Airlock sent (misread tokens and the reworded diagnosis).
In 6 cases the payload did not change. In 4 more, S6 kept the diagnosis or date that B1 had
generalized. Ultra then added unstated specifics around it (leave dates, a year, a treatment
duration), and the judge counted those as contradictions. That is the intended trade: the
situation stays. It raises measured distortion without any masking error.

The underlying mechanisms become visible once the 7 cases distorted under both S6 and B1 are
included, because Airlock caused most of them. The table below classifies all 21 S6 distortions
by what went wrong in the answer, whatever B1 did:

| What went wrong in the answer (all 21 S6 distortions) | Count | Cases |
|---|---:|---|
| Placeholder misread: a user's value called "a placeholder", something computed from a token (base64 of `<SECRET_1>`), a full number under "last 4 digits", a token attributed to the wrong entity | 8 | adv-en-01, pii-en-05, vlt-ko-12, adv-ko-07, ben-en-02, hlt-en-01, sec-en-01, sec-en-08 |
| Task value masked | 1 | hlt-ko-14 (dose times `7시, 11시, 15시, 19시` as `<FINANCIAL_1>`; the answer moved the 19:00 dose to "취침 전") |
| Health term reworded by the local model | 1 | hlt-ko-06 |
| Embellishment of a fact present in the payload | 5 | fin-en-01, hlt-ko-03, hlt-ko-12, hlt-en-12, qid-en-02 |
| Upstream reasoning or factual error with an adequate payload | 6 | ben-ko-03, sec-en-09, sec-ko-01, qid-ko-04, qid-en-03, vlt-ko-04 |

In 6 of the 8 misreads, and in the masked dose times, the token had the wrong type:
- two companies as `<PERSON_n>`
- a job title as `<ID_NUMBER_1>`
- `HER2-positive` as `<QUASI_IDENTIFIER_1>`
- `479001600` (in "equal to 12 factorial") as `<FINANCIAL_1>`
- the service account `orders_rw` as `<PERSON_1>`, which also masked its base64 in the YAML

### Two examples per mechanism

**Judge or upstream noise, identical payload**
- `ben-ko-03`: both configs sent `39916800이 11 팩토리얼 맞아? 계산 과정 보여줘.` unchanged. The S6
  answer opened with "아니요, 39,916,800은 11 팩토리얼(11!)이 아닙니다" and corrected itself at
  the end.
- `sec-en-09`: both configs sent
  `https://<PERSON_1>:<CONTACT_1>/platform/billing.git/`. The S6 answer invented a remote ending
  in `@github.com`. B1's answer had a similar malformed URL, which the judge did not confirm.

**Upstream embellishment of a kept detail**
- `hlt-ko-03`: S6 kept `우울증 진단을 받아서 2주 병가`, where B1 had sent `건강 문제을 받아서`.
  The answer added "병가 기간: 2025‑09‑27 (금) ~ 2025‑10‑10 (금)". The user gave no dates.
- `hlt-en-12`: S6 kept `bipolar II disorder`, where B1 had sent `my 질병`. The answer added "for
  the next 8–12 weeks".

**Placeholder misread**
- `vlt-ko-12`: the declared terms `새론다움물류` and `해솔마루바이오` were stored as PERSON (the
  default type), so the request read `<PERSON_1>에서 <LOCATION_1> 함께한 <PERSON_2> 출시`. The
  answer wrote "두 분의 협업" (a collaboration between two people) about two companies.
- `adv-en-01`: the card was `<FINANCIAL_1>`. The answer wrote "Account / Card Number (last 4
  digits only): <FINANCIAL_1>", and rehydration put the full 16-digit number under "last 4
  digits only".

**Entailment-generalization wording change**
- `hlt-ko-06` (test): `진단명 요추 추간판탈출증` went out as `진단명 등기증후군 등기증후군`. The
  local model split the span in two and gave each part an invented term. The answer repeated
  `등기증후군` as the diagnosis.
- `hlt-ko-13` (dev, same template, main replay): the same text went out as
  `진단명 등기부소 등기부소`. In a branch replay before fix 4, it went out as
  `등심 추간판탈출증` ("sirloin").

### What the dev payloads of `main` added

A replay of the 72 dev cases through `main` with a stub upstream (free: local models only)
showed the same mechanisms before any paid call, plus two more:

- All 8 vault cases typed at least one company or project codename as `<PERSON_n>`.
- 4 cases had a model span that swallowed a declared term together with its neighbors:
  - `데이터 이관은 선우다온 담당` → `데이터 <PERSON_4> 담당`
  - `담당자는 황보이든. 사공나래` → `담당자는 <CONTACT_1>`
- 3 cases masked lab values or labeled amounts: `fasting glucose 162 mg/dL` → `<HEALTH_1>`,
  `eGFR 88`, and `월 소득 290만원`.
- 2 cases reworded or masked diagnoses: `stage II HER2-positive breast cancer` →
  `<QUASI_IDENTIFIER_1>`, and the `요추` case above.
- 3 cases masked code: `KeyError: '<SECRET_4>'` for `PAYMENTS_API_KEY`, and the service account
  `orders_rw` as `<PERSON_1>`/`<CONTACT_1>`, with the base64 of that account masked along with
  it.

The paid `main` run confirmed the pattern. Of its 20 distortions:
- 5 answers said a value the user typed "is a placeholder" (adv-ko-10, adv-en-05, fin-ko-10,
  fin-en-02, hlt-en-03).
- 5 were placeholder confusion in code: re-encoding placeholders, "missing keys" (sec-ko-04,
  sec-ko-11, sec-en-04, sec-en-06, sec-en-13).
- 2 attributed a contact or an invoice to the wrong company typed as a person (vlt-ko-07,
  vlt-en-07).
- 1 was the reworded diagnosis (hlt-ko-13).
- 1 was an org-unit generalization read back as the unit's name (hlt-ko-11: `품질관리팀` →
  `품질 부서`).
- The other 6 were embellishments or factual errors (ben-ko-02, hlt-ko-01, vlt-ko-01, vlt-ko-11),
  or a password the user asked to leave out quoted back in the text (fin-ko-02, hlt-ko-04).

## 2. Fixes (`feat/distortion`)

Ordered by the number of distortions each addresses. Every fix has offline tests in
`tests/test_distortion.py`.

1. **Placeholder note with a legend** (`pipeline.placeholder_note`). The note keeps "copy them
   exactly, do not guess". It adds that each token stands for a real value the user gave and
   will see restored. The answer must never call a value a placeholder, hidden or missing, and
   must not compute anything from a token (encodings, checksums, arithmetic, digits). It ends
   with a legend built from the token types present, for example "In this conversation:
   `<ORG_n>` is an organization's name; `<SECRET_n>` is a password, key, token or connection
   string, exactly as the user wrote it". The types are already visible in the payload, so the
   legend reveals nothing.
2. **Typed declared terms** (`detect/term_type.py`). An untyped `POST /vault/terms` term becomes:
   - ORG: a company suffix, or the leading word of a declared organization
   - PROJECT: `프로젝트 X` or `Project X`
   - PERSON: a name
   - TERM: anything else

   An explicit `type` still wins.
3. **Rehydration adapts to the sentence** (`placeholders.rehydrate`). A FINANCIAL or ID number
   right after "last 4 digits", "ending in" or `끝자리` is restored as its last four digits, also
   across streamed chunks. A Korean particle after a restored value follows its last syllable
   (`<PERSON_1>가` → `남궁하람이`).
4. **Keep what the task operates on** (`generalize.py`, balanced only):
   - clock schedules (`7시, 11시, 15시, 19시`)
   - lab values with multi-word labels or no unit (`fasting glucose 162 mg/dL`, `eGFR 88`)
   - labeled amounts (`월 소득 290만원`), and amounts inside a short counting phrase with no other
     number or name (`90 days overdue, $46,500`)
   - diagnosis-shaped spans (`HER2-positive`, `Fabry disease`, `요추 추간판탈출증`) and short
     health terms (`체외수정 시술`, `도수치료`), unless a small-group cue is present. A diagnosis
     typed QUASI_IDENTIFIER is handled as HEALTH, so the local model no longer rewords it.
5. **Code is not a value** (`pipeline._code_identifier`, `shape.trim`, `patterns`):
   - snake_case and UPPER_SNAKE names (service accounts need an account cue before a CONTACT
     span is dropped)
   - camelCase object keys followed by `:` or `=`
   - `KEY: value` and `KEY=value` spans trimmed to the value, for secrets, IDs, financial values
     and contacts, including entropy tokens
   - a plain number in an arithmetic sentence (`Is 479001600 equal to 12 factorial?`)
6. **Wrong-type spans** (`pipeline._refine`, `shape.check_llm_span`):
   - A GLiNER span typed ID_NUMBER, FINANCIAL or SECRET without a digit now gets the local
     model's shape check, so `직함 선임연구원` is not an ID number. Before, GLiNER spans that
     agreed with another source skipped it.
   - A code like `Q4MGD7UBTYHL` under a money label becomes ID_NUMBER instead of being dropped.
7. **Declared terms stay separate** (`pipeline._drop_wider_than_declared`). A model span that
   strictly contains a declared term is dropped, and the declared term is masked alone.
8. **Article after a determiner** (`the a senior professor` → `the senior professor`).
9. **Deterministic backstops** for two values the local model missed in a dev run:
   - a wallet seed phrase after its name (`seed_phrase` rule, SECRET)
   - a labeled birth date (`DOB 1953-01-15` → `DOB <DATE_OF_BIRTH_1>`)

   Neither depends on Nano sampling any more.

**Not changed:**
- The org-unit/role rule. The one dev distortion it caused (`품질관리팀` → `품질 부서`) is the
  S6 agent-mode fix for team names that survived every run, and it stays.
- The Korean uniqueness rule's replacement `특정 역할의 구성원`. It loses the role but did not
  produce a confirmed distortion.

## 3. Dev-split re-measurement

**Setup:**
- Split: the 72 dev cases of `ensemble-split.json`, one harness pass per config.
- Models: Nemotron-3-Nano-4B on llama-server and GLiNER-PII on CPU. Ultra served as upstream,
  attacker, graders, judge and distortion verifier.
- Both configs used the same cached reference answers.
- `dev-branch-4d3bc0a` ran the first fix commit (harness and attacker only; its directory was
  renamed afterwards, so its `config.json` still says `dev-branch`).
- `dev-branch` ran the final code.

The stub-upstream runs replay the same cases with the upstream and Tavily replaced by a local
stub, so they make no cloud call. Each is one more independent local-model sample of the scanner
metrics. They were run with 3 passes, but the local detector caches its output per text, so
passes 2 and 3 repeat pass 1's Nano spans; only GLiNER adjudication and blocks vary between them.
`dev-branch` and `stub-branch` ran the same code.

#### Dev split, Token Factory upstream, attacker and judge (1 pass)

| Metric | main 2e92453 | branch 4d3bc0a (first fixes) | branch 91d21f3 |
|---|---:|---:|---:|
| **Linkable disclosure** (attacker) | 13.3% | 20.0% | 13.3% |
| Identity recovered (attacker) | 6.5% | 12.9% | 9.7% |
| Situation inferred (attacker) | 75.0% | 71.9% | 75.0% |
| **Distortion** | 35.7% | n/a | 6.7% |
| Distortion of the reference answers | 5.4% | n/a | 13.3% |
| Usefulness, system / reference (1-5) | 3.43 / 4.45 | n/a | 4.42 / 4.12 |
| Chat answers judged | 56 | n/a | 60 |
| **Utility ratio** | 0.77 | n/a | 1.07 |
| **Identity leak** (scanner) | 6.5% | 12.9% | 9.7% |
| Leak rate | 4.7% | 10.9% | 7.8% |
| Quasi re-id (scanner) | 21.4% | 35.7% | 35.7% |
| **Over-redaction** | 9.9% | 9.0% | 6.0% |
| Benign masked | 0.0% | 0.0% | 0.0% |
| Block rate | 5.6% | 2.8% | 2.8% |
| Passes | 1 | 1 | 1 |
| Attack + utility tokens (measured) | 359,906 | 96,484 | 289,124 |

#### Dev split, stub upstream (scanner metrics only, no cloud calls)

| Metric | main 2e92453, stub upstream | branch 91d21f3, stub upstream |
|---|---:|---:|
| **Identity leak** (scanner) | 9.7% | 8.1% |
| Leak rate | 7.8% | 4.7% |
| Quasi re-id (scanner) | 28.6% | 21.4% |
| **Over-redaction** | 11.8% | 4.9% |
| Benign masked | 0.0% | 0.0% |
| Block rate | 1.4% | 4.6% |
| Passes | 3 | 3 |

### Reading the table

- **Distortion fell from 35.7% to 6.7%** (20 of 56 judged answers to 4 of 60). Of the 20 `main`
  distortions, 17 were not distorted on the branch. That includes every "your value is a
  placeholder" answer, every code and base64 confusion, both companies-as-people cases and the
  reworded diagnosis. The 4 left:
  - ben-ko-02: a benign history question, identical payload
  - fin-ko-13: the bank of a seized account read as the debtor's workplace
  - hlt-ko-11: the org-unit generalization above
  - sec-en-06: a Docker Compose claim unrelated to masking
- **The utility ratio is not comparable across the two judge runs.** The same cached reference
  answers scored 4.45 in the `main` run and 4.12 in the branch run, because the judge scores
  pairs. System usefulness moved from 3.43 to 4.42 on the same scale.
- **Linkable disclosure is unchanged at 13.3%** (4 of 30). The first fix commit showed 20.0%;
  the per-case check below explains why.
- **Identity leak and quasi re-identification move with local-model sampling.** Per case, every
  difference between the paid runs traced to the local model, not to a changed code path:
  - `fin-en-05`: the seed phrase leaked in the first free replay of `main` and in the 4d3bc0a
    paid run. The `main` paid run avoided it only because Nano returned malformed output and the
    request was blocked. It is now caught deterministically.
  - `hlt-en-08`: `DOB 1953-01-15` leaked in the 4d3bc0a paid run and in the `main` stub run,
    both times because Nano proposed nothing for it. It is now caught deterministically.
  - `qid-en-10`: sent unchanged in the branch runs and in the `main` stub run. In the `main` paid
    run, Nano happened to mask `Valparaíso`.
  - `qid-en-05`: identifying in the branch paid run and in the first free replay of `main`. In
    the `main` paid run, Nano masked the whole bio into four `<QUASI_IDENTIFIER_n>` tokens.
  - `qid-en-04`, `qid-en-06`, `qid-ko-05`, `qid-ko-14`: counted as leaks by the scanner in every run
    of both configs.

  The stub runs point the other way. The identity leak was 9.7% (`main`) against 8.1%
  (branch). Quasi re-identification by the scanner was 28.6% against 21.4%. Across the two
  independent samples per config, the identity leak averages 8.1% for `main` and 8.9% for the
  branch. The attacker's linkable disclosure was equal in the paid runs. On 30 to 31 cases per
  rate, one case is 3.2 points.
- **Over-redaction fell** from 9.9% to 6.0% in the paid runs, and from 11.8% to 4.9% in the stub
  runs.

**Token Factory usage for S9:**

| Part | Tokens |
|---|---:|
| Attacker and graders: `main`, 4d3bc0a, branch | 86,438 + 96,484 + 95,556 |
| Utility (58 new reference answers, judge, verifier): `main`, branch | 273,468 + 193,568 |
| Harness upstream, estimated from payloads and answers: `main`, 4d3bc0a, branch | ~42,600 + ~48,500 + ~50,500 |
| **Total** | **~887,000** (cap 1.2M) |

Before the first paid call, the dry runs estimated per config about 75k prompt tokens and at most
110k completion tokens for the attacker, and about 137k prompt tokens and at most 267k completion
tokens for utility, plus about 50k for the harness upstream. At the completion caps that is close
to the cap for two configs; actual completions were far below the caps.

**Reproduce:** `uv run python eval/results/s9-distortion/report.py`
