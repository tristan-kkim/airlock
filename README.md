# Airlock

**A local privacy airlock between your apps and cloud AI.**

Point any OpenAI-compatible app at `http://127.0.0.1:8787/v1`. Before a request leaves your machine, deterministic detectors and a small local model find what is private, the vault swaps it for placeholders, and a deterministic gate checks the exact outbound bytes. The large cloud model does the reasoning on the sanitized text. The answer is restored locally, and every request leaves an audit record of exactly what the cloud saw.

> The small local model does not solve the task. It only decides what is private. The big cloud model does the reasoning.

## Try the demo

**Hosted demo: TBD** (goes live in October 2026 and stays free and open until judging ends on 2026-12-15).

Click any of the five fictional scenarios (chat, private web search, research agent; English and Korean) to see what you typed, what the cloud saw, and the answer. The hosted demo differs from real use in a few ways:

- **Detection runs on the demo server, not your machine.** The hosted demo uses NVIDIA Nemotron-3-Nano-30B-A3B on Nebius Token Factory as the detector. A banner says so, and says not to paste real personal data. For real privacy, run Airlock locally ([Quickstart](#quickstart)), where the detector never leaves your device.
- **Every visitor gets a separate in-memory session.** The vault and audit log are never written to disk and expire after 30 minutes idle.
- **Usage is limited:** 20 requests per 10 minutes, 4,000 characters per input, and a daily budget. When the budget is used up, scenarios show a clearly labeled *recorded run* of the same input.

Operators: see [`deploy/DEMO_RUNBOOK.md`](deploy/DEMO_RUNBOOK.md) (`AIRLOCK_DEMO=1`, `Dockerfile`, Nebius Serverless and Fly.io configs).

## Why

People and companies avoid cloud AI mainly because of leakage: names, customer data, health details, credentials pasted into a prompt. Local-only models avoid the leak, but they are much weaker than frontier models. Airlock splits the job:

- **On device:** regex and entropy detectors mask secrets and identifiers first. NVIDIA Nemotron-3-Nano-4B then proposes semantic spans (names, organizations, health details, quasi-identifiers) on the partially masked text, and deterministic Korean rules back it up where the small model is weak. Optionally, you confirm the redactions before anything is sent.
- **In the cloud:** Nemotron 3 Ultra on Nebius Token Factory answers the sanitized request.
- **Between them:** a gate written in plain code, not a prompt. A model never gets to say "this is fine."

It works with tools you already use (scripts, notebooks, editors, agents) by changing one `base_url`.

## Measured results

Final measurement ([`eval/results/FINAL.md`](eval/results/FINAL.md), full tables in [`eval/results/COMPARISON.md`](eval/results/COMPARISON.md)): all 243 synthetic cases (122 Korean, 121 English), 3 passes, each system alone on an M3 Pro, GLiNER ensemble on, attacker and judges on Nemotron 3 Ultra. **Linkable disclosure** is the share of the 98 situation-sensitive cases where an attacker reading only the outbound payloads recovers an identity item and infers the private situation.

- **Placeholder row:** mean ± sd over 3 independent passes. The server was reset before every pass, and the per-pass detect time and payload check confirm the passes were independent.
- **Baselines:** outputs were identical across passes and scored once.
- **Surrogate row (†):** from an earlier run whose passes were not independent. That run reset the server only before pass 1, so later passes reused cached detections. Its numbers are means with no measured spread.

| System | **Linkable disclosure** | Identity leak | Usefulness 1-5 | Utility ratio | Distortion | Over-redaction | Benign masked |
|---|---:|---:|---:|---:|---:|---:|---:|
| raw (pass-through) | 84.7% | 98.5% | 4.52 | 1.05 | 7.7% | 0.0% | 0.0% |
| regex only | 79.6% | 92.7% | 3.91 | 0.87 | 13.9% | 0.4% | 7.4% |
| Presidio + ko/en spaCy | 53.1% | 76.7% | 3.01 | 0.66 | 33.7% | 16.7% | 66.7% |
| NVIDIA GLiNER-PII alone | 9.2% | 18.9% | 2.69 | 0.59 | 24.5% | 14.1% | 59.3% |
| **Airlock, placeholders (default)** | **13.9% ± 0.6** | 8.6% ± 0.7 | 4.16 ± 0.03 | 0.95 ± 0.01 | 15.2% ± 1.4 | 7.1% ± 1.3 | 11.1% |
| Airlock, surrogates † | 12.6% | 8.3% | 4.08 | 0.94 | 19.4% | 6.4% | 11.1% |

- **Linkable disclosure falls from 84.7% to 13.9%, and usefulness is mostly kept.** Airlock with placeholders keeps a utility ratio of 0.95. Its distortion is 15.2%, against 7.7% for the reference answers judged in the same run.
- **Every remaining linkable case is a quasi-identifier prompt.** There were 0 in finance, health and intent search. What links is a combination of attributes that each look harmless and that the answer often needs: a rank plus a cohort, a role plus a small place, a rare personal fact.
- **GLiNER-PII alone links less (9.2%), at a large utility cost.** It masks 59.3% of benign prompts and scores 2.69 for usefulness.
- **Placeholders stay the default.** Surrogates link 1.3 points less but distort 4.2 points more, and they were judged in a different run with a different reference distortion.
- **Korean costs more.** Identity leak is 10.6% in Korean vs 6.5% in English, the utility ratio 0.86 vs 1.04, and over-redaction 10.0% vs 4.3%. All benign masks are Korean, and two benign Korean searches are blocked.
- **Latency:** local overhead p50 4.0 s / p95 8.8 s per request, stable across passes. Local detection alone is p50 3.4 s.

These are lower bounds from one attacker on synthetic data, and the judge's noise is about ±0.05 in utility ratio and ±3 points in distortion. The subset and dev-split tables further down are earlier one-pass measurements kept for their diagnoses.

## Architecture

```mermaid
flowchart LR
    App["Any app<br/>(OpenAI SDK, base_url = localhost)"] -->|request| Detect

    subgraph Local["Your machine"]
        Detect["Detect<br/>1. regex / entropy / vault terms<br/>2. mask them, then Nemotron-3-Nano-4B<br/>3. Korean rules + span verification"]
        Review{{"Review (optional)<br/>HTTP 409 → POST /review/id"}}
        Vault[("Vault<br/>original ↔ #60;PERSON_1#62;<br/>SQLite, local only")]
        Gate{"Deterministic gate<br/>originals, declared terms,<br/>canaries, secret patterns"}
        Rehydrate["Rehydrate<br/>#60;PERSON_1#62; → original"]
        Audit[("Audit log<br/>exact outbound payload,<br/>hashes only")]
        Detect --> Review --> Vault --> Gate
        Gate -. record .-> Audit
    end

    Gate -->|"BLOCK: HTTP 422"| App
    Gate -->|"ALLOW: sanitized JSON"| TF["Nebius Token Factory<br/>Nemotron 3 Ultra"]
    TF -->|"answer with placeholders"| Rehydrate
    Rehydrate -->|"answer with originals"| App

    subgraph Search["Private search"]
        Rewrite["Local rewrite<br/>(no identity, no intent)"] --> Gate2{"Gate"} --> Tavily["Tavily /search"]
        Tavily --> Rerank["Local re-rank<br/>against private context"]
    end
```

Request flow for `POST /v1/chat/completions`:

1. **Detect.** Every text slot (message content, text parts, tool-call arguments) goes through these steps, in order:
   1. **Deterministic spans first:** regex and entropy detectors, exact and variant matching against the vault (your declared terms and this conversation's earlier originals), and base64 blobs that hide a known value. The regexes and the Korean name rules also run on a normalized copy of the text ([`obfuscation.py`](airlock/detect/obfuscation.py)), so a value nobody declared is still masked when it is written apart or encoded: `정.민.준`, `김 민 지`, separated jamo, `공일공 공구일일 …`, Hanja or full-width digits, a card number split over two lines, Cyrillic look-alike letters.
   2. **Mask before the model:** those spans are replaced by local tokens (`<SECRET_1>`) in the copy the local model reads. The model never receives raw secrets, cannot echo them, and has less to copy.
   3. **Korean semantic rules** ([`airlock/detect/ko_rules.py`](airlock/detect/ko_rules.py)) propose spans the small model often misses in Korean: uniqueness cues (`유일한 여성 부사장`, `the only male nurse`), health terms in a sentence about a person (`공황장애 진단을 받았`), company and institution suffixes (`새론다움물류`, `㈜누리소프트`, `한빛병원`), names before titles (`박지훈 고객`, `문태오 대리`), and names after a label or in a self-introduction (`예금주 강채원`, `박하은입니다`). Each rule has negative lists (public figures, famous companies, generic words like `유일한 방법`, `초등학교`, `국회의원`) and never fires inside a placeholder.
   4. **Local model:** Nemotron-3-Nano-4B reads the masked draft with a JSON-schema-constrained output (temperature 0.6, top_p 0.95, thinking off, output cap sized to the input). The prompt lives in [`airlock/prompts/detector.md`](airlock/prompts/detector.md).
   5. **Verify:** a model span whose text does not occur in the original (after the vault's normalization) is discarded, so hallucinated IDs never become redactions. Discard counts are recorded in the audit record.
   6. **Refine the whole request at once.** All slots of a request, agent turn or search go through one entry point (`Sanitizer.detect_many`), so the GLiNER ensemble and these steps apply on every path:
      - spans lose honorifics, titles and ID labels (`정다은님` → `정다은`, `invoice 9UUT-9586` → `9UUT-9586`);
      - a local-model span must have the shape of its type ([`shape.py`](airlock/detect/shape.py)): a phone number labeled as an organization becomes CONTACT, `ci-runner` as ORG or `체외수정 시술` as SECRET is dropped, a job title labeled as an ID number is dropped even when GLiNER agreed, a Hangul PERSON span must have a name's shape ([`ko_rules.plausible_name`](airlock/detect/ko_rules.py): a surname-initial syllable, a compound surname at four syllables, no noun-final syllable such as `증`, `법` or `사`, so `실업급여`, `고용보험` and `근로기준법` are never people), and code is never a value (`orders_rw`, `PAYMENTS_API_KEY`, the key of `redisUrl: '...'`, a number the request computes with such as `479001600` in "equal to 12 factorial");
      - a model span that swallows a declared term and the words around it is dropped, so the term is masked alone (`데이터 이관은 <PERSON_2> 담당`, not `데이터 <PERSON_2> 담당`);
      - at `balanced`, what the task operates on is kept: amounts (also inside a short phrase, `90 days overdue, $46,500`), lab values (`fasting glucose 162 mg/dL`, `eGFR 88`), dosages, durations, clock schedules (`7시, 11시, 15시, 19시`), dates that are not a birth date, and diagnoses and short health terms (`HER2-positive`, `요추 추간판탈출증`, `체외수정 시술`) unless a small-group cue ("the only", "3학년 2반 쌍둥이") is present. A diagnosis the model labeled as a quasi-identifier is handled as a health term, not reworded;
      - a labeled birth date (`DOB 1953-01-15`, `생년월일 1990년 3월 2일`) and a wallet seed phrase are caught deterministically, without the local model;
      - employer + org unit + role are linked ([`org_rules.py`](airlock/detect/org_rules.py)): `동해누리정밀(주) 품질보증팀 박성훈 팀장` → `<ORG_1> 품질 부서 <PERSON_1> 관리자`, `the Payments Platform team at Halcyon Freight Systems` → `the engineering team at <ORG_1>`;
      - combinations of quasi-identifiers are scored like k-anonymity ([`quasi.py`](airlock/detect/quasi.py)). Attributes fall in seven categories: place, named institution, cohort, rare fact, role, age and family structure. When the attributes still in the text reach k (3 at `balanced`, 2 at `strict`), the most identifying ones are coarsened until the score is below k: a small place to its region (`경북 새내군` → `경북의 한 군 지역`), a cohort year to its decade (`2022년 행정고시` → `2020년대 행정고시`), a specialty to its profession (`pediatric cardiologist` → `physician`), a rank to a band (`수석` → `상위권`). An attribute the question itself is about is kept, and only a message about a person (first person, a relative, a self-description or a request for anonymity) is scored;
      - a model span that is a well-known public figure (`장영실`) or a job title labeled as an organization (`직함 선임연구원`) is dropped, and a GLiNER-only organization or place in a request about nobody (`KTX 서울 부산 소요시간`) is the topic, not a private value;
      - generalizations must be entailed by the original ([`generalize.py`](airlock/generalize.py)): ages and birth decades are computed from the text and today's date and phrased for their slot (`I'm 34` → `I'm in my 30s`, `34살입니다` → `30대입니다`, `born in 1992` → `born in the 1990s`, `a 34-year-old` → `a 30-something`), places become a containing region (`성남시` → `경기도의 한 도시`, never `서울`), a health generalization is checked by Nano ("does X imply Y?") or falls back to its category, and the replacement stays in the language of the text;
      - a value detected in any slot is masked in every slot of the request before the gate.
2. **Resolve and substitute.** Overlapping spans are resolved with a longest-span-wins rule. `AIRLOCK_SUBSTITUTION` decides what replaces an identity value:
   - `placeholder`: a typed token (`<PERSON_1>`, `<ORG_1>`, ...). A declared term without a type gets one from its surface: a company suffix is `ORG`, `프로젝트 X` / `Project X` is `PROJECT`, the leading word of a declared organization is `ORG`, a name is `PERSON`, anything else `TERM`. Before this, every declared term was `PERSON`, and the cloud model wrote about "two people" behind two companies.
   - `surrogate`: a realistic, format-preserving fake value (see *Surrogates* below).

   Secrets and credentials always get `<SECRET_1>`, and quasi-identifiers get a generalization ("40대", "a plant in Oklahoma"). A generalization is rejected, and the span masked instead, when it still contains the original, a digit run or rare word from it, a proper noun, text in another language, or junk. Within a conversation or agent run, the same original always maps to the same placeholder or surrogate.
3. **Gate.** The final outbound JSON is walked string by string, keys and numbers included. If any vault original, declared term, canary, or high-confidence secret or ID pattern is still present, or if the request contains content Airlock cannot inspect (images), the request is blocked with HTTP 422. "Present" covers variants, not only exact text:
   - letter case, full-width characters, Cyrillic or Greek look-alike letters, separated Hangul jamo (`ㄱㅣㅁ`), and zero-width or other invisible format characters
   - inserted spaces or punctuation (`새론 다움물류` matches `새론다움물류`)
   - numbers written with separators, spaced-out digits, or Korean, Hanja or English numerals (`공일공 이삼사오 …`); high-confidence patterns such as a resident registration number are also checked in that normalized form
   - values hidden inside JSON strings (tool-call arguments), percent-encoding, or base64/base64url, up to two layers deep

   The vault matcher uses the same normalized views, so a variant is usually masked rather than blocked. If the local model is down, times out, or malfunctions (prose instead of JSON, invalid JSON, output cut off at the token cap, a repetition loop), the request is also blocked after at most one resample of a short malformed answer. Airlock fails closed.
4. **Upstream.** The exact bytes that passed the gate go to Token Factory. When placeholders are present, a system note says that tokens like `<PERSON_1>` are placeholders to copy exactly, that each stands for a real value the user gave and will see restored (so the answer must never call a value a placeholder or missing), that nothing may be computed from a token (encodings, checksums, arithmetic), and what kind of value each token type in the request is (`<ORG_n> is an organization's name; <SECRET_n> is a password, key, token or connection string, exactly as the user wrote it`). The legend is built from the placeholder types already in the payload, so it adds no private information. Without it, answers told users that the number they typed "is a placeholder" and base64-encoded `<SECRET_1>` into a "fixed" config. If the primary model returns 5xx or reports itself unavailable, Airlock retries once on the fallback model. That attempt is also audited.
5. **Rehydrate.** Placeholders and surrogates in the answer, including tool-call arguments and streamed deltas, are mapped back to the originals on your machine. Matching is lenient about what a model may do to the brackets (`< PERSON_1 >`, `&lt;PERSON_1&gt;`, `[[PERSON_1]]`, `⟨PERSON_1⟩`, full-width brackets, lower case) but only replaces keys that exist in the conversation, so `List<T>` or HTML is left alone. A card or account number right after "last 4 digits", "ending in" or `끝자리` is restored as its last four digits, and a Korean particle after a restored value follows its last syllable (`<PERSON_1>가` → `남궁하람이`). The older `[[PERSON_1]]` syntax is still accepted in client histories and old vault files.
6. **Audit.** One record per request stores the outbound payloads verbatim, detections as SHA-256 hashes, the gate decision, and timings.

### Optional: NVIDIA GLiNER-PII ensemble

`AIRLOCK_GLINER=on` adds [`nvidia/gliner-PII`](https://huggingface.co/nvidia/gliner-PII) (570M span NER, the NeMo Guardrails PII backend) as a second local proposer. Install it with `uv sync --extra gliner` and point `AIRLOCK_GLINER_MODEL` at the downloaded weights.

```mermaid
flowchart LR
    T["Text slots of one request"] --> D["regex / entropy / vault<br/>→ mask → Nano-4B spans<br/>+ Korean rules"]
    T --> G["GLiNER-PII<br/>34 labels, threshold 0.4<br/>(runs in parallel, CPU)"]
    D --> A{"Agreement?<br/>overlaps a span from<br/>another source"}
    G --> A
    A -->|yes| Accept["accept"]
    A -->|"GLiNER only"| F{"Type consistency<br/>SECRET: entropy/pattern<br/>phone/ID/account: digit or code shape<br/>PERSON: surname + 3-4 Hangul syllables<br/>or capitalized Latin words<br/>age/date/money text: drop<br/>city, birth date: agreement only"}
    F -->|fails| Drop["drop (counted)"]
    F -->|passes| J{"Nano-4B adjudication<br/>one batched call per request<br/>JSON schema, temp 0, thinking off<br/>'private to the user here?'"}
    J -->|yes| Accept
    J -->|no| Drop
    Accept --> R["overlap resolution → vault → gate"]
```

Why three steps instead of trusting GLiNER:

- **GLiNER has the recall.** Alone on the 243-case eval it leaks 19.0% of cases, against 76.9% for Presidio and 94.0% for regex ([`eval/results/COMPARISON.md`](eval/results/COMPARISON.md)).
- **It over-masks, most of all in Korean.** It masks 59.3% of benign prompts and loses 14.1% of the strings answers need. It was trained on English only: in `qid-ko-01` the age `마흔다섯` became PASSWORD and the company RELIGIOUS_BELIEF. Airlock drops the labels that drove that (religion, gender, occupation, age, dates, URLs, IPs), and Nano and the Korean rules handle quasi-identifiers with generalizations instead.
- **Agreement is free precision.** When regex, the rules or Nano already flagged an overlapping span, the second opinion costs nothing and can only widen a mask. A GLiNER span next to a generalization never overrides it.
- **Type consistency is deterministic and explainable.** A span labeled PASSWORD with no Latin letters and digits, or a phone number with no digits, is a mislabel no matter the score. Korean particles the tokenizer attached (`조유나입니다`, `F8YAXXGS이고`) are trimmed first, and a Korean name under a wrong label (`독고새론` as password) is kept as PERSON.
- **Local adjudication settles context.** Whether `Tucson` or `Corvenna Systems` is private depends on the sentence. Only GLiNER-only spans that passed the shape check are asked, all in one call with `<TYPE>` tokens in place of pattern values, so requests without such candidates pay nothing. A malformed answer blocks the request, like any local detector failure.

If the package or weights are missing while `AIRLOCK_GLINER=on`, `airlock serve` refuses to start and `airlock doctor` reports it; nothing fails per request. Per-request counters go to `meta.detector` (`gliner_spans`, `gliner_agreed`, `gliner_rejected_mislabel`, `gliner_rejected_shape`, `gliner_remapped`, `gliner_candidates`, `adjudication_calls`, `adjudicated_yes`, `adjudicated_no`, `gliner_ms`, `adjudication_ms`). With GLiNER off these keys are absent and behavior is unchanged.

**Measured** ([`eval/results/ENSEMBLE.md`](eval/results/ENSEMBLE.md)), 1 pass per config on the 171-case test split. Thresholds, shape rules, the adjudication prompt and the variant were chosen on a separate 72-case dev split.

| Test split (70%) | Leak | Canary leak | Quasi re-id | Benign masked | Over-block benign | Over-redaction | Leak ko / en |
|---|---:|---:|---:|---:|---:|---:|---:|
| GLiNER off (HEAD detector) | 26.3% | 14.1% | 38.9% | 0.0% | 0.0% | 14.1% | 26.0% / 26.7% |
| GLiNER ensemble (default) | 11.2% | 1.0% | 27.8% | 21.1% | 10.5% | 15.5% | 13.0% / 9.3% |

Over all 243 cases, an LLM attacker reading only the outbound payloads recovers 1.0% of planted values with the ensemble, against 9.9% without it. The cost is real: 4 of 19 benign test prompts get a mask, and 2 benign searches are blocked because the local rewrite kept an organization GLiNER flagged. GLiNER adds p50 457 ms / p95 635 ms of CPU inference, run in parallel with Nano. The adjudication call is needed in 28% of chat requests and then takes p50 1.7 s / p95 2.2 s. Local latency across runs was contaminated by other models sharing the laptop.

### Detector round two (S6): measured

What changed is described in *Architecture* (step 1.6, step 2) and *Surrogates*. Rules and thresholds were tuned on the 72-case dev split only. The one-pass numbers on the 171-case test split and its 90-case attack subset are in [`eval/results/s6-split/REPORT.md`](eval/results/s6-split/REPORT.md). The 3-pass full-dataset measurement in [`eval/results/FINAL.md`](eval/results/FINAL.md) supersedes them, including the placeholder vs surrogate comparison.

What that round found:

- **Linkable disclosure and over-redaction roughly halved against B1**, the ensemble before the round. Linking the employer, unit and role removes the combination that linked most, and amounts, lab values and common diagnoses now stay in the prompt. More situations are therefore visible to the cloud, as intended: the cloud may learn the problem, not who has it.
- **Distortion rose.** The distorted answers included invented dates and wrong arithmetic in both configs, and a masked role read back as an ID number. In surrogate mode, answers were also built on the surrogate itself:
  - a card "ending in" the surrogate's digits
  - a surrogate name transliterated into Korean in a translation task
  - a pronoun that did not match the surrogate's gender
  - a clinic written without its suffix

  Those three surrogate failure kinds were fixed afterwards: card surrogates keep the last four digits, English first names are gender-neutral, and an organization's stem alone is rehydrated. The distortion diagnosis and fixes are in *Answer distortion (S9)*.
- **Benign masking is unchanged**: all four benign masks on the test split come from GLiNER-only spans the adjudicator accepted (`KTX` and `경주 불국사` as organizations in two search queries, which the gate then blocked, `장영실이` as a person, the number 479001600 in a factorial question as an account number).

### Answer distortion (S9): diagnosed and reduced on dev

[`eval/results/s9-distortion/DIAGNOSIS.md`](eval/results/s9-distortion/DIAGNOSIS.md) reads every S6 answer that was distorted on the test subset against what was sent.

- **Noise and embellishment, 10 of 14.** Of the 14 answers distorted under S6 but not B1, 6 had a payload identical to B1's. In 4 more, S6 had kept a diagnosis or date that B1 generalized, and Ultra embellished around it.
- **Caused by masking.** Across all 21 S6 distortions, the masking-related ones were mostly placeholder misreads, usually caused by a wrong token type:
  - a user's number called "a placeholder"
  - base64 of `<SECRET_1>` in a "fixed" config
  - two companies declared without a type, sent as `<PERSON_n>`, and written up as "두 분"
  - a job title sent as `<ID_NUMBER_1>`
  - a full card number restored under "last 4 digits"

The fixes are described in *Architecture*: the placeholder legend, typed declared terms, sentence-aware rehydration, kept schedules, lab values, amounts and health terms, code that is never a value, and deterministic birth dates and seed phrases.

On the 72 dev cases, one pass each with Ultra as upstream, attacker and judge:

| Dev split | main 2e92453 | feat/distortion 91d21f3 |
|---|---:|---:|
| Distortion | 35.7% | **6.7%** |
| Usefulness, system / reference (1-5) | 3.43 / 4.45 | 4.42 / 4.12 |
| Linkable disclosure | 13.3% | 13.3% |
| Over-redaction | 9.9% | 6.0% |
| Identity leak, this run / stub replay | 6.5% / 9.7% | 9.7% / 8.1% |

The utility ratio is not shown: the same cached reference answers scored 4.45 in one judge run and 4.12 in the other, because the judge scores answer pairs. Identity-leak differences trace case by case to the local model's sampling, not to changed code. The full dataset with these fixes, 3 passes per config, is measured in [`eval/results/FINAL.md`](eval/results/FINAL.md).

Agent mode, 4 scenarios (layoff and HR warning, Korean and English), airlock mode, 1 pass each ([`eval/results/s6-agent/`](eval/results/s6-agent/)). Identity facts found by the deterministic scanner in anything that left the machine: **0 of 19** with placeholders and 0 of 19 with surrogates. Before this round, team and employer names (`품질보증팀`, `영업2팀`, `Payments Platform`) survived all three passes of every run. The first agent attempt blocked every run at its third turn: GLiNER read the tool-argument key `doc_id` as an HTTP cookie. Object keys of tool-call arguments are now never rewritten and code identifiers are not secrets; a later surrogate attempt blocked once more (a title match crossed a line break and a surrogate organization contained that protected string), which was fixed before the runs counted here.

Latency: Nemotron-3-Nano-4B Q4_K_M on an M3 Pro with GLiNER on CPU; another idle llama-server was loaded on the same machine during the runs. Detect time per chat request p50 3.4 s / p95 8.4 s (B1 on the same cases: 3.9 s / 8.2 s). The extra local call (health entailment) is only made for health generalizations outside the category table.

## Agent mode: egress firewall for tool calls and web search

Masking a prompt and restoring the answer is a solved problem: PasteGuard, Kiji, and LiteLLM with Presidio all do it. Agents leak through other channels. A research agent that reads your documents sends their contents to the cloud model on every planning turn, replays its own tool-call arguments, and sends search queries to a search API. MosaicLeaks (Gurung et al., 2026, [arXiv:2605.30727](https://arxiv.org/abs/2605.30727)) shows that an observer can infer private document contents from a deep-research agent's search queries alone. AWS Bedrock Guardrails [documents](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-sensitive-filters.html) that it does not inspect tool-call arguments or tool results.

In agent mode, Airlock treats every hop that leaves the machine as an egress event, gates it, and audits it:

| Hop | Destination | What Airlock does before it leaves |
|---|---|---|
| planning turn (`prompt`, then `tool_result`) | Nemotron 3 Ultra | The whole history (question, documents read so far, search results, the model's earlier tool calls) goes through the normal detector and vault, then the deterministic gate. The same value keeps the same placeholder for the whole run. |
| search (`search_query`) | Tavily | The search-intent guard: span detection, a local rewrite into a generic query, the gate on the exact Tavily payload, an intent judge, one retry, then that one search is blocked. |
| local tools (`list_local_docs`, `read_local_doc`) | nowhere | They run on your machine. A document reaches the cloud only as a sanitized tool result. |
| final answer | nowhere | The answer arrives with placeholders and is rehydrated locally. |

```mermaid
sequenceDiagram
    autonumber
    participant U as You (question + local docs)
    participant A as Airlock (local)
    participant N as Nemotron-3-Nano-4B (local)
    participant T as Nemotron 3 Ultra (Token Factory)
    participant S as Tavily
    U->>A: question, documents
    loop each planning turn (max 8)
        A->>N: detect spans in the whole history
        A->>A: vault placeholders + deterministic gate
        A->>T: sanitized turn (hop: upstream)
        T-->>A: tool call with placeholders
        alt read_local_doc / list_local_docs
            A->>A: runs locally, result joins the history
        else web_search(query)
            A->>N: rewrite query without the private situation
            A->>A: gate on the exact Tavily payload
            A->>N: intent judge (or Content Safety model)
            alt judged generic
                A->>S: rewritten query (hop: tavily)
                S-->>A: results
            else still revealing after one retry
                A->>A: block this search, the agent continues without it
            end
        end
    end
    T-->>A: finish(answer with placeholders)
    A->>U: rehydrated answer + trace of every hop
```

### Search-intent guard

Search queries are short, so the risk is rarely a string the gate already knows. It is intent: `<ORG_1> layoff list team lead how to respond` still tells the search provider that someone at a company is on a layoff list. For each query the agent wants to send ([`airlock/search_guard.py`](airlock/search_guard.py)):

1. **Detect.** The normal span detector runs on the query, with the agent's placeholders restored locally.
2. **Rewrite.** Nemotron-3-Nano-4B rewrites it toward a generic, information-seeking query ([`agent_search_rewrite.md`](airlock/prompts/agent_search_rewrite.md)). It receives the user's question and excerpts of the documents read so far as the thing it must not reveal. Example from a live run: the agent asked for `Tessellate Health AI ambient clinical documentation Denver competitors funding valuation`, and Tavily received `ambient clinical documentation market valuation competitors`.
3. **Gate.** The exact Tavily payload is checked for every value detected in the query, every original masked during the run, declared terms, canaries, secret patterns and leftover placeholders.
4. **Judge.** An intent judge decides whether the rewritten query still reveals a private situation. The policy is [`search_judge_policy.md`](airlock/prompts/search_judge_policy.md). `AIRLOCK_SEARCH_JUDGE` selects the judge:
   - `nano` (default): the same local Nano-4B, yes/no JSON at temperature 0.
   - `safety`: NVIDIA Nemotron 3.5 Content Safety in custom-policy mode (`chat_template_kwargs.custom_policy`, temperature 0.01, categories on, thinking off). Placeholders are swapped for `[REDACTED]` in the judge input, because the model reads `<PHONE_1>` as a phone number.
   - `both`: block if either one flags the query.

   In a live spot check of 5 queries through `both`, the two judges agreed on 4. On `Tessellate Health AI acquisition by Corvane Analytics due diligence`, Nano answered "no" and Content Safety flagged it (`Naming a specific non-public person or organization`). The evaluation below used `nano` only.
5. **Retry, then block.** A rejected rewrite is retried once, with the rejected query as feedback. If that also fails, only this search is blocked: the agent is told the search was withheld and continues. A judge that errors, times out or answers off-schema counts as a flag (fail closed).

The audit hop records `original_query_hmac`, the `outbound_query` actually sent (or `null`), the judge verdict and model, and each attempt's gate reasons and verdict. Rejected candidates are stored only as HMACs.

To run the Content Safety judge ([GGUF by mradermacher](https://huggingface.co/mradermacher/Nemotron-3.5-Content-Safety-GGUF), Q4_K_M, 2.5 GB). `--swa-full` lets llama.cpp cache the policy prefix for this Gemma 3 model:

```bash
llama-server -m ~/.cache/airlock/models/safety/Nemotron-3.5-Content-Safety.Q4_K_M.gguf \
  --alias nemotron-3.5-content-safety --host 127.0.0.1 --port 8086 \
  -ngl 999 -fa on -c 4096 -np 1 --swa-full --jinja --cache-ram 0 --no-webui
AIRLOCK_SEARCH_JUDGE=safety uv run airlock serve
```

### Running the agent

```bash
uv run airlock agent "I got a layoff notice. Should I sign the separation agreement?" --docs ./private_docs
```

The CLI prints one line per hop: what went to Ultra, what went to Tavily (local query next to the query actually sent), which tools ran locally, and the rehydrated answer. In the demo UI, the **Agent** tab streams the same trace with a Korean preset (a resignation-notice scenario with fictional documents).

`POST /v1/agent/run`

```json
{"question": "...", "docs": [{"name": "notice.md", "text": "..."}], "max_steps": 8}
```

Returns `{"run_id", "request_id", "status", "answer", "steps", "searches", "search_rewritten", "search_blocked", "trace": [...]}`. `status` is `finished`, `max_steps`, `blocked` (a planning turn failed the gate or the local detector failed) or `error`. With `?stream=1` the response is `text/event-stream`, one `event: <type>` per event:

| Event | Fields |
|---|---|
| `run_started` | `run_id`, `request_id`, `guard`, `max_steps`, `docs` (`id`, `title`), `question` |
| `hop` (upstream) | `hop`, `step`, `destination: "upstream"`, `kind`, `decision` (`allow`/`block`), `reasons`, `outbound` (messages new in this turn, as sent), `local` (the same messages as you have them), `model_used`, `ms` |
| `hop` (tavily) | `hop`, `step`, `destination: "tavily"`, `kind: "search_query"`, `decision` (`allow`/`rewritten`/`block`), `reasons`, `model_query` (with placeholders), `local_query`, `outbound_query`, `judge`, `attempts`, `results`, `ms` |
| `tool` | `step`, `name`, `executed: "local"`, `summary` |
| `final` | `status`, `answer` (rehydrated), `steps`, `searches`, `search_rewritten`, `search_allowed`, `search_blocked` |
| `done` | `run_id`, `request_id` (the audit record, `GET /audit/{request_id}`) |

The `local` fields and `local_query` contain your originals. Like review previews, they are a response to the local client only. The audit record (`kind: "agent"`) holds one `hops[]` entry per hop: the exact payload for hops that were sent, and reasons and keyed hashes for hops that were not.

Documents are listed to the model by neutral ids (`doc-1`), because file names often describe the situation. A run has at most `AIRLOCK_AGENT_MAX_STEPS` planning turns (default 8); the last turn offers only `finish`. Ultra's native OpenAI tool calling is used, with `reasoning_effort: "none"`. In a live check it called `list_local_docs`, `read_local_doc` and `finish` correctly and kept `<ORG_1>`-style placeholders intact inside tool arguments, so no JSON-action fallback was needed. Two quirks showed up during evaluation and are handled: Token Factory occasionally returns `finish` with `{}` arguments after the whole answer was generated (the agent asks once more, outside the step limit), and a long answer can hit the output cap inside the arguments (the cap is 6000 tokens and a cut-off answer is recovered).

Masking is recomputed for the whole history on every turn, through the same detection entry point as chat (GLiNER ensemble and refinement included; the search guard uses it too). When one turn adds several tool results, a value can be detected in one of them and missed in another: the pipeline propagates every detected value to every slot of the turn before the gate decides, and object keys of tool-call arguments (`{"doc_id": ...}`) are never rewritten. If a known value then survives only inside web search results (for example in an encoded URL the gate decodes), those results are withheld from the history and the agent is told so. A document or the question is never dropped: such a turn stays blocked.

### Measured: unguarded agent vs Airlock

[`eval/agent/`](eval/agent/) holds 16 fictional scenarios, 8 Korean and 8 English: a lab result with a medication question, a layoff notice and severance, a lawsuit summons, an M&A memo with competitor research, an HR performance warning, a visa refusal, a debt collection notice, and a pregnancy with job-offer timing. Each scenario has local documents, a question, the private facts an observer must not learn, a one-sentence private situation, and an answer rubric. The same agent loop runs each scenario in two modes:

- **unguarded:** raw documents and raw queries go out. This mode exists only in-process for evaluation, needs `AIRLOCK_ALLOW_UNGUARDED=1`, and records every hop the same way.
- **airlock:** the guarded path described above.

The attacker is Nemotron 3 Ultra with the [`eval/attack.py`](eval/attack.py) prompt, which sees only what left the machine. Each run is attacked twice: once over all hops, and once over the Tavily queries alone (the MosaicLeaks threat model). Private facts are matched deterministically in the attacker's output, and a strict grader decides whether the attacker inferred the private situation. A blind grader scores the final answer against the rubric from 1 to 5.

Results: 16 scenarios × 2 modes × 3 passes, Nemotron-3-Nano-4B judge ([`eval/agent/results/demo/`](eval/agent/results/demo/) has the full summary, per-scenario table and sample traces):

| Metric | Unguarded agent | Airlock |
|---|---:|---:|
| Private facts recovered, all hops | 87.2% ± 7.8 | **41.3% ± 4.2** |
| Private situation inferred, all hops (strict grader) | 89.6% ± 7.2 | 89.6% ± 3.6 |
| Private facts recovered, search queries only | 4.9% ± 1.6 | **0.7% ± 0.6** |
| Private situation inferred, search queries only | 8.3% ± 3.6 | 4.2% ± 7.2 |
| Answer utility (1-5, blind rubric grader) | 4.44 ± 0.12 | 4.71 ± 0.18 |
| Searches rewritten / blocked | 0% / 0% | 93.2% / 4.9% |
| Steps per run | 6.2 | 6.6 |
| Latency per run, median | 23 s | 367 s |

Mean ± sample sd across passes. How to read it:

- **Documents are where agents leak most, and masking halves it.** Unguarded, the attacker recovered 87% of the private facts (names, organizations, case and account numbers, amounts, dates). Through Airlock, 41% remain, and those are detector misses. Nemotron-3-Nano-4B sometimes returns no spans at all for plain English business text: in the English M&A memo every private fact reached the cloud model in 2 of 3 passes. By language, 38% remain in Korean (where the deterministic Korean rules help) and 44% in English.
- **The situation is still visible to the cloud model.** 90% in both modes. The planning model has to read "a layoff notice with a 21-day release" to help, and the facts the detector missed give the grader the named anchor it needs. Airlock removes identity, not the topic of your documents.
- **Search queries.** With a neutral system prompt, Nemotron 3 Ultra's own queries were already fairly generic (5% of facts, 8% of situations; 7% and 17% in Korean). Unguarded queries included, for example, `Maple Ridge College DLI O0000000E-0031 Business Administration Diploma designated learning institution` and `위로금 3개월분 통상임금 1650만원 적정성 퇴직금 계산`. Airlock rewrote 93% of queries, blocked 5%, and cut fact recovery from queries to 0.7%. The remaining 4.2% situation matches are 2 of 48 runs where fully generic queries (`study permit refusal reasons and reapplication process in Canada`) were enough for the grader, which accepts a country as the anchor. This scenario set does not reproduce a MosaicLeaks-scale query leak: the search guard removed a small leak, it did not close a large one.
- **No utility cost measured.** Rewritten or blocked searches did not lower rubric scores. Low scores occurred in both modes: answers about the wrong case or target, one degenerate answer, and one run per mode that ended without an answer. The M&A scenario in Korean scored low in both modes.
- **Latency is not representative.** The local model shared the GPU with two other llama-servers and decoded at about 4-7 tokens/s (about 33 alone). Guarded runs spend most of their time detecting spans in whole documents on every turn.
- **The attacker is a lower bound.** On 4 unguarded runs and 1 Airlock run whose outbound payloads contained every private fact verbatim, it recovered none: it summarized the public search results instead, or continued the agent's tool calls. The run also exposed agent bugs (cross-slot masking blocks, empty `finish` arguments). They were fixed, and the affected runs were discarded and rerun; `config.json` lists them.


### Threat model for agent mode

**Covered:**

- Every string Airlock knows is sensitive is enforced on every hop, including tool results and the agent's own tool-call arguments, not only the first prompt. "Knows" means detected in any document or turn of the run, declared, a canary, or a secret pattern.
- Search queries are rewritten on the device and judged for intent before they leave, which targets the MosaicLeaks channel: the rewrite drops private organizations, people and the private event even when the cloud model asked for exactly that, and the search-only attacker row above measures how well it works.
- Every hop is audited, so you can check afterwards exactly what Ultra saw at each turn and what Tavily saw.
- The agent never runs unguarded outside evaluation.

**Not covered:**

- **Detector misses inside documents.** If the local detectors miss a name or a company in a document, and you did not declare it, the cloud model sees it on every later turn. The table above measures how often this happens. Declare your own name, employer and project names with `/vault/terms`.
- **Content, not identity.** The cloud model must see the substance of your documents to help: a diagnosis, a severance clause, a deal price. Airlock removes identifiers and generalizes some quasi-identifiers. The provider can still learn that *someone* has this situation.
- **The judge is a small model.** Nano-4B and Content Safety are 4B classifiers. In the local safety spike both judged all 16 probe queries correctly in 3 runs each, but that small set was also used to write the policy. The only deterministic guarantee is the gate on known strings.
- **Linking queries.** Several generic queries in a row (`severance agreement review`, `Oregon non-compete`, `COBRA after layoff`) can still suggest the topic, and Tavily also sees timing and your network address.
- **Inbound content.** Search results and documents are not checked for prompt injection. An injected instruction can steer the agent. It still cannot get known strings past the gate, and its search queries still pass the rewriter and judge.
- **Utility cost.** A search that needs a private name (research on a small, non-public competitor) is rewritten to its category or blocked. The answer can be less specific.
- **Scope.** Only the built-in tools are wired to the egress policy. The policy has an `http_tool` destination for more tools, but no generic HTTP tool ships.

## Quickstart

Requirements: macOS or Linux, Python 3.12, [uv](https://docs.astral.sh/uv/), [llama.cpp](https://github.com/ggml-org/llama.cpp) (`llama-server`).

```bash
git clone https://github.com/tristan-kkim/airlock && cd airlock
uv sync

# 1. Local detector model (Nemotron-3-Nano-4B GGUF via llama-server on 127.0.0.1:8081)
scripts/local_model/serve.sh

# 2. Keys
cp .env.example .env   # set NEBIUS_API_KEY and TAVILY_API_KEY

# 3. Check everything (never prints secrets), then run
uv run airlock doctor
uv run airlock serve   # http://127.0.0.1:8787
```

See [`scripts/local_model/serve.sh`](scripts/local_model/serve.sh) for downloading the model and serving it.

Open <http://127.0.0.1:8787/> for the demo UI. It has three panes: **What you typed**, **What the cloud saw**, and **Answer (rehydrated)**, plus the gate decision and detections. With **Review redactions before sending** on, it first lists every proposed redaction with a before/after preview; uncheck the ones you want sent as written, add anything that was missed, then **Send**.

Use it from any OpenAI client:

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8787/v1", api_key="unused-locally")
reply = client.chat.completions.create(
    model="any",  # Airlock always uses AIRLOCK_UPSTREAM_MODEL
    messages=[{"role": "user", "content": "I'm Jane Park, 010-2345-6789. Draft a note to my landlord."}],
)
print(reply.choices[0].message.content)  # contains your real name and number again
```

Run the tests (fully offline, all services mocked):

```bash
uv run pytest -q
uv run ruff check
uv run pytest -m live   # opt-in: real local model / Token Factory / Tavily using .env
```

## How Airlock uses NVIDIA Nemotron and Nebius Token Factory

Airlock is built around a division of labour between two NVIDIA open models.

| Role | Model | Where it runs | Why this model |
|---|---|---|---|
| Privacy detector, search rewriter, result re-ranker | **NVIDIA Nemotron-3-Nano-4B** (`nvidia/NVIDIA-Nemotron-3-Nano-4B-GGUF`, Q4_K_M) | On your machine via llama.cpp | Small enough to run on a laptop, and it follows a JSON schema reliably. It sees private text (with pattern-detected secrets already masked), so it must never leave the device. Reasoning is disabled per request (`chat_template_kwargs.enable_thinking=false`) to keep latency low. |
| Optional second PII proposer | **NVIDIA GLiNER-PII** (`nvidia/gliner-PII`) | On your machine (PyTorch, CPU by default) | High recall on names, IDs and secrets, including many Korean spans. Its over-masking is filtered by agreement, type checks and a Nano adjudication call (see the ensemble section). |
| Reasoning over the sanitized request | **NVIDIA Nemotron 3 Ultra** (`nvidia/Nemotron-3-Ultra-550b-a55b`) | **Nebius Token Factory** (OpenAI-compatible API) | A frontier-class open model for the real task. It only ever receives placeholders and generalizations, and it keeps `<PERSON_1>`-style placeholders intact, including in Korean output. |
| Fallback | **NVIDIA Nemotron 3 Super** (`nvidia/nemotron-3-super-120b-a12b`) | Nebius Token Factory | Used once, automatically, when Ultra returns 5xx or is unavailable. `reasoning_effort` is dropped for this model because it rejects that field. Its `reasoning_content` is hidden from clients unless they opt in. |

Token Factory is on the execution path of every allowed chat request: `POST https://api.tokenfactory.nebius.com/v1/chat/completions` with `Authorization: Bearer $NEBIUS_API_KEY`. Airlock forwards `tools`, `tool_choice`, `reasoning_effort` and `stream` unchanged. It does not rely on upstream `response_format: json_schema`.

**Data retention.** By default, Token Factory may store prompts and outputs unless Zero Data Retention (ZDR) is enabled for your account or project. We recommend enabling ZDR. Airlock's guarantee does not depend on it: whatever the provider keeps is the sanitized payload shown in the audit log, never your originals.

Web search uses [Tavily](https://tavily.com) (`POST /search`, basic depth). Nemotron-3-Nano rewrites the query locally before it is sent, and re-ranks the results locally afterwards.

## Configuration

All settings are environment variables. Airlock also reads `.env`; see [`.env.example`](.env.example).

| Variable | Default | Purpose |
|---|---|---|
| `AIRLOCK_LOCAL_BASE_URL` | `http://127.0.0.1:8081/v1` | Local OpenAI-compatible server (llama.cpp) |
| `AIRLOCK_LOCAL_MODEL` | `nemotron-3-nano-4b` | Model name sent to the local server |
| `AIRLOCK_LOCAL_DISABLE_THINKING` | `true` | Send `chat_template_kwargs.enable_thinking=false` |
| `NEBIUS_API_KEY` | none | Token Factory key |
| `AIRLOCK_UPSTREAM_BASE_URL` | `https://api.tokenfactory.nebius.com/v1` | Upstream API |
| `AIRLOCK_UPSTREAM_MODEL` | `nvidia/Nemotron-3-Ultra-550b-a55b` | Primary cloud model |
| `AIRLOCK_UPSTREAM_FALLBACK_MODEL` | `nvidia/nemotron-3-super-120b-a12b` | Retried once on 5xx or model unavailable; empty disables it |
| `TAVILY_API_KEY` | none | Tavily key for `/v1/search` |
| `AIRLOCK_VAULT_PATH` | `./.airlock/vault.sqlite3` | Vault (holds originals; `:memory:` for none on disk) |
| `AIRLOCK_AUDIT_DB` | `./.airlock/audit.sqlite3` | Audit log |
| `AIRLOCK_AUDIT_HASH_KEY` | none | HMAC key for audit hashes; if unset, one is generated at the key file |
| `AIRLOCK_AUDIT_HASH_KEY_FILE` | `./.airlock/audit_hash.key` | Where the generated key is stored (mode 600) |
| `AIRLOCK_PROTECTION_LEVEL` | `balanced` | `strict`, `balanced` or `minimal` (see below) |
| `AIRLOCK_SUBSTITUTION` | `placeholder` | `placeholder` (`<PERSON_1>`) or `surrogate` (format-preserving fake values; secrets stay placeholders). See *Surrogates* |
| `AIRLOCK_REVIEW` | `never` | `always`, `uncertain` or `never`: when to stop and ask for confirmation (see review mode) |
| `AIRLOCK_LOCAL_TIMEOUT_S` | `30` | Local detector timeout; a timeout blocks the request |
| `AIRLOCK_CANARIES` | none | Comma-separated tripwire strings that must never leave |
| `AIRLOCK_GLINER` | `off` | `on` adds the NVIDIA GLiNER-PII ensemble (needs `uv sync --extra gliner`) |
| `AIRLOCK_GLINER_MODEL` | `nvidia/gliner-PII` | Local weights directory or an already-cached Hub id (falls back to `GLINER_PII_MODEL`); never downloaded at runtime |
| `AIRLOCK_GLINER_THRESHOLD` | `0.4` | Score threshold for every label |
| `AIRLOCK_GLINER_THRESHOLDS` | none | Per-label overrides, e.g. `city=0.6,first_name=0.5` |
| `AIRLOCK_GLINER_DEVICE` | `cpu` | `cpu`, `mps` or `cuda`. On an M3 Pro, `mps` is faster alone but slower while Nano decodes on Metal |
| `AIRLOCK_GLINER_ADJUDICATE` | `on` | Ask the local model about GLiNER-only spans; `off` accepts every span that passes the shape check |
| `AIRLOCK_GLINER_AGREEMENT_ONLY` | `city,date_of_birth` | Labels whose GLiNER-only spans are dropped; only agreement with another source confirms them. Empty adjudicates every label |
| `AIRLOCK_GLINER_KO_NAME_MIN_SYLLABLES` | `3` | Shortest Hangul name GLiNER may add on its own |
| `AIRLOCK_HOST` / `AIRLOCK_PORT` | `127.0.0.1` / `8787` | Bind address |
| `AIRLOCK_ALLOWED_HOSTS` | `127.0.0.1,localhost,::1` | Accepted `Host` headers (DNS-rebinding protection). Outside demo mode only loopback names are honored; other names and `*` are ignored with a warning |
| `AIRLOCK_DEMO` | unset | `1` runs the hosted public demo: per-session in-memory state, rate limits, daily budget, presets, banner, security headers. Never for real data. See [`deploy/DEMO_RUNBOOK.md`](deploy/DEMO_RUNBOOK.md) |
| `AIRLOCK_DETECTOR_BACKEND` | `local` | `cloud` runs the detector on Token Factory (`AIRLOCK_CLOUD_DETECTOR_MODEL`, default `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`). Refused unless `AIRLOCK_DEMO=1` |
| `AIRLOCK_DEMO_*` | see `deploy/demo.env` | Demo guards: `IP_LIMIT`, `SESSION_LIMIT`, `WINDOW_S`, `MAX_INPUT_CHARS`, `MAX_BODY_BYTES`, `MAX_TOKENS`, `AGENT_MAX_STEPS`, `MAX_CONCURRENT`, `DAILY_REQUESTS`, `DAILY_CLOUD_CALLS`, `SESSION_TTL_S`, `MAX_SESSIONS`, `PRESETS` (`auto`/`recorded`), `TRUSTED_PROXY_HOPS`, `CLIENT_IP_HEADER` |
| `AIRLOCK_AGENT_MAX_STEPS` | `8` | Planning turns per agent run (1-16) |
| `AIRLOCK_AGENT_REASONING_EFFORT` | `none` | `reasoning_effort` sent with agent turns; empty omits it |
| `AIRLOCK_SEARCH_JUDGE` | `nano` | Intent judge for agent searches: `nano`, `safety` or `both` |
| `AIRLOCK_SAFETY_BASE_URL` / `AIRLOCK_SAFETY_MODEL` | `http://127.0.0.1:8086/v1` / `nemotron-3.5-content-safety` | Nemotron 3.5 Content Safety server for `safety` and `both` |
| `AIRLOCK_ALLOW_UNGUARDED` | unset | Evaluation only: allows in-process `guard=False` agent runs (never over HTTP or the CLI) |

Protection levels:

| Level | Direct identifiers and secrets | Quasi-identifiers and precise location | Kept as-is (the situation) |
|---|---|---|---|
| `strict` | masked | masked with placeholders; the detector is told to flag aggressively | nothing the detectors flag |
| `balanced` | masked (or surrogates) | generalized, entailed by the original ("마흔다섯" → "40대", "Tulsa" → "a city in Oklahoma"); employer + unit + role linked into one generalization | amounts, lab values, dosages, durations, clock schedules, dates that are not a birth date, diagnoses, medications and short health terms without a small-group cue; a health generalization that is not entailed |
| `minimal` | masked (or surrogates) | `QUASI_IDENTIFIER` spans are left as-is; location is still generalized | as `balanced` |

### Surrogates

`AIRLOCK_SUBSTITUTION=surrogate` replaces identity values with decoys instead of tokens. With placeholders, the baseline's cloud answers sometimes told the user that their own value "is a placeholder" and could not be processed. With surrogates the cloud model reads an ordinary document ([`airlock/surrogate.py`](airlock/surrogate.py)):

| Value | Surrogate |
|---|---|
| Korean name | another name with the same syllable count, from a curated pool without public figures (`정다은` → `엄민재`) |
| English name | same token count; a later last name alone reuses the same surrogate part |
| Organization | a fictional name with the same suffix type (`새론다움물류` → `해솔물류`, `Halcyon Freight Systems` → `Larkmoor Freight Systems`) |
| Phone, email | same shape in reserved or invalid ranges: `010-0000-xxxx`, `(415) 555-01xx`, `…@example.com` |
| ID, card, account | same shape: RRN with month `00`, SSN area `000`, a card number that fails Luhn, IBAN check digits `00`, ticket prefixes kept (`HFS-40418` → `HFS-83120`) |
| Street address | same region, fictional street and numbers (`경기도 성남시 분당구 은행나무샘길 88, 111동 2304호` → `경기도 성남시 분당구 새솔길 137, 441동 4511호`) |
| Secret, credential | never a surrogate: `<SECRET_1>` |

A value without a recognised shape (a declared project name) falls back to a placeholder. Surrogates are drawn with a keyed hash (not predictable from the original), stored in the vault (consistent for the conversation or agent run), and rejected when they occur in the request, contain another original, repeat another surrogate, or match a high-confidence secret pattern. Rehydration finds a surrogate as written or reformatted (`01000004821`), restores a name's first or last part used alone, keeps English possessives, and corrects the Korean particle after the restored value (`해솔물류과의` → `새론다움물류와의`, `김서준이` → `박지우가`), also across streamed chunks. The placeholder note is only added when a placeholder remains.

## API

### `POST /v1/chat/completions`

OpenAI-compatible request and response, streaming included. Airlock-specific headers:

- Response `x-airlock-request-id`: key for `GET /audit/{id}`.
- Request/response `x-airlock-conversation-id`: scopes placeholder numbering. If omitted, it is derived from the first user message.
- Request `x-airlock-include-reasoning: 1`: forward the model's `reasoning_content` (rehydrated). Off by default.

Forwarded fields: `messages`, `tools`, `tool_choice`, `parallel_tool_calls`, `reasoning_effort`, `stream`, `stream_options`, `temperature`, `top_p`, `max_tokens`, `max_completion_tokens`, `n`, `stop`, `seed`, `presence_penalty`, `frequency_penalty`, `response_format`, `logprobs`, `top_logprobs`. Everything else (`user`, `metadata`, ...) is dropped. `model` is always replaced by `AIRLOCK_UPSTREAM_MODEL`.

- Request `x-airlock-review: required`: return proposed redactions for confirmation instead of sending (see below).

Blocked requests return HTTP 422:

```json
{"error": {"type": "airlock_blocked", "reasons": ["declared_term:PERSON:6e0aeb4d2ed5"], "request_id": "req_..."}}
```

Agent runs: see [Agent mode](#agent-mode-egress-firewall-for-tool-calls-and-web-search) for `POST /v1/agent/run` and its search reason codes (`search_intent_revealed`, `judge_malformed:<kind>`, `safety_judge_unavailable:<error>`, `safety_judge_malformed:<kind>`).

Reason codes: `vault_original`, `declared_term`, `canary`, `secret_pattern:<rule>`, `uninspectable_content:<part type>`, `local_detector_unavailable:<error>` (connection failure or HTTP error), `local_detector_malformed:<kind>` with kind `prose`, `invalid_json`, `schema`, `length`, `repetition` or `timeout`, and for search also `local_rewriter_unavailable:<error>`, `rewrite_empty`, `rewrite_contains_placeholder`. Reasons carry the first 12 hex characters of the value's keyed hash (see the audit section), never the text.

Other errors: `400 invalid_request_error`, `415` (non-JSON POST), `502 airlock_upstream_error`, `503 airlock_not_configured`.

### Review mode: HTTP 409 and `POST /review/{review_id}`

The local detector is a proposer, and on Korean semantic spans it is far from perfect. Review mode puts the user in the loop before anything is sent. It is triggered by the request header `x-airlock-review: required`, or by `AIRLOCK_REVIEW`:

- `always`: every chat request is held for review.
- `uncertain`: only when the local model found a span no deterministic detector confirmed, when spans or generalizations were discarded, or when a Korean quasi-identifier or health rule fired.
- `never` (default): send directly.

A held request returns HTTP 409 and nothing is written to the vault or sent upstream:

```json
{"error": {"type": "airlock_review_required", "review_id": "rev_...", "reasons": ["llm_only_spans"],
  "proposed": [{"span_id": "s1", "type": "PERSON", "action": "mask", "text": "문태오",
                "replacement": "<PERSON_1>", "preview_before": "…동료 문태오 대리가…",
                "preview_after": "…동료 <PERSON_1> 대리가…", "source": "llm", "sources": ["llm", "rule"],
                "confidence": 0.85, "locked": false}],
  "request_id": "req_...", "expires_in_s": 600}}
```

The previews contain the originals. They are a response to the local client only and never go upstream. `confidence` is a heuristic (higher when independent detectors agree), not a calibrated probability. `locked` marks spans that the gate enforces anyway (vault terms, high-confidence secret patterns): rejecting one makes the gate block.

Continue with:

```json
POST /review/rev_...
{"approve": ["s1"], "reject": ["s2"], "add": [{"text": "Nightjar", "type": "PROJECT"}]}
```

Spans not listed are approved. The response is the normal chat completion (or 422 if the gate blocks), and its audit record carries `meta.review` counts. A review id works once and expires after 10 minutes; `POST /vault/reset` discards pending reviews.

### `POST /v1/search`

```json
{"query": "Can my employer fire me without severance?", "context": "I'm Minji Lee at ...", "max_results": 5}
```

Returns `{"request_id", "outbound_query", "results": [{"title", "url", "content", "score", "local_rank"}], "answer"}`. The context never leaves the machine. Masked values found in the query or context may not appear in the rewritten query; generalized topics (a condition, an age range) may.

### `GET /audit/{request_id}`

```json
{
  "request_id": "req_...", "created_at": "2026-09-13T12:00:00+00:00", "kind": "chat",
  "detections": [{"text_sha256": "...", "type": "PERSON", "action": "mask", "source": "llm"}],
  "outbound": [{"destination": "upstream", "payload": {"model": "...", "messages": ["..."]}}],
  "gate": {"decision": "allow", "reasons": []},
  "timings_ms": {"detect": 212.4, "gate": 0.8, "upstream": 1530.2, "rehydrate": 0.1, "total": 1745.0},
  "meta": {"stream": false, "model_used": "nvidia/Nemotron-3-Ultra-550b-a55b", "fallback": false,
           "detector": {"pattern_spans": 1, "masked_before_llm": 1, "rule_spans": 2, "llm_calls": 1,
                        "llm_proposed": 3, "llm_kept": 2, "llm_discarded_ungrounded": 1,
                        "llm_discarded_invalid": 0, "generalize_rejected": 0, "semantic_cues": 1, "...": 0}}
}
```

`meta.detector` holds counts only: how many spans each detector produced, how many the local model proposed and how many were discarded as ungrounded or invalid, and how many generalizations were rejected. A held request is recorded with `gate.decision` `review`.

`text_sha256` is **HMAC-SHA256** of the original under the local audit key (`AIRLOCK_AUDIT_HASH_KEY`, or the generated `.airlock/audit_hash.key`). The field name is kept for compatibility. To check whether a value you know was detected, compute `hmac.new(key, value.encode(), hashlib.sha256).hexdigest()`. The key is never served over HTTP. `action` is `mask`, `generalize`, or `keep` (detected but intentionally left, under `minimal`). `outbound` holds one entry per payload that was sent, so a fallback produces two. `GET /audit?limit=50` lists recent records.

### `POST /vault/terms`

```json
{"terms": ["Jane Park", "Hanbit Labs"], "kind": "sensitive"}
```

`type` is optional. Without it, each term's type is inferred (`Jane Park` → `PERSON`, `Hanbit Labs` → `ORG`, `Project Nightjar` → `PROJECT`, otherwise `TERM`); pass `"type": "PERSON"` to set one for every term in the request. `kind: "sensitive"` terms are always masked and enforced by the gate. `kind: "canary"` terms are never masked: if one reaches an outbound payload, the request is blocked. Returns `{"added", "total", "kind"}`.

### `DELETE /vault/terms`

Body `{"terms": ["Hanbit Labs"], "kind": "sensitive"}` (`kind` optional; omitted removes both kinds). Returns `{"removed", "total"}`.

### `POST /vault/reset`

Body `{}`. Clears every declared term, canary and conversation mapping, plus the in-memory detection caches (local detector and health entailment). Audit records are kept. Returns `{"reset": true, "terms_removed", "mappings_removed", "detection_cache_cleared"}`. The evaluation harness calls it before every pass instead of restarting the server.

All `POST` endpoints require `Content-Type: application/json`, including `/vault/reset`.

### `GET /healthz`

Status, version, protection level, model names, the local detector temperature, and whether keys are configured. It makes no network calls.

## Threat model and limitations

**What Airlock is designed to stop:** accidental disclosure of identifying or secret strings from your machine to a cloud LLM provider or a web search provider, through an app you control that talks to the OpenAI API.

**What it guarantees, and how:** a string that Airlock knows is sensitive cannot leave through the proxy in any JSON field. That holds regardless of letter case, Unicode width, invisible characters, inserted spaces or punctuation, digit separators or spelled-out numerals, or base64, percent or JSON-string encoding up to two layers deep. "Knows" means it was detected in this request, detected earlier in the conversation, declared by you, configured as a canary, or matched by a high-confidence secret or ID pattern. This check is plain code on the final bytes. A misbehaving local model can cause over-masking or a block. It cannot cause a known string to be sent.

**What it does not protect against.** Please read this before relying on it.

- **Detector misses.** If the local model, the regexes and the Korean rules all fail to recognise something (an unusual name, an internal project described in plain words), and you did not declare it, it is sent. The gate only enforces what is known. Declare your own name, employer, and key project names with `/vault/terms`, and use review mode for sensitive work. In our local-model spike, Nemotron-3-Nano-4B alone found 70% of Korean semantic spans (11% of Korean quasi-identifiers), against 93% in English; the Korean rules exist to narrow that gap and are measured on a small probe set that was also used to tune the prompt, so treat any number as optimistic.
- **Rule false positives.** The Korean rules prefer to over-mask. A private-sounding company name, a name before a title, or a health term in a personal sentence may be masked even when it is harmless. Review mode lets you undo this.
- **Paraphrase and inference.** Airlock removes strings, not meaning. "My wife, the only female neurosurgeon at the hospital in our small town" contains no name and may still identify someone. Generalization of quasi-identifiers reduces this; it does not eliminate it.
- **Combining requests.** The provider sees many sanitized requests from the same account and may link them.
- **Non-text content.** Images, audio, and files are not inspected, so requests containing them are blocked rather than sent.
- **Tool schemas and names are not rewritten.** Rewriting them would break function calling. The gate still scans them and blocks if they contain known sensitive strings.
- **Search results and answers.** Inbound content is not filtered, and a cloud answer may still mention public facts about you.
- **Your machine.** The vault stores originals in plain text under `./.airlock/`. Anyone with access to your account or disk can read it. Airlock does not protect against malware, a compromised local model server, or other local users. Keep `.airlock/` out of backups and file-sync tools you do not trust, or use `AIRLOCK_VAULT_PATH=:memory:`.
- **Other obfuscations.** The variants listed for the gate are covered. Translation, transliteration (`Kim Minsu` for `김민수`), deliberate misspellings, other encodings (hex, ROT13, compression), splitting a value across messages or fields, and encoding more than two layers deep are not.
- **Audit hashes.** Detections and gate reasons use HMAC-SHA256 under a local key, so the audit file alone does not let anyone brute-force short values such as phone numbers. Anyone who has both the audit file and the key (`.airlock/audit_hash.key`, mode 600) can still test guesses. Protect or rotate the key like the vault. Rotating it makes older records unmatchable.
- **Local API exposure.** The server listens on loopback, checks the `Host` header, and requires JSON content types to resist browser-based cross-origin requests. It has no authentication. Do not expose it on a network.
- **Streaming.** Placeholders split across chunks are held back until complete. Tool-call deltas are buffered and delivered in one piece at the end of the stream.

## Project layout

```
airlock/
  config.py         env configuration
  detect/llm.py     local model client + LLM span detector (fail-closed errors)
  detect/patterns.py Korean-aware PII regexes, secret patterns, entropy check
  detect/ko_rules.py deterministic Korean/English semantic rules (quasi-identifiers, health, orgs, names)
  detect/gliner.py  NVIDIA GLiNER-PII wrapper and ensemble policy (agreement, type checks, adjudication)
  detect/verify.py  grounding check for model spans, generalization leak check
  detect/shape.py   type shape checks for local-model spans, trimming of honorifics, titles, ID labels
  detect/org_rules.py employer, org unit, site, role and age candidates and their request-level link
  detect/quasi.py   k-anonymity-style scorer for quasi-identifier combinations and their coarsening
  detect/obfuscation.py detection on the normalized text (spaced names, spelled or split numbers)
  detect/regions.py Korean admin regions and foreign cities, for containing-region generalizations
  generalize.py     entailed generalizations (ages, birth decades, places, health) and kept situation values
  surrogate.py      format-preserving surrogates and their rehydration (particles, possessives, streams)
  detect/spans.py   span model, term matching, overlap resolution
  placeholders.py   <TYPE_N> syntax, lenient matching for rehydration
  pipeline.py       one detection entry point: patterns -> masked local model -> rules -> ensemble ->
                    refinement -> cross-slot propagation -> vault substitution
  vault.py          original <-> placeholder mappings, declared terms (SQLite)
  gate.py           deterministic allow/block on the exact outbound payload
  textnorm.py       normalized views (compact, digits, detection, decoded) with raw offset maps
  hashing.py        HMAC key loading for audit hashes
  upstream.py       Token Factory client with one-shot fallback
  rehydrate.py      placeholder and surrogate restoration, including streams and tool calls
  search.py         private search: local rewrite, gate, Tavily, local re-rank
  egress.py         egress events and per-run hop audit for agent mode
  search_guard.py   search-intent guard: rewrite, gate, intent judge, retry, block
  agent.py          private research agent (Ultra tool calling, local tools, guarded hops)
  agent_api.py      POST /v1/agent/run (JSON and SSE)
  agent_settings.py agent-mode environment settings
  audit.py          audit records (hashes only)
  server.py         FastAPI app
  cli.py            `airlock serve`, `airlock doctor`, `airlock agent`
  prompts/          detector, adjudication, search rewrite, re-rank, agent and search-judge prompts
  static/index.html demo UI
  demo/             hosted public demo (AIRLOCK_DEMO=1): gateway, guards, sessions, presets and
                    recorded runs, cloud detector adapter, banner UI
Dockerfile            demo image (`demo`: cloud detector; `sidecar`: llama.cpp in the container)
deploy/               demo runbook, Nebius Serverless and Fly.io configs, smoke test
scripts/demo/         records the presets' fallback runs
scripts/local_model/  llama.cpp serving for the local model
eval/                 synthetic evaluation set and harness
eval/agent/           agent-mode scenarios and the unguarded vs Airlock egress evaluation
tests/                offline test suite
```

All examples and evaluation data are synthetic.

## License

Apache License 2.0. Copyright 2026 Tristan Kim. See [LICENSE](LICENSE).
