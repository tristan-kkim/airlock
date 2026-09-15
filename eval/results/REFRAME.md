# Reframing the evaluation: the cloud may learn the problem, but not who has it

This note explains why the headline metrics changed, what the new ones measure, and what the
existing result directories say under them. The numbers below were backfilled from results that
already existed. Nothing was re-run locally: no system was measured again, and the detector is
still changing. Treat them as a first reading, not the final table (see *Caveats*). The final
measurement protocol is `eval/final_protocol.sh` (README, *Final measurement protocol*).

## Why reframe

Two earlier findings made the old headline (case leak rate) misleading.

1. **Agent mode** (16 scenarios, 3 passes). Airlock cut private-fact recovery across all outbound
   hops from 87.2% to 41.3%, but the attacker inferred the private situation in 89.6% of runs in
   both modes. That is not a failure. A cloud model has to understand the problem to help with it,
   so hiding the situation is neither possible nor the goal. Counting a diagnosis the same as a
   name hides what Airlock is for.
2. **Baseline f0ba569.** It had a 22.2% case leak rate with 21% over-redaction, and a manual check
   found 10 of 14 sampled answers distorted by bad generalization ("마흔다섯" became "in their
   30s"). A leak metric alone rewards destroying the prompt.

The claim Airlock can defend is **unlinkability**: an observer of everything that left the machine
may learn that someone has a problem, but should not be able to say who.

## What is measured now

**Identity vs situation.** Every protected item is classified (`eval/protected.py`, written into
each case as `protected`; agent scenarios carry `fact_classes`):

- *identity*: names, contact details, national, account, card, patient, ticket and case numbers,
  exact addresses, credentials, declared vault terms, private employer and client names, and the
  quasi-identifier attributes that single a person out in combination;
- *situation*: the diagnosis, the legal, financial or employment circumstance, the intent.

**Metrics** (per system, mean ± sd over passes):

| Metric | Meaning |
|---|---|
| `identity_leak_rate` | an identity item is in an outbound payload (scanner, normalized matching), or enough identity attributes of a quasi group reach one destination |
| `attack_identity_recovery_rate` | an LLM attacker reading only the outbound payloads recovers at least one identity item |
| `situation_inference_rate` | a grader says the attacker inferred the specific circumstance; no name or anchor required. Chat and search |
| **`linkable_disclosure_rate`** | both for the same case: the cloud could say who has what. 98 situation-sensitive cases (health, finance, quasi-identifier, intent search) that carry identity items |
| `utility_ratio_vs_reference` | blind judge: mean usefulness (1-5) of the system's answer / mean usefulness of a reference answer to the raw prompt from the same upstream model |
| `distortion_rate` | the judge says the answer contradicts a fact the user stated, confirmed by a second focused call |

Full definitions, the judge rubric and the cache layout are in `eval/README.md`.

## Backfilled numbers

### 243 cases

One harness pass was attacked and judged per system (the baselines are deterministic; f0ba569 ran
its detector at temperature 0 and its three passes sent identical payloads for 242 of 243 cases).
Identity leak and over-redaction are over the three harness passes.

| System | Identity leak | **Linkable disclosure** | Identity recovered | Situation inferred | Utility ratio | Distortion (reference) | Over-redaction |
|---|---:|---:|---:|---:|---:|---:|---:|
| raw (pass-through) | 98.5% | 84.7% | 94.7% | 86.1% | 1.05 | 7.7% (10.6%) | 0.0% |
| regex only | 92.7% | 79.6% | 88.8% | 80.6% | 0.87 | 14.0% (10.1%) | 0.4% |
| Presidio + ko/en spaCy | 76.7% | 53.1% | 73.8% | 77.8% | 0.66 | 33.7% (6.7%) | 16.7% |
| NVIDIA GLiNER-PII | 18.9% | 9.2% | 19.4% | 63.0% | 0.59 | 24.5% (4.8%) | 14.1% |
| **Airlock f0ba569** | 21.8% | 17.3% | 18.0% | 61.1% | 0.83 | 29.3% (6.7%) | 21.0% |

By language, Airlock f0ba569: linkable disclosure ko 18.0% / en 16.7%, utility ratio ko 0.76 /
en 0.91, distortion ko 31.4% / en 27.2%.

### Agent mode (16 scenarios × 2 modes × 3 passes)

Stored attacker outputs were reused; the new situation grader and a blind pairwise
utility/distortion judge (the unguarded answer is the reference) were added
(`eval/agent/results/demo-pre-s6/reframe/`, the `d2ff994` run; the current run at `eb311ed` is in `eval/agent/results/demo/reframe/` and summarized in `COMPARISON.md`).

| Metric | unguarded | Airlock |
|---|---:|---:|
| Identity leak (scanner) | 97.9% ± 3.6 | 77.1% ± 3.6 |
| **Linkable disclosure** | 89.6% ± 7.2 | 68.8% ± 6.2 |
| Identity facts recovered (share of identity facts) | 91.5% ± 5.2 | 37.0% ± 2.1 |
| Situation facts recovered (share of situation facts) | 81.3% ± 11.3 | 47.2% ± 11.5 |
| Situation inferred (no anchor needed) | 93.8% ± 6.2 | 93.8% ± 6.2 |
| Utility, blind pairwise judge (1-5) | 4.12 ± 0.17 | 4.54 ± 0.32 |
| Utility ratio Airlock / unguarded | | 1.10 ± 0.05 |
| Distortion | 39.6% ± 9.5 | 12.5% ± 0.0 |

## Reading the numbers

- **The framing holds in direction, not yet in size.** On the 243 cases, f0ba569 cuts linkable
  disclosure from 84.7% (raw) to 17.3% while the attacker still infers the situation in 61.1% of
  cases. In agent mode the situation is inferred in 93.8% of runs in both modes, as expected, but
  the attacker still names at least one identity fact in 68.8% of Airlock runs. Airlock removes
  most identity facts (37% recovered vs 91.5%), yet one surviving fact is enough to link.
- **What still links, 243 cases.** 15 of f0ba569's 17 linkable cases are quasi-identifier cases
  where the combination of employer, site, team, role and age was not generalized below
  `identity_k`; the other two are a Korean password (`hlt-ko-11`) and an English self-introduction
  (`hlt-en-12`).
- **What still links, agent mode.** Team and department names (`영업2팀`, `품질보증팀`,
  `품질관리팀`, `Payments Platform`) and employers (`Halcyon Freight Systems`, `루미엔바이오`)
  survived in 3 of 3 Airlock runs, as did the names `Samuel Mensah` and `최유진`.
- **Utility is where f0ba569 pays.** Its answers keep 83% of the reference usefulness, better than
  Presidio (66%) and GLiNER-PII (59%) but with 29.3% distortion against a 7.7% floor for raw.
  GLiNER-PII has the lowest linkable disclosure (9.2%) only because it masks aggressively: 59.3% of
  benign cases get masked and its utility ratio is the lowest. Low linkability without utility is
  not the goal.
- **Situation inference drops for f0ba569 and GLiNER-PII** (61-63% vs 86% raw). That is not a
  privacy win to claim. For f0ba569 it comes from generalizing the diagnosis ("a medical
  condition"), which is the same over-redaction that costs utility.
- **In agent mode Airlock answers were judged better, not worse.** Many unguarded answers state
  wrong case facts (dates, amounts, jurisdictions) after long document and search contexts. We
  report it, but do not explain it from this data; the rubric grader of the original run agrees
  in direction (4.44 vs 4.71).

## Where f0ba569's distortions come from

A manual read of the 61 distorted f0ba569 answers (pass 1) puts roughly half on masking itself:

- **"Your value is a placeholder."** About 16: masked secrets, base64 blobs, lab values and trade
  details that the model then declared missing, malformed or undecodable (`adv-ko-03`,
  `hlt-ko-09`, `hlt-en-03`, `fin-en-07`, `fin-en-14`, `sec-en-11`, the `.env` cases).
- **Wrong generalization.** About 11: `1999-05-21` as "in their 30s" (`pii-en-09`), 38 as "30s"
  (`hlt-en-09`), vegetarian and gluten-free as "no dietary restrictions" (`pii-en-11`), lumbar disc
  herniation as "a back pain condition" (`hlt-ko-06`, `hlt-ko-13`), a Seongnam address as "a
  district in Seoul" (`hlt-ko-07`, `hlt-ko-14`), a Puerto Rico ZIP as "South Korea" (`qid-en-02`),
  "2주" as "a short period" (`hlt-ko-03`).
- **Wrong type labels.** About 5: a phone number read back as an affiliation (`adv-ko-02`), a
  seized account as a contact (`fin-ko-13`), a pump serial as a support line (`hlt-en-06`).
- The rest are ordinary model errors or judge calls a human might dispute (invented dates,
  outdated tax rules, one refusal).

## What the detector work (S6) should target

1. **Quasi-identifier generalization** below `identity_k`, especially employer + team + role in
   both languages. It is 15 of 17 linkable cases on the 243 set and the main agent-mode link
   (team and employer names in documents).
2. **Generalization that preserves facts.** Never move a number or place outside its true range
   (ages, dates, cities), keep diagnoses specific when the identity is already masked, keep the
   replacement in the text's language. Reject a generalization that contradicts the original.
3. **Don't mask what the task operates on.** Values the user asks to decode, calculate or
   validate (base64 input, lab values, trade amounts, config keys) are better kept or replaced by
   a typed, same-shape surrogate; a bare placeholder makes the upstream model declare the input
   missing.
4. **Type labels.** A wrong type (`CONTACT` for an account, `ORG` for a runner name) produces
   confidently wrong answers after rehydration.
5. **Korean names in documents and self-introductions**, which still survive in agent runs.

Re-measure with `eval/final_protocol.sh` once the detector settles: linkable disclosure should
fall without utility ratio falling or distortion rising.

## Caveats

- **One attacked and judged pass per system.** No sd is available for the attack and utility
  columns. The baselines are deterministic, so that matters less for them; for Airlock it does.
- **Contrast in the pairwise judge.** The same reference answers got mean usefulness from 4.33 to
  4.57 depending on which system answer they were paired with. The ratio is paired and blind, but
  it is not an absolute scale. The raw row (ratio 1.05, distortion 7.7% vs 10.6% for the
  reference) is the noise floor: identical prompts, different samples.
- **The judge is noisy on distortion.** A pilot showed the one-shot judge calling placeholder
  tokens distortions; a verifier call now confirms every flag (it overturned 10 of 71 for
  f0ba569), but a few questionable flags remain (for example invented dates counted as
  contradictions). One model family plays upstream, attacker, grader and judge; nothing is
  calibrated against human labels.
- **Classification is a judgment call.** Credentials count as identity (a linkable handle to an
  account). A company name alone is not identity in a quasi group, so 10 intent cases that name
  only an employer and a circumstance cannot become linkable disclosures. In agent scenarios a
  city is situation and a street is identity. Different calls would move the numbers; the tables
  in `protected.py` and `fact_classes` make them explicit and testable.
- **Deterministic matching undercounts.** An attacker that translates or paraphrases an identity
  item is not credited, so identity recovery is a lower bound, as before.
- **f0ba569 conditions.** It ran with GPU contention (latency is not usable) and an older detector
  prompt at temperature 0. Baselines have no rehydration, so their judged answers keep
  placeholders, while Airlock's answers were rehydrated.
- **Agent latency and mode differences** are unchanged from the original run notes
  (`eval/agent/results/demo-pre-s6/config.json`).
- **Synthetic data.** Reference answers (`eval/results/_reference_answers/`), baseline replays
  and the attacker send fictional prompts to Token Factory. Never run these tools on real data.

## Cost of this backfill

About 4.8M prompt and 1.8M completion tokens on `nvidia/Nemotron-3-Ultra-550b-a55b` (from the
`usage` records in each `attack/config.json`, `utility/config.json` and the agent reframe
`config.json`, plus about 0.1M for pilots not kept): attacks for regex, GLiNER-PII and f0ba569
(0.72M / 0.25M), situation grades added to the raw and Presidio attacks (0.12M / 0.02M), utility
for five systems (3.37M / 1.49M: 198 new reference answers, 840 baseline answers, 1,040 judge and
382 verifier calls), and agent mode (0.55M / 0.04M).
