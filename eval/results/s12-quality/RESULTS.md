# S12: demo recording quality, common nouns as names, slot-fitted generalizations

Two quality issues were visible in the recorded demo runs, plus one precision problem from the
S10 report. This branch fixes them at the root and re-measures on the **72-case dev split** with
the free local scan only. No cloud scoring was run; the only cloud calls were the two
re-recordings (40 Token Factory and Tavily calls, cap 100).

All data is synthetic.

## Root causes and fixes

1. **Common Korean nouns masked as PERSON** (`agent-resignation-ko` sent the search
   `<PERSON_8> 수급 자격 <PERSON_7>법`). The audit of the recording lists the PERSON masks with
   source `llm`: the cloud detector (Nemotron 3 Nano 30B in the hosted demo) proposed `실업급여`
   and `고용보험` as people, and the only shape check on a model PERSON span
   ([`shape.py`](../../../airlock/detect/shape.py)) was "fewer than four digits". The Korean
   honorific rule was not involved (it needs a title after the name), and GLiNER is off in the
   demo, but GLiNER's `ko_name` accepted the same words (`연말정산` as `user_name` was remapped to
   PERSON and adjudicated yes on main in `fin-ko-10`).

   Fix, structural first ([`ko_rules.plausible_name`](../../../airlock/detect/ko_rules.py)):
   a Hangul PERSON span must be 2-4 syllables per name, start with a surname syllable (a
   compound surname at four syllables, so `고용보험`, `연차수당`, `권고사직` fail), and not end
   in a syllable that ends nouns but never given names (`증`, `법`, `사`, `급`, `률`, ...: `자격증`,
   `근로기준법`, `노무사`, `실업급여`). Endings that real names share (`원`, `서`, `진`, `자`, `금`,
   `실`) are deliberately not in that set. A short last-resort list covers legal and HR nouns
   that pass every structural check (`위로금`, `배우자`, `고용주`). The same shape is applied to
   the GLiNER ensemble's `ko_name`. Bare given names (`예진`, `다은`) stay accepted.
2. **Awkward text after generalization** (`chat-medical-en` sent "I'm age"). The model proposed
   the bare `34` with a free-form replacement, and [`generalize.py`](../../../airlock/generalize.py)
   only recognized an age when its unit was inside the span, so nothing checked it. Now a bare
   number in an age slot (after a copula or "aged", before "살"/"세"/"years old") is an age, the
   span takes in its unit or cue, and the phrase is built for the slot: `I'm 34` → `I'm in my
   30s`, `she's 34` → `she's in her 30s`, `a 34-year-old` → `a 30-something`, `I turned 52` →
   `I am in my 50s`, `34살입니다` → `30대입니다`, `만 34세` → `30대`, `born in 1992` → `born in
   the 1990s`, `1992년생` → `1990년대생`, `DOB: 1999-05-21` → `DOB: the 1990s`. Small places
   were already slot-safe (`성남시` → `경기도의 한 도시`, `Duluth` → `a city in Minnesota`) and
   are covered by tests.
3. **Korean search rewrite keeping an organization in a generic query.** The S10 fix (a
   GLiNER-only organization or place in a request about nobody is the topic) holds: the three
   `ben-ko` search cases go out unmasked in both passes (table below). No further change.

Tests: `tests/test_ko_rules.py` (20 legal/HR terms never a name, 19 names still a name, a Korean
search that keeps its terms, an HR document that masks only the employee),
`tests/test_distortion.py` (en/ko age, birth year, birth date and small-place slots).

## Dev split: main vs branch

**Setup:** main `d97a815` against branch `9bcc1d5`. GLiNER on (CPU), Nemotron-3-Nano-4B
Q4_K_M at temperature 0.6, placeholder substitution, `balanced`, server reset before every
pass (`--reset-vault`), 2 passes each with a stub upstream and stub Tavily (no cloud calls).
Cells are all / ko / en. `uv run python eval/results/s12-quality/report.py` rebuilds the tables.

| Metric | main d97a815 | branch |
|---|---:|---:|
| **Identity leak** (scanner, 2 passes) | 2.4% / 0.0% / 4.8% | 4.8% / 3.2% / 6.5% |
| Leak rate, cases (scanner) | 0.8% / 0.0% / 1.6% | 4.7% / 3.1% / 6.2% |
| Quasi re-id (scanner) | 3.6% / 0.0% / 8.3% | 14.3% / 0.0% / 33.3% |
| **Over-redaction** (scanner, 2 passes) | 5.9% / 6.5% / 5.3% | 5.0% / 3.5% / 6.7% |
| Benign masked | 0.0% / 0.0% / 0.0% | 0.0% / 0.0% / 0.0% |
| Benign blocked | 0.0% / 0.0% / 0.0% | 0.0% / 0.0% / 0.0% |
| Block rate, all cases | 0.7% / 1.4% / 0.0% | 1.4% / 0.0% / 2.8% |

Benign: 0 of 8 masked and 0 blocked per pass on both. Korean over-redaction fell from 6.5% to
3.5%.

**The identity-leak and quasi re-id rows moved, so every differing case was checked.** Six
cases differ between the two dev runs:

- `adv-en-11`, `pii-en-07` (branch blocked once): Nano returned malformed output
  (`local_detector_malformed:length`, `:repetition`); fail-closed, no code path of this branch.
- `adv-ko-08` (branch leaked once): the spaced RRN `7 3 1 5 2 1 - 1 3 8 5 8 3 5` is found only
  by Nano on both checkouts. The normalized view joins it correctly, but the synthetic value fails
  the RRN checksum, so the deterministic rule does not fire. Pre-existing; Nano missed it in one
  branch pass.
- `fin-ko-10` (branch leaked once): `권소율` comes only from Nano, which missed it in one pass
  (the S10 report records the same miss on main). On main the case also masked `연말정산`
  (year-end tax settlement) as `<PERSON_1>` through GLiNER; the branch no longer does.
- `qid-en-05`, `qid-en-06` (branch re-identified in both passes): Nano proposed nothing for
  these prompts in the branch passes and 3-5 spans in main's. Nothing in the branch touches the
  model input; the rule spans are identical.

To separate sampling from the change, the four leak cases were rerun 4 passes each on both
checkouts against the same llama-server, minutes apart:

| Case | main: identity leaks / blocks / Nano proposals per pass | branch |
|---|---|---|
| `adv-ko-08` | 0/4 / 2 / 2 0 1 0 | 0/4 / 0 / 2 3 2 2 |
| `fin-ko-10` | 1/4 / 0 / 4 4 6 4 | 0/4 / 0 / 5 6 5 5 |
| `qid-en-05` | 4/4 / 0 / 0 0 0 0 | 3/4 / 0 / 0 4 0 0 |
| `qid-en-06` | 4/4 / 0 / 0 0 0 0 | 4/4 / 0 / 0 0 0 2 |

On the same cases main leaks as much or more. Nano's proposals for the two `qid-en` prompts
come and go between sessions (8 of 8 main passes here had none; main's dev run had them in
both), and that alone decides the quasi re-id row for the 4 English quasi-identifier cases
(each is 25% of the en cell). Read the dev-split identity and quasi rows as detector sampling;
the branch shows no regression on any case it touches.

## Benign Korean searches (branch, local scan only)

| Case | pass | sent | masking detections | outbound query |
|---|---|---|---:|---|
| `ben-ko-05` | 1 | sent | 0 | 2026 minimum wage rate |
| `ben-ko-08` | 1 | sent | 0 | KTX Seoul Busan travel time |
| `ben-ko-13` | 1 | sent | 0 | 경주 불국사 석굴암 2일 여행 코스 |
| `ben-ko-05` | 2 | sent | 0 | 2026 minimum wage hourly |
| `ben-ko-08` | 2 | sent | 0 | KTX Seoul Busan travel time |
| `ben-ko-13` | 2 | sent | 0 | 경주 불국사 석굴암 2일 여행 코스 |

## Re-recorded demo presets

`scripts/demo/record_presets.py --max-cloud-calls 100 chat-medical-en agent-resignation-ko`
against a demo server with the cloud detector backend. Both accepted on the first attempt, 40
cloud calls in total, 0 private values in the outbound payloads (1 and 18 payloads).

- `chat-medical-en`: the cloud text now reads "I'm in my 30s and was just diagnosed with type 1
  diabetes at <ORG_1>" (was "I'm age").
- `agent-resignation-ko`: 3 searches, all rewritten and sent, none blocked (was 2 rewritten, 1
  blocked); the only PERSON placeholder in any outbound text is `<PERSON_1>`, the employee (the
  last recording sent `<PERSON_8> 수급 자격 <PERSON_7>법`).
