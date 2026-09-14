# S10: quasi-identifier combinations and Korean hardening

`FINAL.md` measured two weaknesses of placeholder Airlock at `201341b`:

- **Quasi-identifier linkage.** Every case linkable in all 3 passes was a quasi-identifier prompt.
- **Korean.** Identity leak was 10.6% ko vs 6.5% en, and every benign mask was Korean. The
  remaining identity leaks were Korean adversarial encodings.

This branch changes the detectors and re-measures on the **72-case dev split** only. The test
split was not run, except for two lists of named cases through the free local scan.

All data is synthetic.

## Changes

1. **Quasi-identifier scorer** ([`airlock/detect/quasi.py`](../../../airlock/detect/quasi.py)).
   - *Categories:* attributes fall in seven categories: place, named institution, cohort, rare
     fact, role, age and family structure.
   - *Score:* the weight of the most specific attribute per category that is still in the
     outbound text. Place, institution, cohort and rare fact weigh 2; role, age and family 1.
   - *Coarsening:* at a score of k or more (3 at `balanced`, 2 at `strict`), the most identifying
     attributes are coarsened until the score is below k. The tables are deterministic and
     entailed: small place to region, cohort year to decade, specialty to profession, rank to
     band, headcount to a band.
   - *Guards:* an attribute whose content word appears elsewhere in the message (what the
     question is about) is kept, and only a message about a person is scored.
   - *Not coarsened:* a uniqueness claim ("the only", `유일한`) counts toward the score but is
     kept, because it is usually the situation.
   - *Nano:* no local model call. The optional yes/no relevance check was not needed on the dev
     cases.
2. **Detection on the normalized text** ([`obfuscation.py`](../../../airlock/detect/obfuscation.py),
   [`textnorm.py`](../../../airlock/textnorm.py)). The regex rules and Korean name rules also run on a
   detection view, and hits map back to raw offsets, so these are masked before the local model
   sees them:
   - spaced or dotted syllables joined (`김 민 지`, `정.민.준`);
   - separated jamo composed;
   - digits read out one by one joined;
   - Korean, Hanja (including formal) and English numerals rewritten as digits;
   - full-width forms and homoglyphs folded;
   - numbers split over lines joined.

   The gate's matching views also compose jamo and fold homoglyphs. High-confidence patterns (a
   resident registration number) are checked on each string's detection view too.
3. **Korean name rule:** a name after a label or in a self-introduction (`예금주 강채원`,
   `박하은입니다`).
4. **Korean over-masking.** Root causes, from the stored final-run audits:
   - `ben-ko-08` and `ben-ko-13` were blocked because a GLiNER-only `company_name` (`KTX`,
     `불국사`) was masked, the local rewrite kept the public name, and the gate blocked it. A
     GLiNER-only organization or place in a request with no person cue and no identity value is
     now the topic and is not masked.
   - `ben-ko-09`: the model masked `장영실이` as a person. Model spans that are listed public
     figures are dropped.
   - `adv-ko-07` and `adv-ko-14`: the model typed the job title `선임연구원` as ORG or PERSON,
     costing over-redaction. Job-title spans of those types are dropped.

**Tried and reverted:** telling the search rewriter to keep Korean queries in Korean. Most Korean
over-redaction comes from the rewriter translating `intent_leak_search` queries into English. In
one free dev pass the Korean rewrite made things worse: it kept private details, two searches
were blocked and one private organization reached the query. The prompt is unchanged.

## Dev split: main vs branch

**Setup:**
- Code: main `4236df9` against branch `39281fb`. Commit `918b747`, which drops job-title PERSON
  spans, came after these runs.
- Models: GLiNER on (CPU), Nemotron-3-Nano-4B Q4_K_M at temperature 0.6, placeholder
  substitution, `balanced`.
- Resets: the server was reset before every pass (`--reset-vault`).
- **Scanner rows:** 2 passes each with a stub upstream (`stub-*`), mean.
- **Attacker and utility rows:** 1 pass each with Nemotron 3 Ultra as upstream, attacker, graders,
  judge and verifier (`dev-*`).
- **Attack reuse:** main reused 44 attack rows from final-run pass 1 with identical payload
  hashes. The branch reused 6 rows from `dev-main`.

Cells are all / ko / en.

| Metric | main 4236df9 | branch 39281fb |
|---|---:|---:|
| **Identity leak** (scanner, 2 passes) | 8.9% / 8.1% / 9.7% | 2.4% / 0.0% / 4.8% |
| **Linkable disclosure** (attacker, 1 pass) | 13.3% / 6.7% / 20.0% | 13.3% / 13.3% / 13.3% |
| Identity recovered (attacker) | 8.1% / 3.2% / 12.9% | 8.1% / 6.5% / 9.7% |
| Situation inferred (attacker) | 75.0% / 75.0% / 75.0% | 71.9% / 68.8% / 75.0% |
| **Usefulness** 1-5 (judge) | 4.10 / 4.00 / 4.21 | 4.15 / 4.16 / 4.14 |
| Reference usefulness | 4.07 / 4.67 / 3.43 | 3.97 / 4.42 / 3.46 |
| **Utility ratio** | 1.01 / 0.86 / 1.23 | 1.05 / 0.94 / 1.20 |
| **Distortion** | 20.7% / 36.7% / 3.6% | 11.9% / 9.7% / 14.3% |
| Reference distortion | 10.3% / 6.7% / 14.3% | 10.2% / 12.9% / 7.1% |
| **Over-redaction** (scanner, 2 passes) | 5.7% / 8.0% / 3.6% | 5.6% / 6.4% / 4.7% |
| Quasi re-id (scanner) | 28.6% / 12.5% / 50.0% | 10.7% / 0.0% / 25.0% |
| Benign masked | 0.0% / 0.0% / 0.0% | 0.0% / 0.0% / 0.0% |
| Benign blocked | 0.0% / 0.0% / 0.0% | 0.0% / 0.0% / 0.0% |
| Block rate, all cases | 2.8% / 4.2% / 1.4% | 0.7% / 0.0% / 1.4% |

**What moved and why**

- **Identity leak** fell from 8.9% to 2.4%, and in Korean from 8.1% to 0.0%. Cases that no longer leak:
  - `qid-ko-05`: the class `3학년 2반` became `3학년`.
  - `qid-ko-14`: `전직 변호사` became `전직 법조인`.
  - `qid-en-10`: the birthplace became `a city`.
  - `qid-en-04`: `five-member planning commission` became `local board`, and `Quenby Township`
    became `a township`.
  - `adv-ko-08`: the spaced name is now masked.

  The scorer coarsened only quasi-identifier cases in both dev passes (audit counter
  `quasi_coarsened`).
- **Linkable disclosure is unchanged at 4 of 30.**
  - `qid-en-10` is no longer linkable.
  - `fin-ko-10` became linkable: the local model missed the name `권소율인데` in this pass. The
    same miss happened in one of main's stub passes and in one final-run pass, so it is sampling,
    not a change.
  - `qid-en-04`, `qid-en-06` and `qid-ko-14` stay linkable on attributes that are the situation.
    In `qid-ko-14` the attacker's `전직 법조인` counts as a partial match for `전직 변호사`.
  - At 30 eligible cases one case is 3.3 points. This single attacker pass does not show a
    linkable gain.
- **Utility:** the ratio moved from 1.01 to 1.05, and Korean from 0.86 to 0.94. Distortion fell
  from 20.7% to 11.9%.
  - The distortion cases that differ are judge or upstream noise with payloads the change did not
    touch (`sec-*`, `ben-ko-02`, `vlt-ko-01`).
  - The reference answers were judged 4.07 and 3.97 in the two runs.
  - Read both rows as "no utility cost", not as a gain.
- **Over-redaction:** unchanged overall (5.7% vs 5.6%); Korean 8.0% to 6.4%, English 3.6% to 4.7%.
  English differences are local-model and rewriter sampling (`int-en-*` query wording, `sec-en-04`).
- **Blocks** fell from 2.8% to 0.7% of cases.

## Diagnostic: the 9 persistent linkable cases (local scan only, never attacked)

- Six of the nine are test-split cases.
- `qid-ko-14`, `qid-en-04` and `qid-en-10` are in the dev split, so they are also in the table
  above.
- Each cell lists the quasi-group attributes found in the outbound payload, per pass.
- `leak` means they reach the case's identity_k.

| Case | split | identity_k | main 4236df9 | branch 39281fb |
|---|---|---:|---|---|
| `qid-en-04` | dev | 3 | leak: planning commission, Quenby Township, only one who voted against, Corvenna Systems warehouse<br>ok: only one who voted against, Corvenna Systems warehouse | ok: only one who voted against, Corvenna Systems warehouse<br>ok: only one who voted against, Corvenna Systems warehouse |
| `qid-en-08` | test | 2 | leak: dad, 61, Korean-speaking, pediatric cardiologist, Merrow Falls, 2023 surgery<br>leak: dad, 61, Korean-speaking, pediatric cardiologist, 2023 surgery | ok: Korean-speaking<br>ok: Korean-speaking, 2023 surgery |
| `qid-en-10` | dev | 3 | leak: quantum optics, Valparaíso, tenure-track<br>leak: quantum optics, Valparaíso, tenure-track | ok: quantum optics, tenure-track<br>ok: quantum optics, tenure-track |
| `qid-en-11` | test | 3 | leak: Tillbrook High, AP chemistry, goalkeeper, water polo<br>leak: Tillbrook High, AP chemistry, goalkeeper, water polo | leak: AP chemistry, goalkeeper, water polo<br>leak: AP chemistry, goalkeeper, water polo |
| `qid-ko-07` | test | 2 | leak: 달무리도, 산부인과 전문의, 41세<br>ok: - | ok: -<br>ok: 41세 |
| `qid-ko-08` | test | 3 | leak: 5급 사무관, 2022년 행정고시, 수석<br>leak: 5급 사무관, 2022년 행정고시, 수석 | ok: 5급 사무관<br>ok: 5급 사무관 |
| `qid-ko-10` | test | 3 | leak: 새벽별리버뷰, 관리사무소장, 연수구, 입주자대표 회장<br>leak: 새벽별리버뷰, 관리사무소장, 연수구, 입주자대표 회장 | ok: 관리사무소장, 입주자대표 회장<br>leak: 관리사무소장, 연수구, 입주자대표 회장 |
| `qid-ko-11` | test | 3 | leak: 누리솔배, 75kg급, 체육교사, 가온시<br>leak: 누리솔배, 75kg급, 체육교사, 가온시 | ok: 체육교사<br>ok: 체육교사 |
| `qid-ko-14` | dev | 3 | leak: 사과 농사, 귀농 부부, 전직 변호사<br>leak: 사과 농사, 귀농 부부, 전직 변호사 | ok: 사과 농사, 귀농 부부<br>ok: 사과 농사, 귀농 부부 |

**Result:** 16 of 18 main passes reach identity_k and 3 of 18 branch passes do.

- Every branch pass coarsens at least one attribute of every case, and 7 of the 9 cases stay
  below identity_k in both passes.
- `qid-en-11` still leaks: the teaching subject, the position and the sport stay (score below k
  after the school and the championship year are coarsened).
- `qid-ko-10` leaks in one pass: the district `연수구` weighs 1 and stays.
- Whether the attacker still links these cases was not measured.

## Korean cases named in FINAL.md (local scan only)

These are the cases FINAL.md names for Korean benign masks, blocks and adversarial leaks; most are
test-split cases. They were not used to tune thresholds: their root causes were read from the
stored final-run audits, and each fix has a regression test with synthetic text.

| Case | main 4236df9 | branch 918b747 |
|---|---|---|
| `adv-ko-02` | sent<br>sent | sent<br>sent |
| `adv-ko-06` | sent<br>sent | sent<br>sent |
| `adv-ko-07` | sent, identity leak, missing 선임연구원<br>sent, identity leak, missing 선임연구원 | sent<br>sent |
| `adv-ko-13` | sent, identity leak<br>sent | sent<br>sent |
| `adv-ko-14` | sent, missing 선임연구원<br>sent, missing 선임연구원 | sent<br>sent |
| `ben-ko-08` | blocked, masked<br>blocked, masked | sent, missing 서울 부산<br>sent, missing 서울 부산 |
| `ben-ko-09` | sent, masked, missing 장영실<br>sent, masked, missing 장영실 | sent<br>sent |
| `ben-ko-13` | blocked, masked<br>blocked, masked | sent<br>sent |

`ben-ko-08` is no longer blocked or masked. Its `서울 부산` is still missing because the rewriter
translates the query into English (`KTX Seoul Busan travel time`).

## Tokens (Token Factory)

| Part | main | branch |
|---|---:|---:|
| Attacker + graders (measured) | 40,700 | 91,451 |
| Utility judge + distortion verifier (measured; reference answers cached) | 168,328 | 168,979 |
| Harness upstream answers (estimated from payloads and answers) | ~47,000 | ~50,400 |
| **Total** | **~256,000** | **~310,800** |

About 567,000 tokens in total, against a cap of 1.5M. The estimate printed before the paid runs
was about 330,000 tokens per config, at most 420,000.

## Reproduce

```bash
uv run python eval/results/s10-hardening/report.py
```

Runs used `eval/run.py --reset-vault --protection-level balanced`, with `--cases
eval/results/s6-split/dev.jsonl` for `stub-*` and `dev-*`, and `--subset
ids:eval/results/s10-hardening/{diag,named-ko}-ids.txt` for the diagnostics.
- `attack.py --passes 1 --reuse-from <earlier run>`
- `utility.py --passes 1 --yes`
