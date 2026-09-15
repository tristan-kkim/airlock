# Final measurement: Airlock against four baselines

Three runs, all made with `eval/final_protocol.sh` on all 243 cases, 3 passes:

| Run | Airlock config | Commit | Passes independent? | Log |
|---|---|---|---|---|
| `final-20260915T023627Z/` | **placeholder (default)**, GLiNER on | `eb311ed` (S10 hardening + S12 quality fixes) | **yes**: server reset before every pass | `final-run4.log` |
| `final-20260914T100907Z/` | placeholder, GLiNER on | `201341b` | yes | `final-run3.log` |
| `final-20260914T004056Z/` | placeholder and surrogate, GLiNER on | `e0ee6aa` | **no**: reset only before pass 1 | `final-run.log` |

```bash
eval/final_protocol.sh --commit eb311ed --gliner on --substitution placeholder --passes 3 \
  --reuse-committed --publish --systems "raw regex presidio_ko gliner_pii airlock" --yes
```

- **Airlock placeholder row:** from the run at `eb311ed` on 2026-09-15, the current `main`. Since
  the previous independent run (`201341b`, reported in commit `4236df9`) the detector gained the
  S10 hardening (k-anonymity-style coarsening of quasi-identifier combinations, detection on the
  normalized text for Korean adversarial encodings, fewer Korean benign masks, a job title alone
  is never a PERSON span) and the S12 quality fixes (a plausible-Korean-name check on model and
  GLiNER PERSON spans, slot-fitted age and birth generalizations). See *What changed since
  `4236df9`*.
- **Airlock surrogate row:** from the run at `e0ee6aa`, an older detector. Its passes are not
  independent (see *Pass independence*), so its ± is not a measured spread. Surrogates were not
  rerun; the row is kept for the substitution decision only.
- **Dataset:** 243 cases (122 Korean, 121 English; 210 chat, 33 search), SHA-256
  `cd40ce70...850609`. Linkable disclosure is scored on the 98 situation-sensitive cases that
  carry identity items (finance 27, health 27, quasi-identifier 27, intent search 17).
- **Baselines:** raw, regex, presidio_ko and gliner_pii ran again in this run and sent the same
  payloads as the committed runs (hash-verified, 243 of 243 cases each). Their attack rows and
  623-624 of 630 utility rows were reused from `eval/results/baseline-<name>`; the remaining
  6-7 utility rows per baseline (25 in all) were scored fresh.
- **Scoring:** attacker, intent and situation graders, utility judge and distortion confirmation
  all on Nemotron 3 Ultra (`JUDGE_CALIBRATION.md`); reference answers from the committed cache.
- **Isolation:** systems ran one after another, with exactly one `llama-server`
  (Nemotron-3-Nano-4B Q4_K_M, temperature 0.6) during the Airlock run and none during the
  baselines. Machine: Apple M3 Pro, 18 GB; GLiNER ran on CPU inside the Airlock process.

Full tables: [`COMPARISON.md`](COMPARISON.md).

## Headline

Mean ± sample sd over 3 passes. Baseline outputs were identical across passes and scored once, so
their ± 0.0 does not measure scoring noise. † marks passes that were not independent. Lower is
better except usefulness and utility ratio.

| System | **Linkable disclosure** | Identity leak (scanner) | Identity recovered (attacker) | Situation inferred | Usefulness 1-5 (reference) | Utility ratio | Distortion (reference) | Over-redaction | Benign masked | Over-block benign |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| raw (pass-through) | 84.7% | 98.5% | 94.7% | 86.1% | 4.52 (4.33) | 1.05 | 7.7% (10.6%) | 0.0% | 0.0% | 0.0% |
| regex only | 79.6% | 92.7% | 88.8% | 80.6% | 3.91 (4.49) | 0.87 | 13.9% (10.1%) | 0.4% | 7.4% | 0.0% |
| Presidio + ko/en spaCy + KR recognizers | 53.1% | 76.7% | 73.8% | 77.8% | 3.01 (4.54) | 0.66 | 33.7% (6.7%) | 16.7% | 66.7% | 0.0% |
| NVIDIA GLiNER-PII alone | 9.2% | 18.9% | 19.4% | 63.0% | 2.69 (4.57) | 0.59 | 24.5% (4.8%) | 14.1% | 59.3% | 0.0% |
| **Airlock, placeholder (default)** | **7.5% ± 0.6** | 3.1% ± 0.3 | 4.4% ± 0.0 | 71.6% ± 2.8 | 4.15 ± 0.04 (4.38) | 0.95 ± 0.01 | 14.9% ± 3.0 (10.0%) | 5.3% ± 0.4 | 0.0% ± 0.0 | 0.0% ± 0.0 |
| Airlock, surrogate † (`e0ee6aa`) | 12.6% | 8.3% | 7.8% | 54.0% | 4.08 (4.35) | 0.94 | 19.4% (10.0%) | 6.4% | 11.1% | 7.4% |

Placeholder, other rates:

| Metric | Mean ± sd |
|---|---:|
| Case leak rate, any planted value (scanner) | 2.9% ± 0.3 |
| Canary leak | 0.0% ± 0.0 |
| Quasi re-identification (scanner) | 11.3% ± 2.3 |
| Quasi re-identification (attacker, exact or partial attributes) | 18.0% ± 2.0 |
| Planted values recovered by the attacker, full / full or partial | 0.1% ± 0.1 / 2.1% ± 0.4 |
| Block rate, all cases | 2.6% ± 0.2 |

**Latency, placeholder, local overhead (total minus cloud calls), per pass:**

| Pass | Overhead p50 / p95 | Local detect p50 / p95 | GLiNER p50 |
|---|---:|---:|---:|
| 1 | 4,365 / 10,692 ms | 3,632 / 8,963 ms | 470 ms |
| 2 | 4,111 / 8,588 ms | 3,608 / 7,778 ms | 494 ms |
| 3 | 4,061 / 8,856 ms | 3,378 / 8,188 ms | 604 ms |
| Mean ± sd | 4,179 ± 163 / 9,379 ± 1,145 ms | | |

Pass 1 carries the warm-up (first GLiNER and health-entailment calls), which is where its wider
p95 comes from. Baseline overhead p50 / p95 in the same run: raw and regex 0 / 0 ms, Presidio
2 / 4 ms, GLiNER-PII (on MPS) 78 / 147 ms.

**Attacker sampling variance** (separate from the detector-pass sd above): see *Attacker
sampling variance* below.

### What the table says

- **Linkable disclosure is 7.5%, and every persistent case is a quasi-identifier prompt.** Over
  the 3 passes, placeholder Airlock had 0 linkable cases in finance and health, one intent search
  in one pass (`int-en-07`), and 7 of 27 quasi-identifier cases in every pass. GLiNER-PII alone:
  finance 1, health 1, intent 0, quasi-identifier 7.
- **Against raw pass-through**, Airlock cuts linkable disclosure from 84.7% to 7.5% and identity
  leak from 98.5% to 3.1%, at a utility ratio of 0.95. Distortion is 14.9% against 10.0% for the
  reference answers judged in the same run.
- **Airlock now links less than GLiNER-PII alone (7.5% vs 9.2%)** while keeping a utility ratio
  of 0.95 against 0.59. GLiNER-PII masks 59.3% of benign prompts and scores 2.69 for usefulness.
- **Benign cost is zero in this run:** no benign case was masked or blocked in any pass (the two
  Korean benign searches `ben-ko-08` and `ben-ko-13` that were blocked in every pass at
  `201341b` now go out unmasked). Over-redaction is 5.3%, most of it in the intent-search cases
  where the rewrite drops `must_keep` terms by design (59.5% in that category, under 4% in every
  other).

## What changed since `4236df9`

`4236df9` reported the independent run at `201341b`. The detector at `eb311ed` adds S10 and S12.
Both runs are independent (reset before every pass), same dataset, same scoring models, so the
differences below are detector changes plus sampling noise.

| Metric | `201341b` (previous) | `eb311ed` (this run) | Change |
|---|---:|---:|---:|
| Linkable disclosure | 13.9% ± 0.6 | **7.5% ± 0.6** | −6.4 pt |
| Identity leak (scanner) | 8.6% ± 0.7 | 3.1% ± 0.3 | −5.5 pt |
| Identity recovered (attacker) | 8.4% ± 0.6 | 4.4% ± 0.0 | −4.0 pt |
| Situation inferred | 72.8% ± 1.1 | 71.6% ± 2.8 | unchanged (by design) |
| Quasi re-identification (scanner) | 28.7% ± 2.3 | 11.3% ± 2.3 | −17.4 pt |
| Usefulness (reference in the same run) | 4.16 ± 0.03 (4.40) | 4.15 ± 0.04 (4.38) | unchanged |
| Utility ratio | 0.95 ± 0.01 | 0.95 ± 0.01 | unchanged |
| Distortion (reference in the same run) | 15.2% ± 1.4 (7.7%) | 14.9% ± 3.0 (10.0%) | unchanged; reference moved |
| Over-redaction | 7.1% ± 1.3 | 5.3% ± 0.4 | −1.8 pt |
| Benign masked / over-blocked | 11.1% / 7.4% | 0.0% / 0.0% | −11.1 / −7.4 pt |
| Overhead p50 / p95 (3-pass mean) | 4,004 / 8,771 ms | 4,179 / 9,379 ms | +175 / +608 ms |

By language:

| | `201341b` ko | `eb311ed` ko | `201341b` en | `eb311ed` en |
|---|---:|---:|---:|---:|
| Identity leak | 10.6% ± 1.0 | **2.6% ± 0.6** | 6.5% ± 0.6 | 3.6% ± 0.6 |
| Linkable | 14.0% ± 3.5 | **6.7% ± 1.2** | 13.9% ± 2.4 | 8.3% ± 0.0 |
| Utility ratio | 0.86 ± 0.02 | 0.88 ± 0.02 | 1.04 ± 0.04 | 1.03 ± 0.02 |
| Distortion | 17.0% ± 3.1 | 17.6% ± 2.3 | 13.3% ± 2.1 | 12.1% ± 3.8 |
| Over-redaction | 10.0% ± 1.9 | 7.5% ± 1.0 | 4.3% ± 1.1 | 3.1% ± 0.7 |
| Benign masked | 23.1% | 0.0% | 0.0% | 0.0% |

- **Where the gain is.** The quasi-identifier coarsening is what moved linkable disclosure: the
  persistent linkable set went from 9 cases to 4, and the cases linkable in at least one pass
  from 18 to 12. Korean gained more than English (identity leak 10.6% → 2.6%, linkable 14.0% →
  6.7%), because the Korean adversarial encodings (`adv-ko-07`, `-13`, `-06`, `-02`, `-14`) that
  leaked names and card numbers at `201341b` are now detected on the normalized text. English
  still carries 5 of the 7 quasi-identifier cases that link per pass.
- **What did not move.** Situation inference (71.6% vs 72.8%), usefulness (4.15 vs 4.16), the
  utility ratio (0.95) and distortion (14.9% vs 15.2%) are within one sd of the previous run. The
  distortion gap above the same-run reference is 4.9 points now against 7.5 before, but the
  reference itself moved from 7.7% to 10.0% between runs, which is the judge's noise, not the
  detector's.
- **What got slightly worse.** Local overhead is up about 0.2 s at p50 and 0.6 s at p95 (the
  coarsening adds work on quasi-identifier prompts, and pass 1 had a 10.7 s p95). Korean
  distortion is 17.6% against 17.0% (within sd). The attacker's quasi re-identification on English
  is 24.6% against Korean 12.3%: the English quasi-identifier cases are now the weakest category.
- **Not a held-out estimate.** S10 was tuned against the 9 persistent linkable cases of the
  previous run and the 72-case dev split, and S12 against the dev split; all of those are part of
  these 243 cases. The 4 remaining persistent cases were not targeted by name.

## Pass independence

The run summary reports the independence check (`eval/scoring.py`, `independence_check`): the
share of cases whose outbound payloads are byte-identical in all passes, and the local detect
time p50 per pass. The detector samples at temperature 0.6. A detection served from Airlock's
in-memory cache is almost free, so a sharp drop in detect time after pass 1 is the reliable
signature of a cache.

| Run | Byte-identical payloads, all 3 passes | Detect p50 by pass | Independent |
|---|---:|---|---|
| Placeholder `eb311ed`, reset before every pass | 138 of 232 cases (59.5%) | 3,632 / 3,608 / 3,378 ms | yes |
| Placeholder `201341b`, reset before every pass | 130 of 231 cases (56.3%) | 3,463 / 3,409 / 3,375 ms | yes |
| Placeholder `e0ee6aa`, reset before pass 1 only | 211 of 232 cases (90.9%) | 3,412 / 462 / 475 ms | no |
| Surrogate `e0ee6aa`, reset before pass 1 only | 70 of 231 cases (30.3%) | 3,270 / 506 / 571 ms | no |

Nemotron-3-Nano-4B repeats more than half of its outputs exactly when it really re-runs, mostly
on short prompts. Surrogates are re-drawn per conversation, so a cached run can still show few
identical payloads. The harness therefore warns on the detect-time drop, and on identical
payloads only above 85%.

## Attacker sampling variance

The ± on the attacker columns above is the spread across three detector passes, each attacked
once, so it mixes detector sampling with attacker and grader noise. To separate them, the pass-1
audits of this run were attacked two more times with the same attacker and graders
(`eval/attack.py --rescore <dir> --passes 1 --out-name attack-resample-{2,3}`, stored next to
`attack/`), giving three attacker draws over byte-identical payloads. The attacker and the
graders are called at `temperature: 0` (`eval/attack.py`, `request_body`), so this is the
provider's residual nondeterminism at temperature 0 plus the one-time `reasoning_effort=low`
retry on empty replies, not a temperature-sampling spread; it is a floor for the attacker's
variance, not an estimate of what a differently seeded attacker would do.

| Pass-1 payloads, 3 attacker draws | Draw 1 / 2 / 3 | Mean ± sd (attacker sampling) | Detector-pass sd, for comparison |
|---|---|---:|---:|
| Linkable disclosure (98 cases) | 8.2 / 8.2 / 8.2% | 8.2% ± 0.0 | ± 0.6 |
| Identity recovered (206 cases with identity items) | 4.4 / 4.4 / 4.4% | 4.4% ± 0.0 | ± 0.0 |
| Quasi re-identification, attacker (50 cases) | 18.0 / 18.0 / 18.0% | 18.0% ± 0.0 | ± 2.0 |
| Situation inferred (105 graded cases) | 74.3 / 72.4 / 74.3% | 73.7% ± 1.1 | ± 2.8 |

The same 8 cases were linkable in all three draws (`int-en-07`, `qid-ko-02`, `-04`, `-10`,
`-14`, `qid-en-04`, `-06`, `-11`) and no other case in any draw: at temperature 0 the attacker's
identity extraction is stable on these payloads, and the only moving part is the situation
grader (about 1 point). The spread in the headline table therefore comes from the detector's
sampling, not from the attacker. Cost of the two extra draws: 502,621 prompt + 147,381
completion tokens, about $0.95; 2 min 40 s each.

## By language (placeholder, `eb311ed`)

| | Identity leak | Linkable | Situation inferred | Usefulness | Utility ratio | Distortion | Over-redaction | Benign masked |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Korean | 2.6% ± 0.6 | 6.7% ± 1.2 | 71.5% ± 3.8 | 4.03 ± 0.04 | 0.88 ± 0.02 | 17.6% ± 2.3 | 7.5% ± 1.0 | 0.0% |
| English | 3.6% ± 0.6 | 8.3% ± 0.0 | 71.7% ± 1.9 | 4.27 ± 0.06 | 1.03 ± 0.02 | 12.1% ± 3.8 | 3.1% ± 0.7 | 0.0% |

Surrogate † for reference: identity leak 8.7% / 7.8%, linkable 10.7% / 14.6%, utility ratio 0.88 /
1.01, distortion 21.9% / 16.9% (ko / en).

- **Korean still costs more on utility:** utility ratio 0.88 vs 1.03, over-redaction 7.5% vs
  3.1%, distortion 17.6% vs 12.1%. The reference answers score higher in Korean (4.58 vs 4.17), so
  part of the ratio gap is the reference, not the answer.
- **Korean now leaks less than English:** identity leak 2.6% vs 3.6%, linkable 6.7% vs 8.3%. At
  `201341b` it was the other way round for identity leak (10.6% vs 6.5%).
- **No benign mask in either language** (13 Korean and 14 English benign cases, 3 passes).

## Persistent failures (placeholder, `eb311ed`)

**Linkable in all 3 passes, 4 cases:** `qid-en-06`, `qid-en-11`, `qid-ko-10`, `qid-ko-14`.
12 cases were linkable in at least one pass: 11 quasi-identifier prompts and one intent search
(`int-en-07`, pass 1 only). Per pass, 7 / 7 / 7 quasi-identifier cases linked. In all 4 persistent
cases the scanner also counts an identity leak (the quasi attributes reach `identity_k`), and the
attacker returned the attributes verbatim or lightly paraphrased:

1. **`qid-en-06`:** former CFO of a small Colorado business that closed in January 2025 after the
   founder's DUI. Role, state, month and event all reach the cloud; none is generalized.
2. **`qid-en-11`:** AP chemistry teacher at a Georgia high school who was goalkeeper on the
   school's state-champion water polo team. The school name (`Tillbrook High`) is now masked,
   but subject + state + the team fact still single the person out.
3. **`qid-ko-10`:** `인천 연수구 <LOCATION_1> 아파트 관리사무소장`. The apartment complex is masked,
   the district (`연수구`) and the role (`관리사무소장`) are kept.
4. **`qid-ko-14`:** `경상북도 군 지역`, `사과 농사`, `30대 귀농 부부`, `남편이 전직 법조인`. The
   profession was generalized (`변호사` → `법조인`), the region coarsened to the province, and the
   combination still reaches k.

Compared with `201341b`: `qid-ko-07`, `-08`, `-11` and `qid-en-04`, `-08`, `-10` dropped out of the
persistent set (ranks, cohorts and small places such as `2022년 행정고시 수석`, `달무리도`, `가온시`,
`75kg급`, `Valparaíso` are now coarsened); `qid-en-06` joined it (linkable 2 of 3 passes before).
Closing the remaining four means generalizing one more attribute of the combination (a district,
a month, a team fact) even when each looks harmless alone, against the utility that the
situation-keeping rules bought in S6 and S9.

**Identity leaks outside the quasi-identifier category (scanner):** two, in one pass each:

- `adv-ko-08` (pass 1): a resident registration number.
- `adv-ko-14` (pass 1): an e-mail address.

The Korean adversarial names and card numbers that leaked at `201341b` (`adv-ko-07` in every
pass, `adv-ko-13`, `-06`, `-02`, `-14` in some) did not leak in any pass. `fin-ko-10` (a Korean
name sent verbatim at `201341b`) did not leak either.

**Blocks:** 11 cases were blocked in at least one pass; 3 in every pass (`adv-en-04`,
`int-en-03`, `int-en-11`). No benign case was blocked. Intent-search block rate 13.6% ± 5.7
(18.5% at `201341b`).

## Default: placeholder

The rule set before the measurement: keep placeholders unless surrogates are clearly better on
linkable disclosure without worse distortion. The surrogate row is from the older detector at
`e0ee6aa` and was not rerun, so it is not a like-for-like comparison anymore; on that older
detector, surrogates linked 1.3 points less than placeholders (12.6% vs 13.9%) and distorted
4.2 points more (19.4% vs 15.2%), with lower usefulness (4.08 vs 4.16) and lower situation
inference (54.0% vs 72.8%). At `eb311ed` placeholders link 7.5%, below the surrogate row's 12.6%.
Placeholder stays the default; `AIRLOCK_SUBSTITUTION=surrogate` remains available and would need
its own independent run before any claim about the current detector.

## Agent mode (same commit)

The agent-mode evaluation (`eval/agent/run_agent_eval.py`, 16 scenarios × 2 modes × 3 passes)
was rerun at `eb311ed` on 2026-09-15 with one `llama-server` alone on the GPU, and reframed
with `eval/reframe.py agent`. Full tables: `eval/agent/results/demo/` (the `d2ff994` run is
kept in `eval/agent/results/demo-pre-s6/`); the reframed table is also in `COMPARISON.md`.

| Metric | unguarded | Airlock `eb311ed` | Airlock `d2ff994` |
|---|---:|---:|---:|
| Private facts recovered, all hops | 82.3% ± 2.8 | **23.6% ± 3.2** | 41.3% ± 4.2 |
| Identity leak (scanner) | 95.8% ± 3.6 | 33.3% ± 9.5 | 77.1% ± 3.6 |
| Linkable disclosure | 83.3% ± 3.6 | **17.2% ± 8.2** | 68.8% ± 6.2 |
| Situation inferred (no anchor needed) | 87.5% ± 6.2 | 87.1% ± 6.9 | 93.8% ± 6.2 |
| Utility, rubric grader (1-5) | 4.38 ± 0.29 | 4.50 ± 0.49 | 4.71 ± 0.18 |
| Utility ratio, pairwise judge | | 1.09 ± 0.12 | 1.10 ± 0.05 |
| Runs finished | 100% | 93.8% ± 6.2 | 100% |
| Latency per run, median | 24 s | 216 s | 367 s (GPU shared) |

The unguarded column is from the same run (the `d2ff994` unguarded numbers were 87.2%, 97.9%,
89.6%, 93.8%, 4.44). Three guarded runs ended `blocked` without an answer (two `pregnancy-en`:
a search result page contained vaulted health words; one `debt-en`: local detector repetition
loop), which is where the English utility deficit (4.50 vs 5.00) comes from. Cost: attacker and
graders 979,519 + 154,279 tokens ($1.44), reframe 427,791 + 26,110 ($0.51), plus the agent's
own Ultra calls, not token-logged (610 calls, 287 Tavily searches; about 1.36M prompt and
0.19M answer tokens by the token heuristic, about $1.9 without the tool-call completions).
Duration 54 min (04:56 to 05:50 UTC), of which 49 min agent runs.

## Tokens, cost and duration (`eb311ed` run)

**Measured by the scoring scripts**, list prices:

| Part | Prompt tokens | Completion tokens | Cost |
|---|---:|---:|---:|
| Attacker + graders | 748,474 | 214,418 | $1.39 |
| Utility judge + distortion confirmation | 1,835,913 | 146,349 | $2.27 |
| Baselines: 25 fresh utility rows (not token-logged; about the same rows as in the `201341b` run) | ~14,000 | ~6,000 | ~$0.03 |
| **Scoring total** | **~2,598,000** | **~367,000** | **~$3.69** |

The harness does not token-log Airlock's upstream answers (Nemotron 3 Ultra, 622 calls, 88
Tavily searches). Estimated from the stored payloads and answers with the scripts' token
heuristic: about 0.14M prompt and 0.44M visible completion tokens, about $1.45. Estimated total:
about $5.1, against a projection of $5.99.

Duration: 2 h 19 min, 02:36 to 04:55 UTC.

- Baselines: 25 min, of which 23 min were the `gliner_pii` baseline re-downloading its 1.8 GB
  weights (the earlier runs loaded a local copy via `GLINER_PII_MODEL`); the baselines
  themselves took 2 min.
- Airlock harness: 100 min (03:01 to 04:41).
- Cloud scoring: 14 min.

Token Factory returned no HTTP errors or rate limits, and no upstream request fell back from
Ultra to Super. 64 attacker replies were an empty object on the first attempt and were retried
once with `reasoning_effort=low` as the script is designed to do (69 in the `201341b` run); 9
attacker replies were not valid JSON and were retried once (6 before).

## Caveats

- **Surrogate row is old and not independent.** It comes from the `e0ee6aa` detector and reused
  pass-1 detections. Treat its ± as not measured and its means as one detection per case on a
  detector two hardening rounds behind.
- **Configs judged in different runs.** The judge scores answer pairs, so the same cached
  reference answers scored 4.35, 4.40 and 4.38 for usefulness, and 10.0%, 7.7% and 10.0% for
  distortion, in the three runs. Differences of about 0.05 in utility ratio or 3 points in
  distortion are within that noise.
- **Baselines scored once.** Baseline rows were reused from committed runs (identical payloads,
  same Ultra models), so they carry one draw of attacker and judge sampling, not three.
- **Single attacker, lower bound.** One attacker model and prompt, no reasoning (except the
  empty-reply retry), no retrieval, no background knowledge, and deterministic matching that
  misses translations and generalizations. A stronger adversary would link more. Compare systems
  with each other, not against zero.
- **Synthetic data, tuned in the loop.** Every value is invented, identifiers are deliberately
  invalid, and the quasi-identifier and intent cases are hand-written by the same project that
  built the detector. S10 was tuned against the previous run's persistent failures and the
  72-case dev split, which are part of these 243 cases, so the full-set numbers are not a
  held-out estimate.
- **Earlier results are superseded.** The `201341b` run is kept for the comparison above; the S6,
  S9, S10 and S12 tables were one or two local passes on subsets at other commits. This
  measurement supersedes them for the full dataset.
