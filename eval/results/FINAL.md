# Final measurement: Airlock against four baselines

Two runs, both made with `eval/final_protocol.sh` on 2026-09-14 on all 243 cases, 3 passes:

| Run | Airlock config | Commit | Passes independent? | Log |
|---|---|---|---|---|
| `final-20260914T100907Z/` | **placeholder (default)**, GLiNER on | `201341b` | **yes**: server reset before every pass | `final-run3.log` |
| `final-20260914T004056Z/` | placeholder and surrogate, GLiNER on | `e0ee6aa` | **no**: reset only before pass 1 | `final-run.log` |

```bash
eval/final_protocol.sh --commit 201341b --gliner on --substitution placeholder --passes 3 \
  --reuse-committed --publish --systems "raw regex presidio_ko gliner_pii airlock" --yes
```

- **Airlock placeholder row:** from the independent run at `201341b`. The detector and proxy
  code is that of `44da227`, plus three changes:
  - `/vault/reset` also clears the health-entailment cache;
  - `/healthz` reports the local temperature;
  - an upstream error returns the intended 502 instead of crashing into a 500.

  Detection on a normal request is unchanged.
- **Airlock surrogate row:** from the earlier run at `e0ee6aa`, the same detection code. Its
  passes are not independent (see *Pass independence*), so its ± is not a measured spread.
  Surrogates were not rerun.
- **Dataset:** 243 cases (122 Korean, 121 English; 210 chat, 33 search), SHA-256
  `cd40ce70...850609`. Linkable disclosure is scored on the 98 situation-sensitive cases that
  carry identity items (finance 27, health 27, quasi-identifier 27, intent search 17).
- **Baselines:** raw, regex, presidio_ko and gliner_pii ran again in each run and sent the same
  payloads as the committed runs (hash-verified, 243 of 243 cases each). Their attack rows and
  623-624 of 630 utility rows were reused from `eval/results/baseline-<name>`, and the remaining
  6-7 utility rows were scored fresh.
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
| **Airlock, placeholder (default)** | **13.9% ± 0.6** | 8.6% ± 0.7 | 8.4% ± 0.6 | 72.8% ± 1.1 | 4.16 ± 0.03 (4.40) | 0.95 ± 0.01 | 15.2% ± 1.4 (7.7%) | 7.1% ± 1.3 | 11.1% ± 0.0 | 7.4% ± 0.0 |
| Airlock, surrogate † | 12.6% | 8.3% | 7.8% | 54.0% | 4.08 (4.35) | 0.94 | 19.4% (10.0%) | 6.4% | 11.1% | 7.4% |

Placeholder, other rates (independent run):

| Metric | Mean ± sd |
|---|---:|
| Case leak rate, any planted value (scanner) | 8.0% ± 0.5 |
| Canary leak | 0.0% ± 0.0 |
| Quasi re-identification (scanner) | 28.7% ± 2.3 |
| Planted values recovered by the attacker, full / full or partial | 0.4% ± 0.1 / 2.5% ± 0.2 |
| Block rate, all cases | 3.3% ± 0.0 |

**Latency, placeholder, local overhead (total minus cloud calls), per pass:**

| Pass | Overhead p50 / p95 | Local detect p50 / p95 | GLiNER p50 |
|---|---:|---:|---:|
| 1 | 3,965 / 8,754 ms | 3,468 / 8,179 ms | 483 ms |
| 2 | 3,939 / 8,391 ms | 3,409 / 7,371 ms | 465 ms |
| 3 | 4,108 / 9,168 ms | 3,375 / 8,765 ms | 528 ms |
| Mean ± sd | 4,004 ± 91 / 8,771 ± 389 ms | | |

Baseline overhead p50 / p95 in the same run: raw and regex 0 / 0 ms, Presidio 2 / 4 ms,
GLiNER-PII (on MPS) 78 / 147 ms.

### What the table says

- **Every remaining linkable disclosure is a quasi-identifier case.** Over the 3 independent
  passes, placeholder Airlock had 0 linkable cases in finance, health and intent search, and 13.7
  of 27 quasi-identifier cases per pass. GLiNER-PII alone: finance 1, health 1, intent 0,
  quasi-identifier 7.
- **Against raw pass-through**, Airlock cuts linkable disclosure from 84.7% to 13.9% and identity
  leak from 98.5% to 8.6%, at a utility ratio of 0.95. Distortion is 15.2% against 7.7% for the
  reference answers judged in the same run. The raw baseline, judged in an earlier run, shows how
  noisy that reference is: 7.7% vs 10.6%.
- **GLiNER-PII alone links less (9.2% vs 13.9%), at a large utility cost.** It masks 59.3% of
  benign prompts, and its answers score 2.69 against 4.16 (utility ratio 0.59 vs 0.95), with 24.5%
  distortion.
- **Benign cost:** 3 of 27 benign cases get a mask (all Korean), and the two Korean benign searches
  `ben-ko-08` and `ben-ko-13` are blocked in every pass (7.4%).

## Pass independence

The run summary now reports the independence check (`eval/scoring.py`, `independence_check`).
It gives the share of cases whose outbound payloads are byte-identical in all passes, and the
local detect time p50 per pass. The detector samples at temperature 0.6. A detection served from
Airlock's in-memory cache is almost free, so a sharp drop in detect time after pass 1 is the
reliable signature of a cache.

| Run | Byte-identical payloads, all 3 passes | Detect p50 by pass | Independent |
|---|---:|---|---|
| Placeholder `201341b`, reset before every pass | 130 of 231 cases (56.3%) | 3,463 / 3,409 / 3,375 ms | yes |
| Placeholder `e0ee6aa`, reset before pass 1 only | 211 of 232 cases (90.9%) | 3,412 / 462 / 475 ms | no |
| Surrogate `e0ee6aa`, reset before pass 1 only | 70 of 231 cases (30.3%) | 3,270 / 506 / 571 ms | no |

Nemotron-3-Nano-4B still repeats more than half of its outputs exactly when it really re-runs,
mostly on short prompts. Surrogates are re-drawn per conversation, so a cached run can still show
few identical payloads. The harness therefore warns on the detect-time drop, and on identical
payloads only above 85%.

**What the cached run got wrong for placeholders:**

| Metric | Cached `e0ee6aa` | Independent `201341b` |
|---|---:|---:|
| Linkable disclosure | 15.3% ± 1.0 | 13.9% ± 0.6 |
| Identity leak | 9.7% ± 0.0 | 8.6% ± 0.7 |
| Utility ratio | 0.95 | 0.95 |
| Distortion | 14.7% | 15.2% |
| Over-redaction | 7.0% ± 0.3 | 7.1% ± 1.3 |
| 3-pass mean overhead p50 / p95 | 1,629 / 5,734 ms | 4,004 / 8,771 ms |

- **Scanner columns:** the cached run reported sd 0.0; the real spread is 0.7 points on identity
  leak and 1.3 on over-redaction.
- **Means:** they moved by about a point, within the spread of a single detection.
- **Latency:** the cached run's 3-pass means understated it by 2.4 s at p50; its pass-1 figures
  (3,930 / 8,416 ms) were close to the true ones.
- **Persistence:** the cached run showed 14 cases linkable in every pass. With independent
  sampling it is 9 in every pass and 18 in at least one: part of the apparent persistence was the
  cache repeating one detection.

## Default: placeholder

The rule set before the measurement: keep placeholders unless surrogates are clearly better on
linkable disclosure without worse distortion. With the independent placeholder numbers, the
answer is still no, and the linkable gap is smaller than first reported.

- **Linkable disclosure:** surrogate 12.6% vs placeholder 13.9% ± 0.6, a 1.3-point gap (about 1
  of 98 cases per pass). The first report said 2.7 points against the cached placeholder run.
- **Distortion:** surrogate 19.4% vs placeholder 15.2% ± 1.4. Each config was judged in its own
  run, and the reference answers scored 10.0% and 7.7% in those runs. Above its own reference,
  surrogate adds 9.4 points and placeholder 7.5. The difference is smaller than the raw rates
  suggest, but it does not favor surrogates.
- **Usefulness:** 4.08 vs 4.16.
- **Situation inference:** lower with surrogates (54.0% vs 72.8%). This accounts for part of their
  linkable figure.

Surrogate was not remeasured with independent passes, so its row carries one detection per case
and no measured spread. An independent surrogate run could move its numbers by about a point, as
the placeholder's moved. A 1.3-point linkable gap against a 4-point distortion gap would not
change the decision. `AIRLOCK_SUBSTITUTION=surrogate` remains available.

## By language (placeholder, independent run)

| | Identity leak | Linkable | Usefulness | Utility ratio | Distortion | Over-redaction | Benign masked |
|---|---:|---:|---:|---:|---:|---:|---:|
| Korean | 10.6% ± 1.0 | 14.0% ± 3.5 | 3.98 ± 0.05 | 0.86 ± 0.02 | 17.0% ± 3.1 | 10.0% ± 1.9 | 23.1% |
| English | 6.5% ± 0.6 | 13.9% ± 2.4 | 4.33 ± 0.09 | 1.04 ± 0.04 | 13.3% ± 2.1 | 4.3% ± 1.1 | 0.0% |

Surrogate † for reference: identity leak 8.7% / 7.8%, linkable 10.7% / 14.6%, utility ratio 0.88 /
1.01, distortion 21.9% / 16.9% (ko / en).

- **Korean costs more.**
  - Identity leak is 10.6% vs 6.5%.
  - The utility ratio is 0.86 vs 1.04.
  - Over-redaction is 10.0% vs 4.3%.
  - Every benign mask is Korean (3 of 13 Korean benign cases).
- **Linkable disclosure is the same in both languages** (14.0% vs 13.9%). The per-language spread
  is wide (sd 3.5 and 2.4 points on about 50 cases each).

## Persistent failures (placeholder, independent run)

**Linkable in all 3 passes, 9 cases:** `qid-ko-07`, `-08`, `-10`, `-11`, `-14` and `qid-en-04`,
`-08`, `-10`, `-11`. 18 cases were linkable in at least one pass, all quasi-identifier prompts.
In all 9 the scanner also counts an identity leak (quasi identity attributes reach `identity_k`)
and the attacker returned the attributes verbatim:

1. **Roles and titles** kept as situation context: `5급 사무관`, `관리사무소장`, `체육교사`,
   `산부인과 전문의`, `전직 변호사`, `pediatric cardiologist`, `tenure-track` + `quantum optics`,
   `goalkeeper`.
2. **Cohort and rank markers:** `2022년 행정고시` + `수석`, `75kg급`, `AP chemistry`,
   `only one who voted against`.
3. **Small places, schools and sites:** `달무리도`, `가온시`, `연수구` + `새벽별리버뷰`,
   `Tillbrook High`, `Corvenna Systems warehouse`, `Valparaíso`.
4. **Rare personal facts:** `Korean-speaking` father aged 61, `귀농 부부` growing apples.

Closing these means generalizing one more attribute of the combination (a rank, a cohort, a small
place) even when each looks harmless alone. That trades against the utility the
situation-keeping rules bought in S6 and S9.

**Identity leaks outside the quasi-identifier category:** all Korean adversarial encodings, plus
one direct name.

- `adv-ko-07` leaked in all 3 passes: a name matched in its alphanumeric-normalized form.
- Leaks in some passes only:
  - `adv-ko-13` (2 passes) and `adv-ko-06` (1): card numbers after digit normalization;
  - `adv-ko-02` (1): a phone number in Korean numerals;
  - `adv-ko-14` (1): a name;
  - `fin-ko-10` (1): a Korean name sent verbatim.

**Blocks:** 12 cases were blocked in at least one pass. Six were blocked in every pass: the two
Korean benign searches and 4 English intent searches (`int-en-01`, `-03`, `-09`, `-11`).

## Tokens, cost and duration (independent placeholder run)

**Measured by the scoring scripts**, list prices:

| Part | Prompt tokens | Completion tokens | Cost |
|---|---:|---:|---:|
| Attacker + graders | 749,444 | 221,127 | $1.41 |
| Utility judge (622 calls) + distortion confirmation (197) | 1,785,715 | 143,945 | $2.22 |
| Baselines: 25 fresh utility rows | 14,398 | 6,106 | $0.03 |
| **Scoring total** | **2,549,557** | **371,178** | **$3.66** |

The harness does not token-log Airlock's upstream answers (Nemotron 3 Ultra, 628 calls, 78 Tavily
searches). Estimated from the stored payloads and answers with the scripts' token heuristic:
about 0.13M prompt and 0.42M visible completion tokens, about $1.39. Estimated total: about
$5.05, against a projection of $5.99.

The first run cost about $10.6 to $11.7 by the same method. The interrupted rerun
(`final-20260914T035811Z`, not committed) cost about $1.2 of upstream answers before Token
Factory returned HTTP 402 (budget exhausted). The harness and scoring scripts now abort on a 402
or a persistent 429 instead of writing error rows.

Duration: 1 h 52 min, 10:09 to 12:01 UTC.

- Baselines: 2 min.
- Airlock harness: 96 min.
- Cloud scoring: 14 min.

Token Factory returned no HTTP errors or rate limits. One upstream request (`qid-ko-01`, pass 1)
fell back from Ultra to Nemotron 3 Super. 6 attacker replies were not valid JSON and were retried
once.

## Caveats

- **Surrogate row not independent.** Its passes reused pass-1 detections. Treat its ± as not
  measured and its means as one detection per case scored three times.
- **Configs judged in different runs.** Placeholder and surrogate were judged in different runs.
  The judge scores answer pairs, so the same cached reference answers scored 4.35 and 4.40 for
  usefulness, and 10.0% and 7.7% for distortion, in the two runs. Differences of about 0.05 in
  utility ratio or 3 points in distortion are within that noise.
- **Baselines scored once.** Baseline rows were reused from committed runs (identical payloads,
  same Ultra models), so they carry one draw of attacker and judge sampling, not three.
- **Single attacker, lower bound.** One attacker model and prompt, no reasoning, no retrieval, no
  background knowledge, and deterministic matching that misses translations and
  generalizations. A stronger adversary would link more. Compare systems with each other, not
  against zero.
- **Synthetic data.** Every value is invented, identifiers are deliberately invalid, and the
  quasi-identifier and intent cases are hand-written by the same project that built the detector.
  Rules and thresholds were tuned on a 72-case dev split that is part of these 243 cases, so the
  full-set numbers are not a held-out estimate.
- **Earlier results are superseded.** Earlier S6 and S9 tables were one pass on subsets (a 90-case
  test subset, a 72-case dev split) at other commits. This measurement supersedes them for the
  full dataset.
- **False warnings in the log.** `final-run3.log` shows independence warnings for the presidio_ko
  and gliner_pii baselines. Those were false positives of the first version of the check: a
  deterministic baseline warms up in pass 1. The check now warns only for a sampling detector,
  and the stored summaries were recomputed with it.
