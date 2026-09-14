# Final measurement: Airlock placeholder vs surrogate, against four baselines

Run `eval/results/final-20260914T004056Z/` (log: `eval/results/final-run.log`), made with
`eval/final_protocol.sh` on 2026-09-14:

```bash
eval/final_protocol.sh --commit e0ee6aa --gliner on --substitution both --passes 3 \
  --reuse-committed --publish --systems "raw regex presidio_ko gliner_pii airlock" --yes
```

- **Airlock** at `e0ee6aa` (the detector and proxy code of `44da227`; that commit only adds the
  `--substitution` option to the protocol script). Two configs, GLiNER ensemble on in both, all other
  settings at their defaults (`balanced`, review off): `AIRLOCK_SUBSTITUTION=placeholder` and
  `AIRLOCK_SUBSTITUTION=surrogate`.
- **Dataset:** all 243 cases (122 Korean, 121 English; 210 chat, 33 search), SHA-256
  `cd40ce70...850609`. Linkable disclosure is scored on the 98 situation-sensitive cases that
  carry identity items (finance 27, health 27, quasi-identifier 27, intent search 17).
- **Passes:** 3 harness passes per system. Each Airlock config was attacked and judged on all 3
  passes. The four deterministic baselines sent identical payloads on every pass and on the
  committed runs (hash-verified for 243 of 243 cases each). Their attack rows and 623-624 of 630
  utility rows were therefore reused from `eval/results/baseline-<name>`; the remaining 6-7
  utility rows per baseline were scored in this run.
- **Scoring:** attacker, intent and situation graders, utility judge and distortion confirmation
  all on Nemotron 3 Ultra, per `JUDGE_CALIBRATION.md`. Reference answers come from the committed
  cache (`_reference_answers/`).
- **Isolation:** systems ran one after another, with exactly one `llama-server` (Nemotron-3-Nano-4B
  Q4_K_M) during each Airlock config and none during the baselines. Machine: Apple M3 Pro, 18 GB;
  GLiNER ran on CPU inside the Airlock process.

Full tables: [`COMPARISON.md`](COMPARISON.md).

> **The Airlock passes in this run are not independent.** The harness reset the server only
> before pass 1, so passes 2 and 3 reused pass-1 detections from Airlock's in-memory cache.
> The independence check added afterwards (`eval/scoring.py`) reports:
>
> | | Byte-identical payloads, all 3 passes | Detect p50 by pass |
> |---|---:|---|
> | Placeholder | 211 of 232 cases (90.9%) | 3,412 / 462 / 475 ms |
> | Surrogate | 70 of 231 cases (30.3%) | 3,270 / 506 / 571 ms |
>
> Surrogates are re-drawn per conversation, so their payloads differ even though detection was
> cached. Treat every Airlock ± below as not measured. The means are one detection per case
> scored three times.
>
> The harness now resets before every pass (commit `91bb954`). A rerun of the placeholder config
> with that fix (`final-20260914T035811Z`, not committed) confirmed the fix: detect p50 stayed at
> 3,321 / 3,357 ms in passes 1 and 2, and 140 of 229 cases (61.1%) sent byte-identical payloads
> in both. The rerun stopped in pass 3, when Token Factory began returning HTTP 402 (budget
> exhausted), before any attack or utility scoring. Its scanner numbers for passes 1 and 2
> (identity leak 8.3% / 8.3%, leak rate 7.4% / 7.4%) are close to this run's 9.7% and 7.9%.
> Independent means ± sd for the default config remain to be measured.

## Headline

Mean ± sample sd over 3 passes. For the baselines, ± 0.0 reflects identical outputs scored once;
it does not measure scoring noise (see *Caveats*). Lower is better except usefulness and utility
ratio.

| System | **Linkable disclosure** | Identity leak (scanner) | Identity recovered (attacker) | Situation inferred | Usefulness 1-5 (reference) | Utility ratio | Distortion (reference) | Over-redaction | Benign masked | Over-block benign |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| raw (pass-through) | 84.7% | 98.5% | 94.7% | 86.1% | 4.52 (4.33) | 1.05 | 7.7% (10.6%) | 0.0% | 0.0% | 0.0% |
| regex only | 79.6% | 92.7% | 88.8% | 80.6% | 3.91 (4.49) | 0.87 | 13.9% (10.1%) | 0.4% | 7.4% | 0.0% |
| Presidio + ko/en spaCy + KR recognizers | 53.1% | 76.7% | 73.8% | 77.8% | 3.01 (4.54) | 0.66 | 33.7% (6.7%) | 16.7% | 66.7% | 0.0% |
| NVIDIA GLiNER-PII alone | 9.2% | 18.9% | 19.4% | 63.0% | 2.69 (4.57) | 0.59 | 24.5% (4.8%) | 14.1% | 59.3% | 0.0% |
| **Airlock, placeholder (default)** | 15.3% ± 1.0 | 9.7% ± 0.0 | 10.2% ± 0.0 | 71.0% ± 2.8 | 4.13 ± 0.04 (4.35) | 0.95 ± 0.02 | 14.7% ± 1.9 (11.2%) | 7.0% ± 0.3 | 11.1% | 7.4% |
| Airlock, surrogate | 12.6% ± 1.2 | 8.3% ± 0.0 | 7.8% ± 0.0 | 54.0% ± 2.1 | 4.08 ± 0.05 (4.35) | 0.94 ± 0.02 | 19.4% ± 1.6 (10.0%) | 6.4% ± 0.2 | 11.1% | 7.4% |

Other measured rates:

| | Placeholder | Surrogate |
|---|---:|---:|
| Case leak rate, any planted value (scanner) | 7.9% ± 0.0 | 7.4% ± 0.0 |
| Canary leak | 0.0% | 0.0% |
| Planted values recovered by the attacker, full / full or partial | 0.6% / 2.5% | 0.1% / 12.8% |
| Block rate, all cases | 2.9% ± 0.7 | 3.2% ± 1.2 |
| Local overhead p50 / p95, pass 1 (cold detector cache) | 3,930 / 8,416 ms | 3,776 / 9,161 ms |
| Local overhead p50 / p95, mean of 3 passes (as in `COMPARISON.md`) | 1,629 / 5,734 ms | 1,632 / 6,541 ms |
| Local model detect time p50 / p95, pass 1 | 3,410 / 7,563 ms | 3,234 / 8,361 ms |
| GLiNER inference p50, pass 1 | 488 ms | 472 ms |

Baseline local overhead p50 / p95: raw and regex 0 / 0 ms, Presidio 2 / 4 ms, GLiNER-PII (on
MPS) 79 / 166 ms. Use the pass-1 row for Airlock latency: passes 2 and 3 hit the detector cache
(see *Caveats*).

### What the table says

- **Every linkable disclosure left for Airlock is a quasi-identifier case.** Across all three
  passes, Airlock had 0 linkable cases in finance, health and intent search in both configs. In
  the quasi-identifier category, 15.0 of 27 cases per pass were linkable with placeholders and
  12.3 of 27 with surrogates. For comparison, GLiNER-PII alone: finance 1, health 1, intent 0,
  quasi-identifier 7 of 27.
- **GLiNER-PII alone links less than Airlock (9.2% vs 15.3%), but at a cost that makes it hard to
  use.** It masks 59.3% of benign prompts, and its answers score 2.69 against 4.13 for Airlock
  (utility ratio 0.59 vs 0.95), with 24.5% distortion. Airlock keeps roles, places and ages that
  a useful answer often needs, and in the quasi-identifier category those are exactly what link.
- **Against the other baselines**, Airlock with placeholders cuts linkable disclosure from 84.7%
  (raw) to 15.3% and identity leak from 98.5% to 9.7%, at a utility ratio of 0.95. Distortion is
  3.5 points above the reference answers judged in the same run (14.7% vs 11.2%). Over-redaction
  is 7.0%.
- **Benign cost:** 11.1% of benign cases get a mask (3 of 27, all Korean) and 7.4% are blocked
  (the two Korean benign searches `ben-ko-08` and `ben-ko-13`, in every pass).

## Default: placeholder

The rule set before the run: keep placeholders unless surrogates are clearly better on linkable
disclosure without worse distortion. They are not.

- **Linkable disclosure:** surrogate 12.6% ± 1.2 vs placeholder 15.3% ± 1.0, a 2.7-point gap,
  about 2 to 3 of 98 cases per pass. In all three passes, 11 cases were linkable with surrogates and 14 with
  placeholders, 10 of them shared. A small improvement, in the right direction.
- **Distortion is worse:** 19.4% ± 1.6 vs 14.7% ± 1.9, while the same judge run gave the reference
  answers 10.0% and 11.2%. Surrogates add 9.4 points of distortion over the reference;
  placeholders add 3.5. Usefulness is also slightly lower (4.08 vs 4.13; the ranges overlap).
- **Part of the linkable drop is lower situation inference** (54.0% vs 71.0%), not only fewer
  identity recoveries (7.8% vs 10.2%). The causes of the situation drop were not analyzed case by
  case. The case leak rate barely moves (7.4% vs 7.9%).
- **Partial value matches rise with surrogates** (12.8% vs 2.5% full or partial). One known
  source is by design: card surrogates keep the last four digits so answers about "the card
  ending in ..." stay correct.

`AIRLOCK_SUBSTITUTION=surrogate` remains available for users who weigh the linkable gap over
distortion.

## By language

| | Identity leak ko / en | Linkable ko / en | Usefulness ko / en | Utility ratio ko / en | Distortion ko / en | Over-redaction ko / en | Benign masked ko / en |
|---|---:|---:|---:|---:|---:|---:|---:|
| Placeholder | 10.6% / 8.8% | 14.0% / 16.7% | 4.02 / 4.25 | 0.89 / 1.02 | 16.2% / 13.3% | 10.2% / 3.8% | 23.1% / 0.0% |
| Surrogate | 8.7% / 7.8% | 10.7% / 14.6% | 4.01 / 4.15 | 0.88 / 1.01 | 21.9% / 16.9% | 8.3% / 4.5% | 23.1% / 0.0% |
| GLiNER-PII alone | 20.2% / 17.6% | 10.0% / 8.3% | 2.56 / 2.82 | 0.54 / 0.65 | 26.7% / 22.3% | 17.7% / 10.5% | 61.5% / 57.1% |
| raw | 98.1% / 99.0% | 88.0% / 81.2% | 4.66 / 4.39 | 1.03 / 1.06 | 8.6% / 6.8% | 0.0% / 0.0% | 0.0% / 0.0% |

- **Korean costs more utility.** With placeholders, the Korean utility ratio is 0.89 against
  1.02 in English, over-redaction is 10.2% vs 3.8%, and every benign mask is Korean (3 of 13
  Korean benign cases, 0 of 14 English).
- **English links more.** Linkable disclosure is 16.7% in English vs 14.0% in Korean, and
  scanner quasi re-identification is 34.8% in English vs 18.5% in Korean.
- **Surrogates lower linkability more in Korean** (14.0% to 10.7%, against 16.7% to 14.6% in
  English), but Korean distortion also rises more (16.2% to 21.9%, against 13.3% to 16.9%).

## Persistent failures

**Linkable in all 3 passes.**

- **Placeholder, 14 cases:** `qid-ko-04`, `-05`, `-08`, `-09`, `-10`, `-11`, `-14` and `qid-en-02`, `-03`, `-04`, `-08`, `-09`, `-12`, `-13`. 16 were linkable in at least one pass.
- **Surrogate, 11 cases:** `qid-ko-05`, `-08`, `-09`, `-11`, `-14` and `qid-en-02`, `-06`, `-08`, `-09`, `-12`, `-13`. 14 in at least one pass.

All are quasi-identifier cases. In each one, no single attribute identifies anyone, but together
they do, and the attacker returned them verbatim:

1. **Roles and titles** kept as situation context: `5급 사무관`, `CTO`, `체육교사`, `관리사무소장`,
   `전직 변호사`, `helicopter mechanic`, `pediatric cardiologist`, `only female airline captain`.
2. **Cohort and rank markers:** `2022년 행정고시` + `수석`, `06학번`, `2019년 공채`, `3학년 2반`.
3. **Small places and units:** `Merrow Falls`, `Camp Harlan`, `Quenby Township`, `가온시`,
   `연수구` + `새벽별리버뷰`, `East Tamsworth` + `Birchwick Elementary`, and part of
   `412th Aviation Maintenance Company`.
4. **Rare personal facts:** `leap day` birthday with Fabry disease at 34, `쌍둥이` / `a twin`,
   `left-handed`, `Korean-speaking` father aged 61.

In 12 of the 14 placeholder cases the scanner also counts an identity leak: quasi identity
attributes reach `identity_k`. In `qid-ko-04` and `qid-en-13` the scanner does not, but the
attacker's partial matches (`반도체 설계`, `only female airline captain`) reach k. Closing these
cases means generalizing one more attribute of the combination (a rank, a cohort year or a small
town) even when each attribute looks harmless alone. That trades against the utility the
situation-keeping rules bought in S6 and S9.

**Identity leaks in all 3 passes outside the quasi-identifier category** are all adversarial
Korean encodings. None of them is linkable-eligible:

- **Placeholder:** `adv-ko-01` and `adv-ko-08` (a name spaced out syllable by syllable), `adv-ko-07`
  (a name matched in its alphanumeric-normalized form), `adv-ko-06` (a card number matched after
  digit normalization).
- **Surrogate:** `adv-ko-07` and `adv-ko-02` (a phone number spelled in Korean numerals).

**Blocks:** with placeholders, 11 cases were blocked in at least one pass: 7 English intent
searches, 1 Korean intent search, the 2 Korean benign searches and `adv-en-11`.

## Tokens and cost

**Measured by the scoring scripts** (`attack/config.json` `usage`, `utility/config.json` `runs`), list
prices:

| Part | Prompt tokens | Completion tokens | Cost |
|---|---:|---:|---:|
| Placeholder: attacker + graders | 752,053 | 220,652 | $1.41 |
| Placeholder: utility judge + distortion confirmation | 1,815,108 | 145,966 | $2.25 |
| Surrogate: attacker + graders | 740,530 | 258,407 | $1.52 |
| Surrogate: utility judge + distortion confirmation | 1,945,401 | 152,909 | $2.40 |
| Baselines: 25 fresh utility rows (answers, 1 judgment, 2 confirmations) | 14,542 | 7,250 | $0.04 |
| **Scoring total** | **5,267,634** | **785,184** | **$7.62** |

The Airlock upstream answers (Nemotron 3 Ultra, 1,252 calls, 162 Tavily searches) are not
token-logged by the harness. Estimated from the stored payloads and answers with the scripts'
token heuristic, they came to about 0.23M prompt and 0.92M visible completion tokens, about
$3.0. Hidden reasoning tokens, if any were billed, are not included, and the pre-run projection
was $4.04. Estimated total: about $10.6 to $11.7, against a projection of $11.98.

Run duration: 3 h 02 min, 00:40:56 to 03:42:48 UTC.

- Baselines: about 2 minutes.
- Placeholder harness: 70 min.
- Surrogate harness: 79 min.
- Cloud scoring: 31 min.

Token Factory returned no HTTP errors, rate limits or upstream fallbacks. 13 attacker replies were
not valid JSON and were retried once, as documented in `eval/README.md`.

## Caveats

- **The three Airlock passes share one local detection for most texts.** `LLMDetector` caches
  results in memory by text, and the harness called `/vault/reset` only once, before pass 1.
  Passes 2 and 3 therefore reused pass-1 detections wherever the text repeated. Local detect
  time p50 fell from 3.4 s in pass 1 to 0.46 s in pass 2, and with placeholders 211 of 232
  cases sent byte-identical payloads in all three passes. As a result:
  - the ± on the scanner columns (identity leak, leak rate: sd 0.0) says almost nothing about
    local-model sampling variance;
  - the ± on attacker and judge columns mostly measures cloud-side noise;
  - the 3-pass latency means in `COMPARISON.md` mix cold and cached requests, so the pass-1
    figures above are the honest latency.

  The harness now resets before every pass; see the note at the top for the rerun status.
- **Judge noise.** The judge scores answer pairs, so the same cached reference answers scored
  between 4.33 and 4.57 depending on the system they were paired with. The raw baseline, whose
  prompt equals the reference prompt, gets a utility ratio of 1.05 and 7.7% distortion against
  10.6% for its reference. Differences of about 0.05 in ratio or 3 points in distortion are within
  that noise. The placeholder vs surrogate distortion gap (4.7 points, sd 1.6 to 1.9) is larger;
  their usefulness gap is not.
- **Baselines scored once.** Baseline rows were reused from the committed runs: identical payloads,
  same Ultra models. Their numbers therefore carry one draw of attacker and judge sampling, not
  three.
- **Single attacker, lower bound.** One attacker model and prompt, no reasoning, no retrieval, no
  background knowledge, and deterministic matching that misses translations and generalizations.
  A stronger adversary would link more. Compare systems with each other, not against zero.
- **Synthetic data.** Every value is invented, identifiers are deliberately invalid, and the
  quasi-identifier and intent cases are hand-written by the same project that built the detector.
  Rules and thresholds were tuned on a 72-case dev split that is part of these 243 cases, so the
  full-set numbers are not a held-out estimate.
- **Earlier results are not directly comparable.** Earlier S6 and S9 tables were one pass on
  subsets (90-case test subset, 72-case dev split) at other commits. Where they differ from these
  numbers (for example S6 placeholder linkable 8.3% on 90 cases vs 15.3% here on 98 cases), this
  run supersedes them for the full dataset.
