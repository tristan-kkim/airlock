# S6 detector round two: test split

Test split of `ensemble-split.json` (seed 20260914): 171 cases, one pass each; rules were tuned on the 72 dev cases only. Attack and utility columns use a stratified 90-case subset of the test split (`test90.json`, seed 6) to stay under the Token Factory budget. Attacker, graders and utility judge: Nemotron 3 Ultra (the S8 calibration kept Ultra for every role).

| Metric | B1 (GLiNER ensemble, main) | s6-placeholder | s6-surrogate |
|---|---:|---:|---:|
| Leak rate (171) | 11.2% | 8.6% | 7.9% |
| Identity leak (171) | 12.5% | 9.0% | 8.3% |
| Quasi re-id, scanner (171) | 27.8% | 27.8% | 25.0% |
| **Linkable disclosure** (90) | 16.7% | 8.3% | 11.1% |
| Identity recovered, attacker (90) | 10.5% | 7.9% | 7.9% |
| Situation inferred (90) | 55.0% | 72.5% | 62.5% |
| Utility ratio (90) | 0.91 | 0.87 | 0.85 |
| Distortion (90) | 16.2% | 27.6% | 32.9% |
| Distortion of the reference answers (90) | 14.9% | 6.6% | 11.8% |
| Benign masked (171) | 21.1% | 21.1% | 21.1% |
| Over-block benign (171) | 10.5% | 10.5% | 10.5% |
| Over-redaction (171) | 15.5% | 7.8% | 8.8% |
| Block rate (171) | 5.8% | 5.3% | 4.1% |
| Leak ko / en (171) | 13.0% / 9.3% | 9.1% / 8.0% | 6.5% / 9.3% |
| Identity leak ko / en (171) | 13.7% / 11.3% | 9.6% / 8.5% | 6.8% / 9.9% |
| Linkable ko / en (90) | 11.1% / 22.2% | 5.6% / 11.1% | 5.6% / 16.7% |
| Utility ratio ko / en (90) | 0.87 / 0.95 | 0.90 / 0.85 | 0.86 / 0.83 |
| Distortion ko / en (90) | 16.2% / 16.2% | 27.0% / 28.2% | 27.0% / 38.5% |
| Detect p50 / p95, chat (ms) | 3858 / 8238 | 3381 / 8376 | 3519 / 7796 |
| Local overhead p50 / p95 (ms) | 4384 / 9983 | 3904 / 8333 | 3876 / 7800 |

## Token Factory usage

| Run | Attack + utility for this report (measured) | Harness upstream (estimated) |
|---|---:|---:|
| B1 (GLiNER ensemble, main) | 273,227 | not re-run |
| s6-placeholder | 341,794 | ~123,687 |
| s6-surrogate | 384,219 | ~124,837 |

Agent runs: not measured by the scripts; about 0.2M tokens estimated from the recorded hop payloads (three attempts, see below). Total for S6: about 1.0M measured (attack, graders, judge) plus about 0.45M estimated (harness upstream answers, agent turns), under the 2.5M cap. The estimate printed before the runs was about 2.6M for attack and utility on all 171 test cases (two configs plus B1), so both were reduced to the 90-case subset.

## Notes

- Commits: both test runs at `071c36c`. Later commits (`b666ac4`, `fa67e0c`, `dcec3ff`) fixed problems found in the agent runs and in the surrogate distortions: object keys of tool-call arguments are never rewritten, code identifiers are not secrets, English titles and organizations do not cross line breaks, surrogates avoid every protected value of the request, card surrogates keep the last four digits, English surrogate first names are gender-neutral, and an organization written without its suffix is rehydrated. A rules-only replay of the 171 test cases gives identical placeholder outbound text before and after these commits; model-span and surrogate effects are not re-measured.
- Default: `placeholder`. Surrogates leak slightly less (identity leak 8.3% vs 9.0%, Korean leak 6.5% vs 9.1%) but link more on the subset (11.1% vs 8.3%), and have a lower utility ratio (0.85 vs 0.87) and more distortion (32.9% vs 27.6%). Answers that mention placeholders or masked values: B1 23/161, placeholder 21/162, surrogate 22/164.
- The utility judge is noisy at one pass: the distortion rate of the same reference answers was 14.9%, 6.6% and 11.8% in the three judge runs.
- Latency: Nemotron-3-Nano-4B Q4_K_M (llama-server on port 8088, `-np 1`, `--cache-ram 0`) and GLiNER on CPU, M3 Pro. Another llama-server (port 8081, not ours) was loaded and idle during the runs; cloud scoring ran concurrently but uses no local model.

## Agent mode: identity facts that reached the cloud

`eval/results/s6-agent/`, 4 scenarios, airlock mode, 1 pass, `AIRLOCK_GLINER=on`, deterministic scanner over every upstream message and Tavily query (`count_survivors.py`), no attacker.

| Scenario | Identity facts | placeholder (`b666ac4`) | surrogate (`dcec3ff`) |
|---|---:|---:|---:|
| layoff-ko (박성훈, 동해누리정밀, 품질보증팀, DN-19044) | 4 | 0 | 0 |
| hr-warning-ko (이수민, 한울에너지솔루션, 영업2팀, HE-22871, 배정호) | 5 | 0 | 0 |
| layoff-en (Daniel Okafor, Halcyon Freight Systems, HFS-40418, Payments Platform, Maria Chen) | 5 | 0 | 0 |
| hr-warning-en (Kelsey Moran, Northgate Community Credit Union, NCCU-5512, Tom Albrecht, Riverside branch) | 5 | 0 | 0 |
| Total | 19 | 0 | 0 |

All eight runs finished. The first attempt (`071c36c`, both modes) blocked every run at the third turn: GLiNER read the argument key `doc_id` as an HTTP cookie, the key was masked in the tool call, and the gate then found it in the tool schema. The second surrogate attempt blocked one run: a role match crossed a line break (`Credit Union\nManager`) and the surrogate organization contained that protected string. For reference, the committed S5 sample run of layoff-ko (before this round) sent `품질보증팀`, and REFRAME.md reports team and employer names surviving all three passes.
