# Adversary inference: airlock 39281fb (feat/s10-hardening), AIRLOCK_GLINER=on, placeholder, dev split

- attacker: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning `none`)
- graders: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning `none`)
- attacked passes: 1 of the proxy run; cases per pass: 72
- tokens used: prompt 70317, completion 21134, about $0.13 at list prices

| Metric | All | ko | en |
|---|---:|---:|---:|
| Values recovered (full value) | 0.5% ± 0.0 | 1.2% ± 0.0 | 0.0% ± 0.0 |
| Values recovered (full or partial) | 3.0% ± 0.0 | 1.2% ± 0.0 | 4.2% ± 0.0 |
| Cases with any full value recovered | 2.0% ± 0.0 | 4.0% ± 0.0 | 0.0% ± 0.0 |
| Canary recovery (cases) | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 |
| Quasi re-identification (exact or partial attributes) | 28.6% ± 0.0 | 12.5% ± 0.0 | 50.0% ± 0.0 |
| Quasi re-identification (exact attributes only) | 14.3% ± 0.0 | 0.0% ± 0.0 | 33.3% ± 0.0 |
| Intent inferred (grader, named anchor required) | 50.0% ± 0.0 | 25.0% ± 0.0 | 75.0% ± 0.0 |
| Identity recovered (any identity item or quasi set) | 8.1% ± 0.0 | 6.5% ± 0.0 | 9.7% ± 0.0 |
| Situation inferred (grader, no anchor needed) | 71.9% ± 0.0 | 68.8% ± 0.0 | 75.0% ± 0.0 |
| Linkable disclosure (identity AND situation, same case) | 13.3% ± 0.0 | 13.3% ± 0.0 | 13.3% ± 0.0 |

Mean ± sample sd over attacked passes (sd is 0 with one pass).
