# Adversary inference: airlock 071c36c S6 round two, AIRLOCK_GLINER=on, AIRLOCK_SUBSTITUTION=surrogate, test split

- attacker: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning `none`)
- graders: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning `none`)
- attacked passes: 1 of the proxy run; cases per pass: 90
- tokens used: prompt 81822, completion 27683, about $0.16 at list prices

| Metric | All | ko | en |
|---|---:|---:|---:|
| Values recovered (full value) | 0.8% ± 0.0 | 0.9% ± 0.0 | 0.8% ± 0.0 |
| Values recovered (full or partial) | 6.6% ± 0.0 | 5.4% ± 0.0 | 7.7% ± 0.0 |
| Cases with any full value recovered | 3.2% ± 0.0 | 3.2% ± 0.0 | 3.1% ± 0.0 |
| Canary recovery (cases) | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 |
| Quasi re-identification (exact or partial attributes) | 21.1% ± 0.0 | 10.0% ± 0.0 | 33.3% ± 0.0 |
| Quasi re-identification (exact attributes only) | 15.8% ± 0.0 | 0.0% ± 0.0 | 33.3% ± 0.0 |
| Intent inferred (grader, named anchor required) | 30.0% ± 0.0 | 40.0% ± 0.0 | 20.0% ± 0.0 |
| Identity recovered (any identity item or quasi set) | 7.9% ± 0.0 | 5.3% ± 0.0 | 10.5% ± 0.0 |
| Situation inferred (grader, no anchor needed) | 62.5% ± 0.0 | 55.0% ± 0.0 | 70.0% ± 0.0 |
| Linkable disclosure (identity AND situation, same case) | 11.1% ± 0.0 | 5.6% ± 0.0 | 16.7% ± 0.0 |

Mean ± sample sd over attacked passes (sd is 0 with one pass).
