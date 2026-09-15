# Adversary inference: airlock@eb311ed gliner=1 substitution=placeholder

- attacker: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning `none`)
- graders: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning `none`)
- attacked passes: 3 of the proxy run; cases per pass: 243
- tokens used: prompt 748474, completion 214418, about $1.39 at list prices

| Metric | All | ko | en |
|---|---:|---:|---:|
| Values recovered (full value) | 0.1% ± 0.1 | 0.2% ± 0.2 | 0.0% ± 0.0 |
| Values recovered (full or partial) | 2.1% ± 0.4 | 1.3% ± 0.7 | 2.8% ± 0.2 |
| Cases with any full value recovered | 0.4% ± 0.3 | 0.8% ± 0.7 | 0.0% ± 0.0 |
| Canary recovery (cases) | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 |
| Quasi re-identification (exact or partial attributes) | 18.0% ± 2.0 | 12.3% ± 2.1 | 24.6% ± 2.5 |
| Quasi re-identification (exact attributes only) | 9.3% ± 1.2 | 3.7% ± 0.0 | 15.9% ± 2.5 |
| Intent inferred (grader, named anchor required) | 29.6% ± 0.0 | 26.2% ± 8.2 | 33.3% ± 8.9 |
| Identity recovered (any identity item or quasi set) | 4.4% ± 0.0 | 3.8% ± 0.0 | 4.9% ± 0.0 |
| Situation inferred (grader, no anchor needed) | 71.6% ± 2.8 | 71.5% ± 3.8 | 71.7% ± 1.9 |
| Linkable disclosure (identity AND situation, same case) | 7.5% ± 0.6 | 6.7% ± 1.2 | 8.3% ± 0.0 |

Mean ± sample sd over attacked passes (sd is 0 with one pass).
