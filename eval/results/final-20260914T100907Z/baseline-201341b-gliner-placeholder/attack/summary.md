# Adversary inference: airlock@201341b gliner=1 substitution=placeholder

- attacker: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning `none`)
- graders: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning `none`)
- attacked passes: 3 of the proxy run; cases per pass: 243
- tokens used: prompt 749444, completion 221127, about $1.41 at list prices

| Metric | All | ko | en |
|---|---:|---:|---:|
| Values recovered (full value) | 0.4% ± 0.1 | 1.0% ± 0.3 | 0.0% ± 0.0 |
| Values recovered (full or partial) | 2.5% ± 0.2 | 1.9% ± 0.2 | 2.9% ± 0.3 |
| Cases with any full value recovered | 1.6% ± 0.3 | 3.2% ± 0.7 | 0.0% ± 0.0 |
| Canary recovery (cases) | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 |
| Quasi re-identification (exact or partial attributes) | 29.3% ± 3.1 | 24.7% ± 5.7 | 34.8% ± 0.0 |
| Quasi re-identification (exact attributes only) | 25.3% ± 4.2 | 23.5% ± 5.7 | 27.5% ± 2.5 |
| Intent inferred (grader, named anchor required) | 25.9% ± 0.0 | 19.0% ± 4.1 | 33.3% ± 4.4 |
| Identity recovered (any identity item or quasi set) | 8.4% ± 0.6 | 9.3% ± 1.5 | 7.5% ± 0.6 |
| Situation inferred (grader, no anchor needed) | 72.8% ± 1.1 | 73.9% ± 2.1 | 71.7% ± 3.8 |
| Linkable disclosure (identity AND situation, same case) | 13.9% ± 0.6 | 14.0% ± 3.5 | 13.9% ± 2.4 |

Mean ± sample sd over attacked passes (sd is 0 with one pass).
