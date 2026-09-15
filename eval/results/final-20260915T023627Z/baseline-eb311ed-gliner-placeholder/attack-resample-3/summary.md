# Adversary inference: airlock@eb311ed gliner=1 substitution=placeholder

- attacker: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning `none`)
- graders: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning `none`)
- attacked passes: 1 of the proxy run; cases per pass: 243
- tokens used: prompt 251170, completion 74413, about $0.47 at list prices

| Metric | All | ko | en |
|---|---:|---:|---:|
| Values recovered (full value) | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 |
| Values recovered (full or partial) | 1.8% ± 0.0 | 0.3% ± 0.0 | 2.9% ± 0.0 |
| Cases with any full value recovered | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 |
| Canary recovery (cases) | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 |
| Quasi re-identification (exact or partial attributes) | 20.0% ± 0.0 | 14.8% ± 0.0 | 26.1% ± 0.0 |
| Quasi re-identification (exact attributes only) | 10.0% ± 0.0 | 3.7% ± 0.0 | 17.4% ± 0.0 |
| Intent inferred (grader, named anchor required) | 29.6% ± 0.0 | 28.6% ± 0.0 | 30.8% ± 0.0 |
| Identity recovered (any identity item or quasi set) | 4.4% ± 0.0 | 3.8% ± 0.0 | 4.9% ± 0.0 |
| Situation inferred (grader, no anchor needed) | 72.2% ± 0.0 | 69.1% ± 0.0 | 75.5% ± 0.0 |
| Linkable disclosure (identity AND situation, same case) | 8.2% ± 0.0 | 8.0% ± 0.0 | 8.3% ± 0.0 |

Mean ± sample sd over attacked passes (sd is 0 with one pass).
