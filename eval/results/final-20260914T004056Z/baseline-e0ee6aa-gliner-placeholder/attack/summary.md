# Adversary inference: airlock@e0ee6aa gliner=1 substitution=placeholder

- attacker: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning `none`)
- graders: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning `none`)
- attacked passes: 3 of the proxy run; cases per pass: 243
- tokens used: prompt 752053, completion 220652, about $1.41 at list prices

| Metric | All | ko | en |
|---|---:|---:|---:|
| Values recovered (full value) | 0.6% ± 0.0 | 1.3% ± 0.0 | 0.0% ± 0.0 |
| Values recovered (full or partial) | 2.5% ± 0.1 | 2.3% ± 0.3 | 2.7% ± 0.0 |
| Cases with any full value recovered | 2.3% ± 0.0 | 4.8% ± 0.0 | 0.0% ± 0.0 |
| Canary recovery (cases) | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 |
| Quasi re-identification (exact or partial attributes) | 32.7% ± 1.2 | 22.2% ± 0.0 | 44.9% ± 2.5 |
| Quasi re-identification (exact attributes only) | 23.3% ± 1.2 | 17.3% ± 2.1 | 30.4% ± 0.0 |
| Intent inferred (grader, named anchor required) | 25.9% ± 6.4 | 14.3% ± 12.4 | 38.5% ± 13.3 |
| Identity recovered (any identity item or quasi set) | 10.2% ± 0.0 | 10.6% ± 0.0 | 9.8% ± 0.0 |
| Situation inferred (grader, no anchor needed) | 71.0% ± 2.8 | 67.3% ± 3.1 | 74.8% ± 2.9 |
| Linkable disclosure (identity AND situation, same case) | 15.3% ± 1.0 | 14.0% ± 0.0 | 16.7% ± 2.1 |

Mean ± sample sd over attacked passes (sd is 0 with one pass).
