# Adversary inference: airlock@e0ee6aa gliner=1 substitution=surrogate

- attacker: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning `none`)
- graders: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning `none`)
- attacked passes: 3 of the proxy run; cases per pass: 243
- tokens used: prompt 740530, completion 258407, about $1.52 at list prices

| Metric | All | ko | en |
|---|---:|---:|---:|
| Values recovered (full value) | 0.1% ± 0.0 | 0.3% ± 0.0 | 0.0% ± 0.0 |
| Values recovered (full or partial) | 12.8% ± 0.4 | 8.9% ± 0.3 | 16.0% ± 0.5 |
| Cases with any full value recovered | 0.6% ± 0.0 | 1.2% ± 0.0 | 0.0% ± 0.0 |
| Canary recovery (cases) | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 |
| Quasi re-identification (exact or partial attributes) | 28.0% ± 0.0 | 18.5% ± 0.0 | 39.1% ± 0.0 |
| Quasi re-identification (exact attributes only) | 20.0% ± 0.0 | 11.1% ± 0.0 | 30.4% ± 0.0 |
| Intent inferred (grader, named anchor required) | 39.5% ± 9.3 | 31.0% ± 8.2 | 48.7% ± 11.8 |
| Identity recovered (any identity item or quasi set) | 7.8% ± 0.0 | 6.7% ± 0.0 | 8.8% ± 0.0 |
| Situation inferred (grader, no anchor needed) | 54.0% ± 2.1 | 48.5% ± 2.1 | 59.7% ± 2.2 |
| Linkable disclosure (identity AND situation, same case) | 12.6% ± 1.2 | 10.7% ± 1.2 | 14.6% ± 2.1 |

Mean ± sample sd over attacked passes (sd is 0 with one pass).
