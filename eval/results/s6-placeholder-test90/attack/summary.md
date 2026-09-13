# Adversary inference: airlock 071c36c S6 round two, AIRLOCK_GLINER=on, AIRLOCK_SUBSTITUTION=placeholder, test split

- attacker: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning `none`)
- graders: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning `none`)
- attacked passes: 1 of the proxy run; cases per pass: 90
- tokens used: prompt 78289, completion 22870, about $0.15 at list prices

| Metric | All | ko | en |
|---|---:|---:|---:|
| Values recovered (full value) | 1.2% ± 0.0 | 1.8% ± 0.0 | 0.8% ± 0.0 |
| Values recovered (full or partial) | 2.9% ± 0.0 | 3.6% ± 0.0 | 2.3% ± 0.0 |
| Cases with any full value recovered | 4.8% ± 0.0 | 6.5% ± 0.0 | 3.1% ± 0.0 |
| Canary recovery (cases) | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 |
| Quasi re-identification (exact or partial attributes) | 15.8% ± 0.0 | 10.0% ± 0.0 | 22.2% ± 0.0 |
| Quasi re-identification (exact attributes only) | 10.5% ± 0.0 | 0.0% ± 0.0 | 22.2% ± 0.0 |
| Intent inferred (grader, named anchor required) | 20.0% ± 0.0 | 40.0% ± 0.0 | 0.0% ± 0.0 |
| Identity recovered (any identity item or quasi set) | 7.9% ± 0.0 | 7.9% ± 0.0 | 7.9% ± 0.0 |
| Situation inferred (grader, no anchor needed) | 72.5% ± 0.0 | 75.0% ± 0.0 | 70.0% ± 0.0 |
| Linkable disclosure (identity AND situation, same case) | 8.3% ± 0.0 | 5.6% ± 0.0 | 11.1% ± 0.0 |

Mean ± sample sd over attacked passes (sd is 0 with one pass).
