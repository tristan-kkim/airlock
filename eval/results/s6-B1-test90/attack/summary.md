# Adversary inference: airlock 79e9891 AIRLOCK_GLINER=on variant 1: agreement-only city,date_of_birth; Korean GLiNER-only names 3+ syllables

- attacker: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning `none`)
- graders: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning `none`)
- attacked passes: 1 of the proxy run; cases per pass: 90
- tokens used: prompt 173603, completion 63286

| Metric | All | ko | en |
|---|---:|---:|---:|
| Values recovered (full value) | 1.2% ± 0.0 | 1.8% ± 0.0 | 0.8% ± 0.0 |
| Values recovered (full or partial) | 4.6% ± 0.0 | 7.2% ± 0.0 | 2.3% ± 0.0 |
| Cases with any full value recovered | 4.8% ± 0.0 | 6.5% ± 0.0 | 3.1% ± 0.0 |
| Canary recovery (cases) | 0.0% ± 0.0 | 0.0% ± 0.0 | 0.0% ± 0.0 |
| Quasi re-identification (exact or partial attributes) | 26.3% ± 0.0 | 20.0% ± 0.0 | 33.3% ± 0.0 |
| Quasi re-identification (exact attributes only) | 21.1% ± 0.0 | 20.0% ± 0.0 | 22.2% ± 0.0 |
| Intent inferred (grader, named anchor required) | 10.0% ± 0.0 | 20.0% ± 0.0 | 0.0% ± 0.0 |
| Identity recovered (any identity item or quasi set) | 10.5% ± 0.0 | 10.5% ± 0.0 | 10.5% ± 0.0 |
| Situation inferred (grader, no anchor needed) | 55.0% ± 0.0 | 50.0% ± 0.0 | 60.0% ± 0.0 |
| Linkable disclosure (identity AND situation, same case) | 16.7% ± 0.0 | 11.1% ± 0.0 | 22.2% ± 0.0 |

Mean ± sample sd over attacked passes (sd is 0 with one pass).
