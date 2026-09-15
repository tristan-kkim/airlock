# Adversary inference: baseline:gliner_pii

- attacker: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning `none`)
- graders: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning `none`)
- attacked passes: 3 of the proxy run; cases per pass: 243
- tokens used: prompt 0, completion 0

| Metric | All | ko | en |
|---|---:|---:|---:|
| Values recovered (full value) | 6.2% ± 0.0 | 7.9% ± 0.0 | 4.8% ± 0.0 |
| Values recovered (full or partial) | 9.3% ± 0.0 | 10.6% ± 0.0 | 8.3% ± 0.0 |
| Cases with any full value recovered | 18.1% ± 0.0 | 20.2% ± 0.0 | 16.1% ± 0.0 |
| Canary recovery (cases) | 11.0% ± 0.0 | 11.1% ± 0.0 | 11.0% ± 0.0 |
| Quasi re-identification (exact or partial attributes) | 22.0% ± 0.0 | 22.2% ± 0.0 | 21.7% ± 0.0 |
| Quasi re-identification (exact attributes only) | 10.0% ± 0.0 | 14.8% ± 0.0 | 4.3% ± 0.0 |
| Intent inferred (grader, named anchor required) | 37.0% ± 0.0 | 28.6% ± 0.0 | 46.2% ± 0.0 |
| Identity recovered (any identity item or quasi set) | 19.4% ± 0.0 | 20.2% ± 0.0 | 18.6% ± 0.0 |
| Situation inferred (grader, no anchor needed) | 63.0% ± 0.0 | 56.4% ± 0.0 | 69.8% ± 0.0 |
| Linkable disclosure (identity AND situation, same case) | 9.2% ± 0.0 | 10.0% ± 0.0 | 8.3% ± 0.0 |

Mean ± sample sd over attacked passes (sd is 0 with one pass).
