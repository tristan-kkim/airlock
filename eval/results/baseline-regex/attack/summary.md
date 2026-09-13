# Adversary inference: baseline:regex

- attacker: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning_effort `none`)
- grader: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning_effort `none`)
- attacked passes: 1 of the proxy run; cases per pass: 243
- tokens used: prompt 235224, completion 86738

| Metric | All | ko | en |
|---|---:|---:|---:|
| Values recovered (full value) | 58.1% ± 0.0 | 56.1% ± 0.0 | 59.7% ± 0.0 |
| Values recovered (full or partial) | 61.4% ± 0.0 | 58.4% ± 0.0 | 63.7% ± 0.0 |
| Cases with any full value recovered | 87.7% ± 0.0 | 90.5% ± 0.0 | 85.1% ± 0.0 |
| Canary recovery (cases) | 82.8% ± 0.0 | 83.3% ± 0.0 | 82.2% ± 0.0 |
| Quasi re-identification (exact or partial attributes) | 92.0% ± 0.0 | 88.9% ± 0.0 | 95.7% ± 0.0 |
| Quasi re-identification (exact attributes only) | 90.0% ± 0.0 | 88.9% ± 0.0 | 91.3% ± 0.0 |
| Intent inferred (grader, named anchor required) | 85.2% ± 0.0 | 85.7% ± 0.0 | 84.6% ± 0.0 |
| Identity recovered (any identity item or quasi set) | 88.8% ± 0.0 | 90.4% ± 0.0 | 87.3% ± 0.0 |
| Situation inferred (grader, no anchor needed) | 80.6% ± 0.0 | 83.6% ± 0.0 | 77.4% ± 0.0 |
| Linkable disclosure (identity AND situation, same case) | 79.6% ± 0.0 | 82.0% ± 0.0 | 77.1% ± 0.0 |

Mean ± sample sd over attacked passes (sd is 0 with one pass).
