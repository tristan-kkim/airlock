# Adversary inference: baseline:presidio_ko

- attacker: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning_effort `none`)
- grader: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning_effort `none`)
- attacked passes: 1 of the proxy run; cases per pass: 243
- tokens used: prompt 176577, completion 69322

| Metric | All | ko | en |
|---|---:|---:|---:|
| Values recovered (full value) | 31.4% ± 0.0 | 40.3% ± 0.0 | 24.3% ± 0.0 |
| Values recovered (full or partial) | 36.4% ± 0.0 | 46.9% ± 0.0 | 28.0% ± 0.0 |
| Cases with any full value recovered | 77.8% ± 0.0 | 85.7% ± 0.0 | 70.1% ± 0.0 |
| Canary recovery (cases) | 78.6% ± 0.0 | 81.9% ± 0.0 | 75.3% ± 0.0 |
| Quasi re-identification (exact or partial attributes) | 48.0% ± 0.0 | 63.0% ± 0.0 | 30.4% ± 0.0 |
| Quasi re-identification (exact attributes only) | 40.0% ± 0.0 | 59.3% ± 0.0 | 17.4% ± 0.0 |
| Intent inferred (grader, named anchor required) | 63.0% ± 0.0 | 71.4% ± 0.0 | 53.8% ± 0.0 |
| Identity recovered (any identity item or quasi set) | 73.8% ± 0.0 | 82.7% ± 0.0 | 64.7% ± 0.0 |
| Situation inferred (grader, no anchor needed) | 77.8% ± 0.0 | 81.8% ± 0.0 | 73.6% ± 0.0 |
| Linkable disclosure (identity AND situation, same case) | 53.1% ± 0.0 | 64.0% ± 0.0 | 41.7% ± 0.0 |

Mean ± sample sd over attacked passes (sd is 0 with one pass).
