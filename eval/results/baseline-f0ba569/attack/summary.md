# Adversary inference: baseline f0ba569: Nano-4B Q4 + Ultra

- attacker: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning_effort `none`)
- grader: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning_effort `none`)
- attacked passes: 1 of the proxy run; cases per pass: 243
- tokens used: prompt 239567, completion 73921

| Metric | All | ko | en |
|---|---:|---:|---:|
| Values recovered (full value) | 4.9% ± 0.0 | 5.9% ± 0.0 | 4.0% ± 0.0 |
| Values recovered (full or partial) | 6.5% ± 0.0 | 7.3% ± 0.0 | 5.9% ± 0.0 |
| Cases with any full value recovered | 11.7% ± 0.0 | 14.3% ± 0.0 | 9.2% ± 0.0 |
| Canary recovery (cases) | 6.9% ± 0.0 | 6.9% ± 0.0 | 6.8% ± 0.0 |
| Quasi re-identification (exact or partial attributes) | 40.0% ± 0.0 | 29.6% ± 0.0 | 52.2% ± 0.0 |
| Quasi re-identification (exact attributes only) | 38.0% ± 0.0 | 29.6% ± 0.0 | 47.8% ± 0.0 |
| Intent inferred (grader, named anchor required) | 29.6% ± 0.0 | 14.3% ± 0.0 | 46.2% ± 0.0 |
| Identity recovered (any identity item or quasi set) | 18.0% ± 0.0 | 19.2% ± 0.0 | 16.7% ± 0.0 |
| Situation inferred (grader, no anchor needed) | 61.1% ± 0.0 | 56.4% ± 0.0 | 66.0% ± 0.0 |
| Linkable disclosure (identity AND situation, same case) | 17.3% ± 0.0 | 18.0% ± 0.0 | 16.7% ± 0.0 |

Mean ± sample sd over attacked passes (sd is 0 with one pass).
