# Adversary inference: baseline:raw

- attacker: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning_effort `none`)
- grader: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning_effort `none`)
- attacked passes: 1 of the proxy run; cases per pass: 243
- tokens used: prompt 174655, completion 82065

| Metric | All | ko | en |
|---|---:|---:|---:|
| Values recovered (full value) | 95.7% ± 0.0 | 94.7% ± 0.0 | 96.5% ± 0.0 |
| Values recovered (full or partial) | 96.5% ± 0.0 | 96.4% ± 0.0 | 96.5% ± 0.0 |
| Cases with any full value recovered | 94.2% ± 0.0 | 95.2% ± 0.0 | 93.1% ± 0.0 |
| Canary recovery (cases) | 93.8% ± 0.0 | 94.4% ± 0.0 | 93.2% ± 0.0 |
| Quasi re-identification (exact or partial attributes) | 92.0% ± 0.0 | 85.2% ± 0.0 | 100.0% ± 0.0 |
| Quasi re-identification (exact attributes only) | 90.0% ± 0.0 | 85.2% ± 0.0 | 95.7% ± 0.0 |
| Intent inferred (grader) | 88.9% ± 0.0 | 92.9% ± 0.0 | 84.6% ± 0.0 |

Mean ± sample sd over attacked passes (sd is 0 with one pass).
