# Adversary inference: airlock 685d3c7 AIRLOCK_GLINER=off (HEAD detector)

- attacker: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning_effort `none`)
- grader: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning_effort `none`)
- attacked passes: 1 of the proxy run; cases per pass: 243
- tokens used: prompt 176282, completion 61221

| Metric | All | ko | en |
|---|---:|---:|---:|
| Values recovered (full value) | 9.9% ± 0.0 | 9.2% ± 0.0 | 10.4% ± 0.0 |
| Values recovered (full or partial) | 11.5% ± 0.0 | 11.2% ± 0.0 | 11.7% ± 0.0 |
| Cases with any full value recovered | 23.4% ± 0.0 | 23.8% ± 0.0 | 23.0% ± 0.0 |
| Canary recovery (cases) | 15.2% ± 0.0 | 13.9% ± 0.0 | 16.4% ± 0.0 |
| Quasi re-identification (exact or partial attributes) | 42.0% ± 0.0 | 29.6% ± 0.0 | 56.5% ± 0.0 |
| Quasi re-identification (exact attributes only) | 38.0% ± 0.0 | 25.9% ± 0.0 | 52.2% ± 0.0 |
| Intent inferred (grader) | 44.4% ± 0.0 | 28.6% ± 0.0 | 61.5% ± 0.0 |

Mean ± sample sd over attacked passes (sd is 0 with one pass).
