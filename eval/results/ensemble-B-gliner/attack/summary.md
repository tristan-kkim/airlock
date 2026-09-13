# Adversary inference: airlock 685d3c7 AIRLOCK_GLINER=on (threshold 0.4, cpu, adjudication on)

- attacker: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning_effort `none`)
- grader: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning_effort `none`)
- attacked passes: 1 of the proxy run; cases per pass: 243
- tokens used: prompt 169626, completion 60791

| Metric | All | ko | en |
|---|---:|---:|---:|
| Values recovered (full value) | 0.6% ± 0.0 | 1.0% ± 0.0 | 0.3% ± 0.0 |
| Values recovered (full or partial) | 2.4% ± 0.0 | 2.3% ± 0.0 | 2.4% ± 0.0 |
| Cases with any full value recovered | 2.3% ± 0.0 | 3.6% ± 0.0 | 1.1% ± 0.0 |
| Canary recovery (cases) | 1.4% ± 0.0 | 1.4% ± 0.0 | 1.4% ± 0.0 |
| Quasi re-identification (exact or partial attributes) | 30.0% ± 0.0 | 22.2% ± 0.0 | 39.1% ± 0.0 |
| Quasi re-identification (exact attributes only) | 22.0% ± 0.0 | 18.5% ± 0.0 | 26.1% ± 0.0 |
| Intent inferred (grader) | 14.8% ± 0.0 | 7.1% ± 0.0 | 23.1% ± 0.0 |

Mean ± sample sd over attacked passes (sd is 0 with one pass).
