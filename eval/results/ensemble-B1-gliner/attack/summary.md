# Adversary inference: airlock 79e9891 AIRLOCK_GLINER=on variant 1: agreement-only city,date_of_birth; Korean GLiNER-only names 3+ syllables

- attacker: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning_effort `none`)
- grader: `nvidia/Nemotron-3-Ultra-550b-a55b` (reasoning_effort `none`)
- attacked passes: 1 of the proxy run; cases per pass: 243
- tokens used: prompt 173603, completion 63286

| Metric | All | ko | en |
|---|---:|---:|---:|
| Values recovered (full value) | 1.0% ± 0.0 | 0.7% ± 0.0 | 1.3% ± 0.0 |
| Values recovered (full or partial) | 3.7% ± 0.0 | 3.6% ± 0.0 | 3.7% ± 0.0 |
| Cases with any full value recovered | 4.1% ± 0.0 | 2.4% ± 0.0 | 5.7% ± 0.0 |
| Canary recovery (cases) | 0.7% ± 0.0 | 0.0% ± 0.0 | 1.4% ± 0.0 |
| Quasi re-identification (exact or partial attributes) | 34.0% ± 0.0 | 25.9% ± 0.0 | 43.5% ± 0.0 |
| Quasi re-identification (exact attributes only) | 26.0% ± 0.0 | 22.2% ± 0.0 | 30.4% ± 0.0 |
| Intent inferred (grader) | 33.3% ± 0.0 | 28.6% ± 0.0 | 38.5% ± 0.0 |

Mean ± sample sd over attacked passes (sd is 0 with one pass).
