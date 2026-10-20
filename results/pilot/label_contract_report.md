# Pilot Label Contract Report

- Samples selected: **200**
- Samples processed: **200**
- Missing CAPA JSON: **0**

## CAPA census

- CAPA-observed functions: **28992**
- Positive functions: **236**
- Weak-negative functions: **28756**
- Function-scope target matches: **169**
- Basic-block target matches: **77**
- Unresolved CAPA-layout block matches: **0**

| Label | Positive functions | Projected full-set | Gate ≥300 |
|---|---:|---:|---|
| `anti_debug` | 121 | 473.0 | PASS |
| `keylogger` | 45 | 241.6 | FAIL |
| `injection` | 71 | 1126.7 | PASS |

## Mapping

- Mapping samples: **5** (subset)
- CAPA-observed → angr coverage: **0.9980513728963685**
- Target-match → angr coverage: **1.0**
- Unresolved target rate: **0.000%**
- Many-to-one collisions: **41**

## Per bucket

| Bucket | Selected | Processed | Observed | Positive functions | Projected full-set positive functions |
|---|---:|---:|---:|---:|---|
| `antidebug` | 84 | 84 | 15600 | 87 | 1484.5 |
| `injection` | 84 | 84 | 1953 | 12 | 194.1 |
| `keylogger` | 32 | 32 | 11439 | 137 | 162.7 |

## CAPA label counts by source bucket

`source_bucket` is stratification metadata, not ground truth.

| Bucket | anti_debug | keylogger | injection |
|---|---:|---:|---:|
| `antidebug` | 21 | 12 | 55 |
| `injection` | 0 | 0 | 12 |
| `keylogger` | 100 | 33 | 4 |

## Gate summary

- Mapping output available: **True**
- Mapping covers all pilot samples: **False**
- CAPA-observed mapping ≥95%: **True**
- Target-match mapping ≥95%: **True**
- Unresolved target rate <2%: **True**
- All selected samples processed: **True**
- Overall: **STOP / REVISE**

Weak negatives mean only that no selected CAPA rule matched in a function CAPA analyzed. They are not benign labels.
