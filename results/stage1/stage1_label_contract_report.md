# Pilot Label Contract Report

- Samples selected: **200**
- Samples processed: **200**
- Missing CAPA JSON: **0**
- Active labels: **anti_debug, injection**

## CAPA census

- CAPA-observed functions: **17872**
- Stage 1 positive functions: **135**
- Function-scope target matches: **41**
- Basic-block target matches: **120**
- Unresolved CAPA-layout block matches: **0**

| Label | Positive functions | Projected full-set | Gate >=300 |
|---|---:|---:|---|
| `anti_debug` | 29 | 396.5 | PASS |
| `injection` | 106 | 1447.4 | PASS |

## Diversity diagnostics

These are pre-registered claim diagnostics, not performance-tuned thresholds.

| Label | Functions | Binaries | Clusters | Families | Top binary | Top cluster | Ready |
|---|---:|---:|---:|---:|---:|---:|---|
| `anti_debug` | 29 | 29 | 3 | 2 | 3.4% | 89.7% | NO |
| `injection` | 106 | 49 | 21 | 3 | 19.8% | 39.6% | NO |

Diversity criteria: >=20 positive binaries, >=10 clusters, >=3 families, top binary <=50%, top cluster <=50%. Labels that fail remain eligible for training but cannot support a binary-level generalization claim.

## Mapping

- Mapping samples: **200** (pilot)
- CAPA-observed -> angr coverage: **0.9959153983885407**
- Target-match -> angr coverage: **1.0**
- Unresolved target rate: **0.000%**
- Many-to-one collisions: **380**

## Per bucket

| Bucket | Selected | Processed | Observed | Positive functions | Projected full-set positive functions |
|---|---:|---:|---:|---:|---|
| `antidebug` | 101 | 101 | 15743 | 121 | 1654.5 |
| `injection` | 99 | 99 | 2129 | 14 | 189.5 |

## CAPA label counts by source bucket

`source_bucket` is stratification metadata, not ground truth.

| Bucket | anti_debug | injection |
|---|---:|---:|
| `antidebug` | 29 | 92 |
| `injection` | 0 | 14 |

## Gate summary

- Mapping output available: **True**
- Mapping covers all pilot samples: **True**
- CAPA-observed mapping >=95%: **True**
- Target-match mapping >=95%: **True**
- Unresolved target rate <2%: **True**
- All selected samples processed: **True**
- Diversity ready: `anti_debug`=False, `injection`=False
- Overall pipeline gate: **PASS**

Weak negatives mean only that no selected CAPA rule matched in a function CAPA analyzed. They are not benign labels.
