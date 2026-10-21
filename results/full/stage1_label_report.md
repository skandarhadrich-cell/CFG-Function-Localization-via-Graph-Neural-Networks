# Stage 1 Label Contract Report

- Scope: **full**
- Samples selected: **2733**
- Samples processed: **2731**
- Missing CAPA JSON: **2**
- Active labels: **anti_debug, injection**

## CAPA census

- CAPA-observed functions: **409513**
- Stage 1 positive functions: **1889**
- Function-scope target matches: **1911**
- Basic-block target matches: **1500**
- Unresolved CAPA-layout block matches: **0**

| Label | Positive functions | Projected full-set | Gate >=300 |
|---|---:|---:|---|
| `anti_debug` | 534 | 534.0 | PASS |
| `injection` | 1355 | 1355.0 | PASS |

## Diversity diagnostics

These are pre-registered claim diagnostics, not performance-tuned thresholds.

| Label | Functions | Binaries | Clusters | Families | Top binary | Top cluster | Ready |
|---|---:|---:|---:|---:|---:|---:|---|
| `anti_debug` | 534 | 373 | 21 | 10 | 17.6% | 51.3% | NO |
| `injection` | 1355 | 808 | 110 | 12 | 1.5% | 32.8% | YES |

Diversity criteria: >=20 positive binaries, >=10 clusters, >=3 families, top binary <=50%, top cluster <=50%. Labels that fail remain eligible for training but cannot support a binary-level generalization claim.

## Mapping

- Mapping samples: **2728** (full)
- CAPA-observed -> angr coverage: **0.9957559033967425**
- Target-match -> angr coverage: **0.9956024626209323**
- Unresolved target rate: **0.440%**
- Many-to-one collisions: **6628**

## Per bucket

| Bucket | Selected | Processed | Observed | Positive functions | Projected full-set positive functions |
|---|---:|---:|---:|---:|---|
| `keylogger` | 12 | 12 | 16220 | 111 | 111.0 |
| `injection` | 1340 | 1338 | 153001 | 367 | 367.0 |
| `antidebug` | 1381 | 1381 | 240292 | 1411 | 1411.0 |

## CAPA label counts by source bucket

`source_bucket` is stratification metadata, not ground truth.

| Bucket | anti_debug | injection |
|---|---:|---:|
| `keylogger` | 106 | 5 |
| `injection` | 116 | 251 |
| `antidebug` | 312 | 1099 |

## Gate summary

- Mapping output available: **True**
- Mapping covers all labelable samples: **True**
- CAPA-observed mapping >=95%: **True**
- Target-match mapping >=95%: **True**
- Unresolved target rate <2%: **True**
- All selected samples processed: **True**
- Diversity ready: `anti_debug`=False, `injection`=True
- Overall pipeline gate: **PASS**

Weak negatives mean only that no selected CAPA rule matched in a function CAPA analyzed. They are not benign labels.
