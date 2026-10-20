# Stage 1 cross-version coverage

Metadata-only scoping report. No model performance is consulted.

- v2 clean samples: **2733**
- v1 samples removed by the v2 PE rule: **81**
- ... of which fall in v2 main train/val: **0**

## v2 main split coverage

| Split | Samples | Clusters | Families |
|---|---:|---:|---:|
| train | 1913 | 112 | 16 |
| val | 410 | 92 | 14 |
| test | 410 | 99 | 13 |

## v2 LOFO split coverage

| Split | Samples | Clusters | Families |
|---|---:|---:|---:|
| train | 2247 | 143 | 13 |
| val | 396 | 109 | 11 |
| test | 90 | 51 | 3 |

LOFO held-out families: `keylogger=bladabindi`, `injection=emotet`, `antidebug=ursnif`

## Removed samples by family / bucket

| Family | Removed |
|---|---:|
| `zbot` | 25 |
| `lokibot` | 21 |
| `ceeinject` | 14 |
| `dridex` | 9 |
| `pkeylog` | 5 |
| `injector` | 5 |
| `gandcrab` | 2 |

| Bucket | Removed |
|---|---:|
| `antidebug` | 36 |
| `keylogger` | 26 |
| `injection` | 19 |

Held-out positive binary/cluster coverage can only be finalised after full
v2 labels; the pre-registered minima are >=10 held-out positive binaries
and >=5 held-out positive clusters per active label.
