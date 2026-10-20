# Phase 0 v1 -> v2 change report

v1 is frozen and was not modified. v2 changes only the packed-sample
quality filter; no compute-driven caps were added.

## Corpus counts

| Version | Clean samples | Clusters | SHA-256 |
|---|---:|---:|---|
| v1 | 2814 | 310 | `fcd27780a1964b04...` |
| v2 | 2733 | 303 | `09a6e1d8210914b9...` |

- v2 clean change: **-81**
- Removed clean samples: **81**
- Added clean samples: **0**
- Filter rule: `text_entropy >= 7.8 and num_imports <= 20 (PE-only); CAPA packer rules are audit-only`

### Removed by bucket

| Bucket | Removed |
|---|---:|
| `antidebug` | 36 |
| `injection` | 19 |
| `keylogger` | 26 |

### Removed by family (top 15)

| Family | Removed |
|---|---:|
| `zbot` | 25 |
| `lokibot` | 21 |
| `ceeinject` | 14 |
| `dridex` | 9 |
| `pkeylog` | 5 |
| `injector` | 5 |
| `gandcrab` | 2 |

- Clusters wholly removed: **7**
- Clusters reduced in size: **1**

## Splits

| Protocol | v1 counts | v2 counts | Common samples | Same split | Changed | Test overlap |
|---|---|---|---:|---:|---:|---:|
| main | `{'test': 422, 'train': 1969, 'val': 423}` | `{'test': 410, 'train': 1913, 'val': 410}` | 2733 | 2093 | 640 | 175 |
| lofo | `{'test': 107, 'train': 2302, 'val': 405}` | `{'test': 90, 'train': 2247, 'val': 396}` | 2733 | 2426 | 307 | 84 |

## v2 integrity checks

- v2 splits bind to v2 manifest SHA: **True**
- Main no cluster crossing splits: **True**
- LOFO no cluster crossing splits: **True**
- Held-out family only in test: **True**
- No duplicate content hashes among clean samples: **True**

LOFO held-out families (v2): `keylogger=bladabindi`, `injection=emotet`, `antidebug=ursnif`

The keylogger LOFO entry is retained only for future work; keylogger is not
an active Stage 1 target and is excluded from Stage 1 training/loss.
