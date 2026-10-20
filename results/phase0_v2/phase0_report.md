# Phase 0 report

Generated: `2026-10-20T15:16:35+00:00`

## Corpus

- Files discovered: **4474**
- Clean files: **2733**
- Excluded: **1741**
- Header repair needed: **4470**
- Architecture (all / clean): `{'x86': 3619, 'x64': 855}` / `{'x86': 2733}`
- Median `.text` entropy (sampled): `7.0288`
- Duplicate content hashes: **0**

## Quality flags

| Flag | Files |
|---|---:|
| `packed` | 1485 |
| `dotnet` | 265 |
| `no_imports` | 8 |
| `non_bodmas` | 4 |

## Buckets

| Bucket | Total | Clean |
|---|---:|---:|
| `antidebug` | 2408 | 1381 |
| `injection` | 1529 | 1340 |
| `keylogger` | 537 | 12 |

## Families

| Family | Total | Clean |
|---|---:|---:|
| `ceeinject` | 1169 | 1113 |
| `gandcrab` | 957 | 935 |
| `zbot` | 473 | 354 |
| `cryptinject` | 192 | 104 |
| `emotet` | 56 | 50 |
| `qakbot` | 42 | 42 |
| `injector` | 58 | 36 |
| `ursnif` | 43 | 34 |
| `aitinject` | 27 | 26 |
| `trickbot` | 13 | 12 |
| `vbinject` | 12 | 11 |
| `bladabindi` | 491 | 6 |
| `smokeloader` | 868 | 3 |
| `agenttesla` | 14 | 2 |
| `keylogger` | 2 | 2 |
| `lokibot` | 24 | 2 |
| `dridex` | 10 | 1 |
| `carberp` | 14 | 0 |
| `pkeylog` | 5 | 0 |
| `unknown` | 4 | 0 |

## Clusters

- Clean imphash/sha clusters: **303**
- Singleton clusters: **118**
- Largest clusters:

| Cluster | Files |
|---|---:|
| `imphash:ef3fd1c1a81435e51fcc42212e25d2ec` | 890 |
| `imphash:b2c87e30ac29fd4e3024b6df9473add6` | 274 |
| `imphash:f54bab47f74e370cf85ce98d899e8149` | 126 |
| `imphash:022e75c8089eb1300c6b4ca118f5ca63` | 64 |
| `imphash:33b412eb0ccf59517cb6c9b4302ed662` | 53 |
| `imphash:649f6ed9a4d576c154bbc0357156a4a4` | 50 |
| `imphash:9e85bc8cd0863f7512a06d6eb4c79827` | 47 |
| `imphash:d1dd6793e073e1336544ec23582ec2cb` | 44 |
| `imphash:9e151e170df0a1329c9f41d17c80156c` | 34 |
| `imphash:9e93f1ba280c384f98cb85e46366f941` | 33 |

## Split: `main`

- Seed: `42`
- Manifest SHA-256: `09a6e1d8210914b920d6884d3d2bd085e1c55df583955336039d1bc91a1490c8`
- Counts: `{'test': 410, 'train': 1913, 'val': 410}`
- Clusters per split: `{'test': 99, 'train': 112, 'val': 92}`

| Bucket | Train | Val | Test |
|---|---:|---:|---:|
| `antidebug` | 967 | 207 | 207 |
| `injection` | 938 | 201 | 201 |
| `keylogger` | 8 | 2 | 2 |

## Split: `lofo`

- Seed: `42`
- Manifest SHA-256: `09a6e1d8210914b920d6884d3d2bd085e1c55df583955336039d1bc91a1490c8`
- Held-out families: `{'keylogger': 'bladabindi', 'injection': 'emotet', 'antidebug': 'ursnif'}`
- Counts: `{'test': 90, 'train': 2247, 'val': 396}`
- Clusters per split: `{'test': 51, 'train': 143, 'val': 109}`

| Bucket | Train | Val | Test |
|---|---:|---:|---:|
| `antidebug` | 1145 | 202 | 34 |
| `injection` | 1097 | 193 | 50 |
| `keylogger` | 5 | 1 | 6 |

## Validation

- Not run yet.

## Gate status

- [x] Manifest generated
- [x] Quality filters applied; no compute caps
- [x] Splits frozen and cluster-integrity checked
- [ ] angr load validation (see `results/phase0_validation.csv`)
- [ ] CAPA smoke test (see `results/phase0_capa_smoke.csv`)
- [ ] Full-set CAPA exit-code pass (belongs to Phase 1, not Phase 0)

