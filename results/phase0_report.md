# Phase 0 report

Generated: `2026-10-20T13:17:07+00:00`

## Corpus

- Files discovered: **4474**
- Clean files: **2814**
- Excluded: **1660**
- Header repair needed: **4470**
- Architecture (all / clean): `{'x86': 3619, 'x64': 855}` / `{'x86': 2805, 'x64': 9}`
- Median `.text` entropy (sampled): `7.0288`
- Duplicate content hashes: **0**

## Quality flags

| Flag | Files |
|---|---:|
| `packed` | 1398 |
| `dotnet` | 265 |
| `no_imports` | 8 |
| `non_bodmas` | 4 |

## Buckets

| Bucket | Total | Clean |
|---|---:|---:|
| `antidebug` | 2408 | 1417 |
| `injection` | 1529 | 1359 |
| `keylogger` | 537 | 38 |

## Families

| Family | Total | Clean |
|---|---:|---:|
| `ceeinject` | 1169 | 1127 |
| `gandcrab` | 957 | 937 |
| `zbot` | 473 | 379 |
| `cryptinject` | 192 | 104 |
| `emotet` | 56 | 50 |
| `qakbot` | 42 | 42 |
| `injector` | 58 | 41 |
| `ursnif` | 43 | 34 |
| `aitinject` | 27 | 26 |
| `lokibot` | 24 | 23 |
| `trickbot` | 13 | 12 |
| `vbinject` | 12 | 11 |
| `dridex` | 10 | 10 |
| `bladabindi` | 491 | 6 |
| `pkeylog` | 5 | 5 |
| `smokeloader` | 868 | 3 |
| `agenttesla` | 14 | 2 |
| `keylogger` | 2 | 2 |
| `carberp` | 14 | 0 |
| `unknown` | 4 | 0 |

## Clusters

- Clean imphash/sha clusters: **310**
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
- Manifest SHA-256: `fcd27780a1964b04faf68c4f8d637fcca6a232b183d155152beec3b28a903d7e`
- Counts: `{'test': 422, 'train': 1969, 'val': 423}`
- Clusters per split: `{'test': 103, 'train': 112, 'val': 95}`

| Bucket | Train | Val | Test |
|---|---:|---:|---:|
| `antidebug` | 992 | 213 | 212 |
| `injection` | 951 | 204 | 204 |
| `keylogger` | 26 | 6 | 6 |

## Split: `lofo`

- Seed: `42`
- Manifest SHA-256: `fcd27780a1964b04faf68c4f8d637fcca6a232b183d155152beec3b28a903d7e`
- Held-out families: `{'keylogger': 'lokibot', 'injection': 'emotet', 'antidebug': 'ursnif'}`
- Counts: `{'test': 107, 'train': 2302, 'val': 405}`
- Clusters per split: `{'test': 48, 'train': 151, 'val': 111}`

| Bucket | Train | Val | Test |
|---|---:|---:|---:|
| `antidebug` | 1176 | 207 | 34 |
| `injection` | 1113 | 196 | 50 |
| `keylogger` | 13 | 2 | 23 |

## Validation

- angr load: **2814/2814** ok, **0** failed
- CAPA smoke: **12/12** exit 0

## Gate status

- [x] Manifest generated
- [x] Quality filters applied; no compute caps
- [x] Splits frozen and cluster-integrity checked
- [x] angr load validation (see `results/phase0_validation.csv`)
- [x] CAPA smoke test (see `results/phase0_capa_smoke.csv`)
- [ ] Full-set CAPA exit-code pass (belongs to Phase 1, not Phase 0)

