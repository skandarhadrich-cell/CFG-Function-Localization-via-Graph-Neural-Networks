# Phase 0 v2 packed-filter audit

- v1 manifest: `/home/lali/cfg-gnn/data/versions/v1/manifest.csv`
- v1 manifest SHA-256: `fcd27780a1964b04faf68c4f8d637fcca6a232b183d155152beec3b28a903d7e`
- Candidate rule: `text_entropy >= T` and `num_imports <= 20`
- CAPA packer detections are an audit signal only; they are not used by the filter.

## Threshold comparison

| Threshold | Removed | Audit caught | Audit missed |
|---:|---:|---:|---:|
| 7.8 | 81 | 27/27 | 0 |
| 7.9 | 67 | 26/27 | 1 |

### Removed by bucket

| Threshold | antidebug | injection | keylogger |
|---:|---:|---:|---:|
| 7.8 | 36 | 19 | 26 |
| 7.9 | 26 | 15 | 26 |

## Samples removed only by 7.8

| Sample | Bucket | Family | Entropy | Imports | W+X sections | Max section entropy | CAPA packer |
|---|---|---|---:|---:|---|---:|---|
| `0a5d8377d237` | antidebug | zbot | 7.8593 | 2 | - | 7.999 | - |
| `16f9863a68d6` | antidebug | zbot | 7.8593 | 2 | - | 7.999 | - |
| `179e7cc46f61` | antidebug | zbot | 7.8593 | 2 | - | 7.999 | - |
| `1c2edff65ec2` | antidebug | zbot | 7.8593 | 2 | - | 7.999 | - |
| `2ef869e88b1f` | injection | ceeinject | 7.8232 | 1 | - | 7.823 | - |
| `5356d625b866` | antidebug | zbot | 7.8593 | 2 | - | 7.999 | - |
| `5d7c19a07236` | injection | ceeinject | 7.8232 | 1 | - | 7.823 | - |
| `6c1ce6e268bb` | injection | ceeinject | 7.8232 | 1 | - | 7.823 | - |
| `8abdfc43e60e` | antidebug | zbot | 7.8593 | 2 | - | 7.999 | - |
| `934eb8a68612` | antidebug | zbot | 7.8593 | 2 | - | 7.999 | - |
| `9f74d3e1e6c6` | antidebug | zbot | 7.8593 | 2 | - | 7.999 | - |
| `ac08c48f2004` | antidebug | zbot | 7.8919 | 2 | - | 7.999 | - |
| `b353ddcb0bb1` | injection | ceeinject | 7.8232 | 1 | - | 7.823 | - |
| `bba922518b5c` | antidebug | zbot | 7.8896 | 2 | - | 7.999 | - |

## Audit flags missed at each threshold

- **7.8**: none.
- **7.9**:
  - `179e7cc46f61` (zbot, entropy 7.8593, imports 2)

## Recommendation

**7.8** — 7.8 catches every pilot audit flag. The 14 samples removed only at 7.8 form two clusters with high-entropy sections or writable+executable sections, so 7.9 would retain likely packed files.

This is a dataset-quality decision. It must not be chosen by comparing resulting positive-label counts.
