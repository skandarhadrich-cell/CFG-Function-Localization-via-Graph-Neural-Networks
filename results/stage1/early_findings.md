# Stage 1 pilot — early findings

Stage 1 pilot selection (`--selection stage1`): 200 samples from Phase 0 v2
main **train/val only**, hard per-cluster cap of 4, family-balanced fill,
test never eligible.

- Selected: 200 (antidebug 101, injection 99), 200 distinct imphash clusters.
- CAPA 9.1.0: 200/200 succeeded, 0 failures, 0 timeouts, 0 skips needed on
  re-verify. Rules commit pinned and clean.
- CAPA-observed functions: 17,872.

## Label projection (CAPA-only, before mapping)

| Label | Positive functions (pilot) | Projected full-set | Gate ≥300 |
|---|---:|---:|---|
| `anti_debug` | 29 | 396.5 | PASS |
| `injection` | 106 | 1,447.4 | PASS |

## Diversity diagnostics (pre-registered)

| Label | Functions | Binaries | Clusters | Families | Top binary | Top cluster | Ready |
|---|---:|---:|---:|---:|---:|---:|---|
| `anti_debug` | 29 | 29 | 3 | 2 | 3.4% | 89.7% | NO |
| `injection` | 106 | 49 | 21 | 3 | 19.8% | 39.6% | NO |

Interpretation (no model performance consulted):

- Both active labels clear the ≥300-function projection gate, so Stage 1 can
  train two outputs.
- **`anti_debug` fails cluster diversity**: 89.7% of pilot positives sit in one
  imphash cluster. Any `anti_debug` result must be reported as **exploratory**,
  not demonstrated generalization.
- **`injection` clears the share tests** (top cluster 39.6% ≤ 50%) and has 49
  binaries / 21 clusters, but only 3 families. It is the stronger primary
  candidate but family coverage is thin.
- Diversity here is measured on CAPA positives in the pilot; mapping may move
  counts slightly. Re-measure after mapping and again after full labels.

## Bucket note

The pilot deliberately over-weights the smaller bucket: the antidebug bucket
contributes 121 of 135 Stage 1 positive functions, while the injection bucket
contributes 14. Per-bucket projections are therefore not the label projection —
they are a stratification artifact, and `source_bucket` remains metadata, not
ground truth.

## Next

- Full-pilot angr mapping (running) → label table → gate report with mapping
  coverage and unresolved-target rate.
- Collision inspection and the 30–50-function Ghidra audit sheet.
- Full-set v2 labeling only after the pilot gates settle.
