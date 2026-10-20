# Stage 1 pilot — findings

**Status:** pilot pipeline gate **PASS**. Training is not started yet.
**Data:** Phase 0 v2 (`data/versions/v2/`), 2,733 clean samples / 303 clusters.
**Selection:** 200 samples from v2 main **train/val only**, per-cluster cap 4,
test never eligible (`results/stage1/samples.json`).
**Contract:** `stage1-v2` — active labels `anti_debug`, `injection`; keylogger
excluded from targets and loss (`src/label/contract.py`).

## Pipeline results

| Stage | Result |
|---|---|
| CAPA 9.1.0 | 200/200 ok, 0 failures, 0 timeouts; rules commit pinned + clean |
| angr mapping | 200/200 samples, 0 failures, 0 timeouts |
| CAPA-observed → angr coverage | **99.59%** (≥95% required) |
| Target-match → angr coverage | **100%** (≥95% required) |
| Unresolved target matches | **0** (0.000%, <2% required) |
| Many-to-one collisions | 380 rows across 70 samples, 0 conflicting positives |
| Full-pilot scope | yes (all 200, not a subset) |

**Overall pilot gate: PASS.**

## Label projections (both pass ≥300)

| Label | Positive functions | Projected full-set | Gate ≥300 |
|---|---:|---:|---|
| `anti_debug` | 29 | 396.5 | PASS |
| `injection` | 106 | 1,447.4 | PASS |

## Diversity diagnostics (pre-registered)

| Label | Functions | Binaries | Clusters | Families | Top binary | Top cluster | Ready |
|---|---:|---:|---:|---:|---:|---:|---|
| `anti_debug` | 29 | 29 | 3 | 2 | 3.4% | **89.7%** | NO |
| `injection` | 106 | 49 | 21 | 3 | 19.8% | 39.6% | NO |

Criteria: ≥20 binaries, ≥10 clusters, ≥3 families, top binary ≤50%, top cluster
≤50%.

- **`anti_debug` fails cluster diversity decisively.** ~90% of pilot positives
  are in a single imphash cluster. Any `anti_debug` result is **exploratory**
  and cannot be described as demonstrated generalization. It remains trainable.
- **`injection` is the stronger primary candidate.** It passes the share tests
  (top cluster 39.6% ≤ 50%) and has 49 binaries / 21 clusters / 3 families.
  Family coverage (3) is the weakest dimension and should be re-checked on full
  labels.

## Collision inspection

- 380 collision rows in 70 samples; the largest groups are gandcrab samples
  (12–13 collisions each).
- Representative collisions are **label-union on weak negatives**: multiple
  CAPA functions merged into one angr function with no target rules. No
  representative collision carried conflicting positive labels. The full list is
  in `results/stage1/collision_inspection.json`.

## Ghidra spot-check

- `results/stage1/ghidra_audit_sheet.csv` holds **40** functions stratified by
  active-label positives, bucket weak negatives, and containment mappings, with
  the sample path, function VA, matched rules, and mapping method. Fill
  `audit_verdict`/`audit_notes` to complete the 30–50-function audit. This is an
  audit of mapping/labels, not ground truth.

## Consequences

- The v2 packed filter and the two-label contract are validated at pilot scale;
  the pipeline may proceed to full-set v2 labeling.
- `injection` is positioned as the primary result; `anti_debug` as a
  conditional/exploratory result driven by its cluster concentration.
- Full-set labels are required before the held-out (≥10 binaries / ≥5 clusters)
  coverage checks can be finalized.
