# Stage 2 — intra-function block localisation

- Corpus: `results/corpus_v2_three_targets`
- Stage 1 checkpoint: `results/train/stage1/best.pt`
- Trunk: **frozen Stage 1 GCN**; only the per-block head is trained
- Split: **three-target-v3** (train=791, val=219, test=127 graphs with localisation labels)
- Best epoch: **2** (selected on validation macro block F1)
- Test: evaluated **once** with validation-selected thresholds

A block is positive for a target when it contains CAPA evidence or an
import-resolved API reference inside a function positive for that target.
Blocks in weak-negative or unlabeled functions are excluded from the oracle
Stage 2 set.

## Oracle-function test (all true positive functions)

- Masked blocks: **14,051**

| label | support blocks | support funcs | threshold | precision | recall | F1 | IoU | AP | function hit |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `anti_debug` | 136 | 27 | 0.94 | 1.0000 | 0.0588 | **0.1111** | 0.0588 | 0.3364 | 0.1481 |
| `keylogger` | 1,344 | 149 | 0.50 | 0.4312 | 0.5900 | **0.4983** | 0.3318 | 0.4233 | 0.8658 |
| `injection` | 2,094 | 197 | 0.64 | 0.6462 | 0.9413 | **0.7663** | 0.6212 | 0.6175 | 0.9949 |

- Macro block F1: **0.4586**
- Macro block IoU: **0.3373**
- Macro function hit rate: **0.6696**

## End-to-end test (Stage 1 selected functions)

Stage 1 selects functions with its validation thresholds; Stage 2 scores
blocks only in those functions. Blocks in Stage 1 false-positive functions
count as block false positives, and blocks in missed true functions count as
block false negatives.

| label | selected funcs | true funcs | function P | function R | function F1 | block P | block R | block F1 | block IoU |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `anti_debug` | 19 | 27 | 0.7895 | 0.5556 | **0.6522** | 0.6667 | 0.1081 | **0.1860** | 0.1026 |
| `keylogger` | 161 | 153 | 0.3292 | 0.3464 | **0.3376** | 0.2980 | 0.6598 | **0.4106** | 0.2583 |
| `injection` | 351 | 202 | 0.3761 | 0.6535 | **0.4774** | 0.3585 | 0.9470 | **0.5202** | 0.3515 |

- Macro end-to-end block F1: **0.3723**
- Macro end-to-end block IoU: **0.2375**

## Validation (oracle-function)

| label | support blocks | support funcs | threshold | precision | recall | F1 | IoU | AP | function hit |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `anti_debug` | 158 | 27 | 0.94 | 0.9048 | 0.1203 | **0.2123** | 0.1187 | 0.1456 | 0.4074 |
| `keylogger` | 1,110 | 137 | 0.50 | 0.2383 | 0.4432 | **0.3099** | 0.1834 | 0.2015 | 0.4599 |
| `injection` | 2,943 | 179 | 0.64 | 0.7441 | 0.9426 | **0.8317** | 0.7118 | 0.7683 | 1.0000 |

- Macro block F1: **0.4513**; macro block IoU: **0.3380**

## Caveats

- The block labels are weak supervision: keylogger and injection positives are
  dominated by API-reference seeds, anti-debug by explicit instruction evidence.
  The metrics measure recovery of those seeds, not every malicious block.
- The anti-debug block threshold (0.94) was selected on 27 validation functions.
  It is very conservative: oracle test precision is 1.00 but recall is 0.059.
  Ranking is better than the thresholded score (test AP 0.336). This is a
  threshold-selection limitation, not evidence that the target is absent.
- Stage 2 is a frozen-trunk baseline. It does not fine-tune the GCN, and the
  test split is cluster-grouped. The end-to-end result includes Stage 1
  false-positive functions, so its precision is lower than the oracle-function
  result.
- Four keylogger and five injection positive functions have no CAPA evidence
  block that maps into the extracted CFG, so they have no block labels and are
  outside the oracle block supports. They still count in the function-level
  supports (153 and 202 test functions); they do not contribute block false
  negatives.
