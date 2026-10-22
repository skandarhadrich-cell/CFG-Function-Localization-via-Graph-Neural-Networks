# CAPA label contract — three targets

**Version:** `stage1-three-target-v1`
**Tool:** CAPA 9.1.0, rules commit `805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5`
**Scope:** x86 PE, BODMAS v2 clean set.

This document defines what a positive, a weak negative, and an unlabeled
function mean. The labels are CAPA rule matches, not ground-truth annotations.

## 1. Target namespaces

A rule is in scope only when its `meta.namespace` starts with one of:

| label | namespace |
|---|---|
| `anti_debug` | `anti-analysis/anti-debugging` |
| `keylogger` | `collection/keylog` |
| `injection` | `host-interaction/process/inject`, `load-code/pe/inject-` |

Only `meta.scopes.static` values `function` and `basic block` produce Stage 1
labels. File-, process-, and call-scope matches are ignored.

## 2. Function inventory

Use `meta.analysis.feature_counts.functions` as the analyzed-function
inventory. `meta.analysis.layout.functions` is not an inventory: CAPA emits a
layout entry only for functions containing a matched basic block. A
function-scope-only match does not necessarily create one.

For basic-block matches, resolve the block to its parent function through
`meta.analysis.layout.functions[].matched_basic_blocks`.

## 3. Addresses

CAPA addresses are normalized to RVAs by subtracting
`meta.analysis.base_address`. The mapping layer compares those RVAs with the
angr function/block ranges in the extracted CFG. The final label table stores
the absolute angr `func_va` alongside the CAPA RVA.

## 4. Three states

| state | definition | used in loss/metrics |
|---|---|---|
| `positive` | mapped function with at least one active target rule match | yes, as positive |
| `weak_negative` | mapped function with no active target match, in a sample where CAPA matched at least one rule of any kind | yes, as negative |
| `unlabeled` | angr function not mapped to CAPA's observed inventory, or sample with no CAPA rule match at all | no |

A weak negative is **not** a benign function. The corpus is malware-only. A
sample with zero CAPA rules is unlabeled and excluded from the loss; its list is
`data/labels/zero_rule_samples.json`.

## 5. Multi-label

The three targets are independent. A function can be positive for more than one
target; the model uses three sigmoids and `BCEWithLogitsLoss`. The background
class is "none of the three", not a fourth learned class.

## 6. Label table

`data/labels/stage1_full_three_targets.parquet` has one row per mapped angr
function:

| column | meaning |
|---|---|
| `sample_id` | BODMAS sample SHA-256 |
| `func_va` | absolute angr function address |
| `capa_func_va` | CAPA function RVA, when mapped |
| `label_anti_debug`, `label_keylogger`, `label_injection` | 0/1 target flags |
| `label_status` | `positive`, `weak_negative`, `unlabeled` |
| `label_mask` | bitmask over the three labels |
| `matched_rules` | CAPA rule names contributing to the labels |
| `matched_block_vas` | absolute block addresses for block-scope matches |
| `mapping_method` | `exact`, `containment`, or `unmapped` |
| `source_bucket`, `family`, `cluster_key`, `split` | stratification metadata |

Current counts (2,727 samples / 2,712,053 functions):

| label | positive functions | positive samples | clusters | top-cluster share |
|---|---:|---:|---:|---:|
| `anti_debug` | 448 | 373 | 21 | 61.2 % |
| `keylogger` | 1,255 | 242 | 41 | 75.7 % |
| `injection` | 1,349 | 804 | 108 | 32.9 % |

The concentration is a property of the CAPA label, not of the model. It is
reported with every held-out result.

Function-scope matches are localised through CAPA's reported evidence
locations. CAPA reports the CAPA function address at the top of a match and the
matched feature locations (e.g. the `rdtsc` instructions) in the nested match
tree. The mapping attaches the label to the angr function(s) containing those
locations, not to every angr function that happens to share the CAPA function
start. Rules without evidence locations fall back to the CAPA function start.
This is why `anti_debug` is 448 rather than the 534 that a start-only mapping
produced.

## 7. Stage 2 labels

Stage 2 needs block-level targets. They are seeded from:

1. CAPA evidence locations for the same namespaces, including basic-block
   matches and the nested evidence of function-scope matches; and
2. blocks inside a positive function that call an API resolved from the PE
   import table.

These are weak block labels. They are suitable for localisation training but
not for claims of exact malicious-block ground truth. The manual Ghidra
spot-check is the validation gate; it is still open (40 functions selected,
0 verdicts recorded), so the current block metrics use the CAPA/API seeds only.

## 8. Splits

The training split is `data/versions/v2/splits/three_target.json` (protocol
`three-target-cluster-stratified-v3`). It is grouped by `cluster_key`, follows
70/15/15 sample counts, and places target positives as close to the same
proportions as the cluster groups allow. The frozen v2 `main.json` is retained
as history but is not used for Stage 1: it was created before keylogger was a
target and put 1,026 of 1,255 keylogger positives in test.

The three-target split holds 394/27/27 anti-debug, 950/152/153 keylogger, and
944/203/202 injection positives in train/validation/test. The test split is not
used for model selection.

## 9. Reproducibility

- Label generation: `src/label/parse_capa.py`, `src/label/mapping.py`,
  `src/label/build_labels.py`, `src/label/merge_labels.py`.
- Label contract constants: `src/label/contract.py`.
- Config: `configs/pilot_stage1.toml`.
- Raw CAPA JSON and the mapping JSONL are git-ignored because they derive from
  malware samples.
