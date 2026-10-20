# CAPA Labeling Contract

**Status:** frozen for the pilot. Version 1.
**Tool identity:** CAPA **9.1.0**; rules commit
`805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5` (clean working tree at the time of
pinning). The pilot must record the actual executable version, rules commit,
argv, and sample hashes in its label metadata.

This document defines what a positive, a weak negative, and an unlabeled
function mean. It exists because CAPA's JSON is match-oriented, not an
exhaustive function inventory.

## 1. Why `layout.functions` is not an inventory

CAPA's `compute_layout()` only emits functions containing at least one matched
basic block. It deliberately avoids writing unreferenced functions. In a clean
`gandcrab` sample inspected during Phase 0:

- `meta.analysis.layout.functions`: **69** functions
- `meta.analysis.feature_counts.functions`: **77** functions
- **8** analyzed functions were absent from `layout.functions`

There is a second trap: `layout.functions` is populated from basic-block-scope
matches. A function-scope-only match does not necessarily create a layout entry.
The label parser must therefore use:

- `meta.analysis.feature_counts.functions` for the analyzed-function inventory;
- `meta.analysis.layout.functions[].matched_basic_blocks` only to map matched
  blocks back to their parent functions;
- the rule scopes directly for function-scope matches.

Do not infer "CAPA parsed this function and found nothing" from absence in
`layout.functions`.

## 2. Target rules

A rule is in scope when its `meta.namespace` starts with one of:

| Label | Namespace prefix |
|---|---|
| `anti_debug` | `anti-analysis/anti-debugging` |
| `keylogger` | `collection/keylog` |
| `injection` | `host-interaction/process/inject` or `load-code/pe/inject-*` |

Use `meta.scopes.static`, not `meta.scope`. In real CAPA 9.1 JSON, `meta.scope`
is often `null`, while `meta.scopes` looks like:

```json
{"static": "basic block", "dynamic": "call"}
```

Only static `function` and static `basic block` scopes produce function labels.
File/process/call-scope matches are ignored for Stage 1.

## 3. Address normalization

CAPA and angr may load the image at different base addresses. Before matching:

1. Read `meta.analysis.base_address`.
2. Normalize CAPA addresses to RVAs, or rebase them to angr's
   `project.loader.main_object.mapped_base`.
3. Record the normalization used in every label row or label-file metadata.

Never compare raw CAPA VAs with angr VAs without checking the base.

## 4. Mapping procedure

For each successfully analyzed sample:

### CAPA-side sets

- `observed`: addresses in `meta.analysis.feature_counts.functions`, plus any
  address in `layout.functions` (defensive; layout should be a subset), plus any
  function-scope target match address (matched functions are observed by
  definition).
- `function_matches`: target rule matches whose `meta.scopes.static` is
  `function`. The match address is the function address.
- `block_matches`: target rule matches whose `meta.scopes.static` is
  `basic block`. Map each block address to its parent function using
  `layout.functions[].matched_basic_blocks`. If the block is not in the layout,
  record a mapping failure; do not drop it silently.
- `matched`: `function_matches ∪ parent(block_matches)`.
- `weak_negatives`: `observed − matched`.

### angr-side mapping

- Exact function-start match first.
- Otherwise, map a CAPA function address to the angr function whose address
  range contains it.
- Map CAPA block addresses to exact angr block starts first, then to the angr
  block whose range contains the address.
- If multiple CAPA functions map to one angr function, union their labels and
  record a many-to-one collision.
- If a CAPA target match cannot be mapped to an angr function, record it as an
  unresolved target match. It is not silently converted to a negative.

### Three output states

| State | Definition | `label_mask` | Label vector |
|---|---|---:|---|
| `positive` | Mapped angr function has at least one target match | 1 | one or more 1s |
| `weak_negative` | Mapped CAPA-observed function has no target match | 1 | `[0,0,0]` |
| `unlabeled` | Angr function has no successful CAPA inventory mapping | 0 | excluded |

The weak-negative meaning is exactly:

> **No selected CAPA rule matched inside a function CAPA analyzed.**

It does **not** mean benign, safe, or "the capability is absent."

## 5. Required label-table fields

`data/labels/function_labels.parquet` should contain at least:

- `sample_id`
- `func_va`
- `capa_func_va` (or blank for unmapped)
- `label_anti_debug`, `label_keylogger`, `label_injection`
- `label_status` (`positive`, `weak_negative`, `unlabeled`)
- `label_mask`
- `matched_rules` (list of rule names)
- `matched_block_vas` (list)
- `mapping_method` (`exact`, `containment`, `unmapped`)
- `mapping_collision` (boolean)

The contract is frozen for the pilot. If mapping logic changes, bump the label
contract version and regenerate labels rather than mixing versions.

## 6. Coverage and audit

For each sample, report:

- `capa_observed` and `capa_matched` counts;
- `angr_functions` and `mapped_angr_functions` counts;
- exact vs containment mappings;
- unresolved target matches;
- many-to-one collisions;
- label counts by status.

Pilot gate (provisional until measured):

- **≥95%** of CAPA-observed functions map to angr by exact match or containment;
- **≥95%** of target rule matches map to an angr function/block;
- unresolved target matches are **<2%** and individually logged;
- label census projects **≥300 positive functions** per label on the full clean
  set;
- 30–50 functions are manually audited in Ghidra, stratified by label, bucket,
  and status. Record disagreements; this is an audit, not ground truth.

If the keylogger projection falls below ~300 positive functions, stop and
revise the label set rather than forcing a three-label result.

## 7. Evaluation consequences

Training may use weak negatives with a masked BCE loss, but evaluation must not
pretend they are true negatives:

- Primary positive metrics: per-label precision, recall, F1, AUROC, and AP on
  positive-labeled functions.
- Secondary: ranking metrics where unlabeled functions are not counted as
  negatives.
- Report "agreement with CAPA weak negatives" separately. Do not call it
  specificity or true-negative rate.
- Calibration is reported with the caveat that weak negatives bias it.
- A positive-unlabeled sensitivity analysis is optional; it is not the primary
  pipeline for the first project.

## 8. Reproducibility metadata

Every CAPA run must record:

- CAPA executable version and path;
- rules repository commit and dirty status;
- complete argv;
- sample SHA-256;
- extractor name and base address;
- timestamp.

The rules revision is part of the experiment. Re-running with a different rules
commit is a new label version.
