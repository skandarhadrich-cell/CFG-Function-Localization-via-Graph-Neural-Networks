# Results index

This directory mixes frozen evidence, current reports, and historical pilot
outputs. The current three-target results are the files linked from the root
[README](../README.md).

## Current results

| Path | Purpose |
|---|---|
| [`audit/label_composition.md`](audit/label_composition.md) | What each CAPA-derived label measures, including cluster concentration |
| [`train/stage1/report.md`](train/stage1/report.md) | Stage 1 function-selection metrics and thresholds |
| [`train/stage2/report.md`](train/stage2/report.md) | Stage 2 oracle and end-to-end block metrics |
| [`infer/inference_validation.json`](infer/inference_validation.json) | Three-sample held-out inference parity check |
| [`infer/block_spotcheck.json`](infer/block_spotcheck.json) | Capstone decode sanity check (not manual validation) |
| [`final_report.pdf`](final_report.pdf) | Aggregate project report |
| [`final_report.html`](final_report.html) | HTML source for the aggregate report |
| [`corpus_v2_three_targets/feature_spec.json`](corpus_v2_three_targets/feature_spec.json) | Feature layout and label names |
| [`corpus_v2_three_targets/build_report.json`](corpus_v2_three_targets/build_report.json) | Corpus counts and API-resolution coverage |
| [`corpus_v2_three_targets/block_label_report.json`](corpus_v2_three_targets/block_label_report.json) | Block-label coverage and seed composition |
| [`full/mapping_summary.json`](full/mapping_summary.json) | Frozen CAPA-to-angr mapping coverage |
| [`full/three_target_split.md`](full/three_target_split.md) | Three-target split construction record |
| [`phase0_v2/threshold_audit.md`](phase0_v2/threshold_audit.md) | v2 packed-filter threshold audit |
| [`collect/PROBE_FINDINGS.md`](collect/PROBE_FINDINGS.md) | External collection probe; not used in the current training corpus |

## Historical pilot outputs

These are retained for provenance. They are **not** the current three-target
methodology and should not be used as the headline result.

| Path | Purpose |
|---|---|
| `pilot/` | Early label-contract pilot, packing audit, and CAPA retry logs |
| `stage1/` | Early two-label pilot, mapping inspection, and Ghidra audit sheet |
| `phase0_*.csv`, `phase0_*.json`, `phase0_report.md` | Original Phase 0 validation and CAPA smoke evidence |

The active contract and evaluation protocol are documented in
[`docs/labeling_contract.md`](../docs/labeling_contract.md) and the root README.
