# Dataset versions

- `v1/` — frozen Phase 0 release used for the original pilot. Never modified.
- `v2/` — Phase 0 revision with the documented PE-based packed filter
  (`text_entropy >= 7.8 and num_imports <= 20`), generated for Stage 1.

Both versions keep the full 4,474-row manifest (excluded rows are flagged, not
dropped). Splits are versioned separately under each version's `splits/`
directory and bind to their manifest SHA-256.

Change record: `results/phase0_v2/change_report.{json,md}`.
Filter audit: `results/phase0_v2/threshold_audit.{json,md}`.
