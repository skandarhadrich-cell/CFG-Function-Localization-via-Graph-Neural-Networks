# Phase 0 v2 (packed-filter revision)

Built from `configs/phase0_v2.toml`. Changes versus v1:

- Packed-sample rule now includes `text_entropy >= 7.8 and num_imports <= 20`
  (PE features only). CAPA packer detections remain an audit signal only.
- 81 clean v1 samples are excluded → 2,733 clean samples, 303 clean clusters.
- Splits regenerated with the same seed/ratios: main 1,913 train / 410 val /
  410 test; LOFO 2,247 train / 396 val / 90 test.

Files:

- `manifest.csv` — 4,474 rows with `is_clean` recomputed under the v2 filter.
- `splits/main.json`, `splits/lofo.json` — bound to this manifest SHA-256.
- `SHA256SUMS` — integrity checksums.

Audit and change record:

- `results/phase0_v2/threshold_audit.md` — 7.8 vs 7.9 decision evidence.
- `results/phase0_v2/change_report.md` — removed IDs, cluster/split changes.
