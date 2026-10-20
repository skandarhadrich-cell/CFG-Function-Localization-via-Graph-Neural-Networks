# Phase 0 v1 (frozen)

This directory is a byte-for-byte copy of the original Phase 0 release:

- `manifest.csv` — 4,474 rows, 2,814 clean samples, 310 clean imphash clusters.
- `splits/main.json` — 1,969 train / 423 val / 422 test.
- `splits/lofo.json` — 2,302 train / 405 val / 107 test.
- `phase0.toml` — configuration used to build it.
- `SHA256SUMS` — integrity checksums.

The canonical working copy (`data/manifest.csv`, `data/splits/`) also matches
these files. v1 must not be regenerated or edited; all revisions go to v2.
