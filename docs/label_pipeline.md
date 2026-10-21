# Pilot Label Pipeline Runbook

This is the operational sequence for the frozen v1 label contract. All commands
run from the repository root with the pinned virtual environment.

**Historical v1 pilot result (2026-10-20):** the three-label gate failed on
`keylogger` (projected ~242 vs the ~300 threshold). The keylogger pilot bucket
was dominated by packed samples that Phase 0 missed: 26 of 32 had
`is_packed=0` but CAPA flags a packer, and those 26 contributed no labels. That
finding produced the v2 packed filter and the two-label Stage 1 contract.

**Current status:** the Stage 1 revision is complete — Phase 0 v2 frozen
(2,733 clean samples / 303 clusters, two-label contract, pilot gate PASS). The
full-set Stage 1 run **is authorized**; sections 8–13 below are the current
path. Sections 1–7 remain the v1 pilot record and describe the retired
three-label table. The full-set run must not start model training until the
Ghidra audit and full-set diversity review are complete.

## 1. CAPA census

```bash
./venv/bin/python -m src.label.run_capa --workers 4
```

- Selects 200 clean main-train/val samples: all 32 keylogger train/val, then
  84 injection and 84 antidebug.
- Repairs each PE into a temporary copy; `data/raw/` is never modified.
- Writes raw JSON to `data/labels/capa_raw/` (git-ignored) and resumes by
  `sample_id`.
- Writes `results/pilot/samples.json` and `results/pilot/capa_summary.json`.
- CAPA executable, version, rules commit/dirty state, and argv are recorded.

## 2. Label contract parse

```bash
./venv/bin/python -m src.label.parse_capa \
  data/labels/capa_raw \
  --out data/labels/capa_parsed.jsonl \
  --summary-out results/pilot/label_census.json
```

The parser uses `meta.analysis.feature_counts.functions` as the observed
inventory and rule scopes from `meta.scopes.static`. `layout.functions` is only
used to map target basic blocks to parent functions. CAPA addresses are
normalized to RVAs.

## 3. CAPA-to-angr mapping

```bash
./venv/bin/python -m src.label.build_labels \
  --samples-file results/pilot/samples.json \
  --workers 4 \
  --sample-timeout 900 \
  --resume
```

`build_labels` recovers angr function/block ranges with `CFGFast`, maps CAPA
RVAs to the angr mapped base, and logs exact/containment mappings, collisions,
unmapped CAPA functions, and unresolved target matches. Each sample runs in an
isolated subprocess with a hard timeout, so one pathological CFG cannot stall
the batch. The output is `results/pilot/mapping.jsonl` (git-ignored).

Samples that time out or fail are listed in `mapping_summary.json`; re-running
with `--resume` retries them because only successful samples are appended.
The pilot's pathological bladabindi sample took 597 s and about 930 MB; a
300 s cap would reject it. Keep the timeout configurable and retry timeouts
rather than silently dropping samples.

## 4. Function label table

```bash
./venv/bin/python -m src.label.merge_labels \
  --mapping results/pilot/mapping.jsonl \
  --out-prefix data/labels/function_labels \
  --format both
```

Writes `function_labels.csv`, `function_labels.parquet`, and
`function_labels.meta.json`. In the retired v1 pilot the table had three
independent binary labels. The **Stage 1** table (section 10) has exactly two
active labels, `label_status` (`positive`, `weak_negative`, `unlabeled`),
`label_mask`, mapping method, and collision flag.

## 5. Gate report

```bash
./venv/bin/python -m src.label.pilot_report \
  --mapping results/pilot/mapping_subset_summary.json
```

Evaluates:

- CAPA-observed function mapping coverage;
- target-match mapping coverage and unresolved rate;
- projected full-set positive functions per label;
- missing CAPA JSON.

The report is `results/pilot/label_contract_report.md` and
`results/pilot/label_census.json`. The current pilot used a five-sample mapping
subset, so the report labels the scope as `subset`; it does not treat a subset
as proof that all 200 samples map.

## 6. Data-quality checks

```bash
./venv/bin/python -m src.data.known_bad
./venv/bin/python -m src.data.packing_audit
```

`known_bad.json` selects 10 .NET and 10 packed rows that the Phase 0 filters
reject. `packing_audit.json` flags pilot rows with high entropy and low import
counts, or with a CAPA packer rule, because the Phase 0 packed filter only
flags high entropy when there are zero imports.

## 7. Tests

```bash
./venv/bin/python -m unittest discover -s tests -v
./venv/bin/python -m compileall -q src tests
```

## 8. Phase 0 v2 packed-filter audit (do this first)

```bash
# 7.8 vs 7.9 audit on the v1 clean set + the 27 pilot packer suspects.
./venv/bin/python -m src.data.phase0_v2_audit

# Build v2 manifest/splits into data/versions/v2/ (v1 untouched).
./venv/bin/python -m src.data.build_manifest --config configs/phase0_v2.toml

# Record removed IDs, cluster changes, and split-membership changes.
./venv/bin/python -m src.data.compare_phase0_versions
```

- v1 stays at `data/manifest.csv` + `data/splits/` (mirrored, checksummed, under
  `data/versions/v1/`). v2 is written only to `data/versions/v2/`.
- Chosen rule: `text_entropy >= 7.8 and num_imports <= 20` (PE features only).
  CAPA packer detections are audit evidence, never an exclusion criterion.
- Audit: `results/phase0_v2/threshold_audit.{json,md}`.
- Change record: `results/phase0_v2/change_report.{json,md}`.

## 9. Stage 1 pilot selection (v2 train/val only)

```bash
./venv/bin/python -m src.label.run_capa \
  --config configs/pilot_stage1.toml \
  --selection stage1 --target 200
```

- Selects 200 samples from v2 main train/val with a hard per-cluster cap
  (`max_per_cluster = 4`) and family-balanced fill. Test is never eligible;
  `--sample-id` in Stage 1 mode rejects test IDs.
- Writes `results/stage1/samples.json` and `results/stage1/capa_summary.json`.
- Re-run is safe: existing valid JSON is skipped. Temporary CAPA outputs use
  unique per-process names, so concurrent runs on the same `sample_id` no
  longer collide (`FileNotFoundError: ...json.tmp` is fixed).

## 10. Stage 1 mapping and label table

```bash
./venv/bin/python -m src.label.build_labels \
  --samples-file results/stage1/samples.json \
  --workers 4 --sample-timeout 1800 --resume \
  --out results/stage1/mapping.jsonl \
  --summary results/stage1/mapping_summary.json

./venv/bin/python -m src.label.merge_labels \
  --mapping results/stage1/mapping.jsonl \
  --manifest data/versions/v2/manifest.csv \
  --splits data/versions/v2/splits/main.json \
  --out-prefix data/labels/stage1_function_labels \
  --format both
```

- Run mapping on the **full** pilot (not a subset) before the gate report.
- The Stage 1 label table has exactly two label columns (`anti_debug`,
  `injection`); `keylogger` evidence stays in raw CAPA JSON only.
- Recompute `label_status`/`label_mask` from the active labels: a
  keylogger-only function is a Stage 1 weak negative, never a positive.

## 11. Stage 1 gate report

```bash
./venv/bin/python -m src.label.pilot_report \
  --samples results/stage1/samples.json \
  --manifest data/versions/v2/manifest.csv \
  --mapping results/stage1/mapping_summary.json \
  --capa-dir data/labels/capa_raw \
  --json-out results/stage1/stage1_label_census.json \
  --md-out results/stage1/stage1_label_contract_report.md
```

Evaluates active labels only, plus the pre-registered diversity diagnostics
(positive binaries/clusters/families, top binary/cluster share). A label that
fails diversity may be trained but its claims stay exploratory. Then run the
30–50-function Ghidra spot check and inspect representative many-to-one
collisions before full-set labeling.

## 12. Full-set Stage 1 run (v2, authorized)

Run only after section 8–11 gates pass. Freeze the inputs first:

```bash
./venv/bin/python -m src.data.freeze_run
# later, to detect drift before any downstream stage:
./venv/bin/python -m src.data.freeze_run --check results/full/frozen_run.json
```

Full-set CAPA processes **clean v2 rows only** (2,733), never the 4,474-row
manifest. The selection is `--selection full`; it writes `results/full/`.

```bash
./venv/bin/python -m src.label.run_capa \
  --config configs/pilot_stage1.toml \
  --selection full --workers 4
```

- Reuses existing valid CAPA JSON only when its recorded `sample_sha256`
  matches the manifest `content_sha256`; stale JSON is regenerated.
- Resumable by `sample_id`; failures and timeouts are recorded in
  `results/full/capa_summary.json`, never silently dropped.

Full-set CFG extraction (Phase 2):

```bash
./venv/bin/python -m src.extract.batch_extract \
  --workers 2 --timeout 1800 --rss-limit-gb 3
```

- One packed `.npz` per sample under `data/graphs_v2/cfg/`, resumable and atomic.
- Each sample runs in an isolated process; timeouts and RSS overruns are recorded
  by category in `results/full/cfg_summary.json`, never silently dropped.
- Nodes come from angr's per-function graph; **edges are strictly
  intraprocedural**. Call targets are node features, not edges. The extractor
  refuses to emit a graph that is missing intraprocedural control flow, and it
  logs dropped interprocedural (call/tail/hook/return) edges.

Label mapping (Phase 3) then reuses stored CFG block ranges instead of running
angr a second time.

**Stop condition:** full-set labels are generated for review, but **model
training does not start** until the Ghidra audit (section 11) and the full-set
diversity review (section 13) are signed off.

## 13. Full-set diversity review

Recompute actual (not projected) per-label counts from the full label table:
positive functions, distinct binaries, imphash clusters, families, top
binary/cluster/family shares, train/val/test coverage, held-out positive
binaries/clusters, and LOFO coverage. Apply the pre-registered criteria in
`configs/pilot_stage1.toml`:

- `injection` is the primary candidate if it passes the diversity checks.
- `anti_debug` stays exploratory while its cluster concentration is high.
- Three represented families do not establish unseen-family generalization.

## 14. External collection (anti_debug coverage expansion)

Purpose: the full-set `anti_debug` census passes every frozen criterion except
`MAX_SINGLE_CLUSTER_SHARE`. One cluster (`imphash:b2c87e30ac`, 274 zbot
binaries) holds 51.3% of positives. The fix is *more positives from new
imphash clusters*, not removing the dominant cluster.

The collection frame is pre-registered in `configs/collect_antidebug.toml`:
targeted anti-debug-prone families, a control slice from families with no
published anti-debug behaviour, and per-family quotas. The frame is a
stratified sampling decision made before any label was observed.

```bash
# 1. collect candidates (resumable, hash-verified, never executes anything)
./venv/bin/python -m src.collect.mb_pull  --probe
./venv/bin/python -m src.collect.zoo_pull

# 2. apply the *unchanged* v2 quality gate
./venv/bin/python -m src.collect.probe_gate

# 3. CAPA the survivors and measure anti_debug yield
./venv/bin/python -m src.collect.probe_capa --source malwarebazaar --workers 3
```

- Every collected file is named after its own SHA-256; a mismatch is a fatal
  integrity error (`tests/test_collect.py`).
- Resume is status-aware: only successful attempts block a retry.
- Cross-source duplicates are rejected via `data/external_meta/content_index.json`
  (external corpus only; BODMAS hashes are never absorbed into it).
- Provenance for every candidate is appended to
  `data/external_meta/<source>.jsonl`.
- Go/no-go bar is pre-registered in `src/collect/probe_gate.py`: **>= 75 new
  positive functions across >= 5 unseen clusters**. If missed, widen the family
  frame — never loosen the quality filter.

Probe findings (2026-10-21) are recorded in `results/collect/PROBE_FINDINGS.md`.
`theZoo` was rejected: 29 distinct binaries, 0 passing the gate.
