# Pilot Label Pipeline Runbook

This is the operational sequence for the frozen v1 label contract. All commands
run from the repository root with the pinned virtual environment.

**Pilot result (2026-10-20):** the three-label gate fails on `keylogger`
(projected ~242 vs the ~300 threshold). The keylogger pilot bucket is dominated
by packed samples that Phase 0 missed: 26 of 32 have `is_packed=0` but CAPA
flags a packer, and those 26 contribute no labels. Do not start the full run
until the label contract and packed filter are revised. See
[`results/pilot/pilot_findings.md`](../results/pilot/pilot_findings.md).

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
`function_labels.meta.json`. The table has three independent binary labels,
`label_status` (`positive`, `weak_negative`, `unlabeled`), `label_mask`,
mapping method, and collision flag.

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
