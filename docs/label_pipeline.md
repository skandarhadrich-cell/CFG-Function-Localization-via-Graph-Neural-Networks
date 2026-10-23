# Label and training runbook — three targets

All commands run from the repository root with `./venv/bin/python`.

## 1. Inputs

| input | path |
|---|---|
| frozen manifest | `data/versions/v2/manifest.csv` |
| splits | `data/versions/v2/splits/three_target.json` |
| CAPA JSON | `data/labels/capa_raw/<sample_id>.json` |
| mapping JSONL | `results/full/mapping_three_target.jsonl` |
| CFG graphs | `data/graphs_v2/cfg/<sample_id>.npz` |

The v2 clean set has 2,733 samples and 303 clusters. 2,729 graphs exist; four
angr crashes are recorded in `results/full/cfg_summary.json` and are excluded.

## 2. Map CAPA labels onto the stored graphs

```bash
./venv/bin/python -m src.label.build_labels \
  --manifest data/versions/v2/manifest.csv \
  --capa-dir data/labels/capa_raw \
  --out results/full/mapping_three_target.jsonl \
  --summary results/full/mapping_three_target_summary.json \
  --cfg-dir data/graphs_v2/cfg \
  --workers 8
```

This reads the stored angr graphs, so it does not re-extract the corpus.
Function-scope matches use CAPA's nested evidence locations (`rdtsc`, API-call
instructions) to choose the angr functions; only rules without evidence fall
back to the CAPA function start.

## 3. Build the three-target label table

```bash
./venv/bin/python -m src.label.merge_labels \
  --mapping results/full/mapping_three_target.jsonl \
  --manifest data/versions/v2/manifest.csv \
  --splits data/versions/v2/splits/three_target.json \
  --out-prefix data/labels/stage1_full_three_targets \
  --format parquet
```

Outputs `stage1_full_three_targets.parquet` and `.meta.json`. The unit is
functions with a positive label. Expected counts: anti_debug 448, keylogger
1,255, injection 1,349.

## 4. Build the cluster-stratified split

```bash
./venv/bin/python -m src.data.build_three_target_splits
```

Outputs `data/versions/v2/splits/three_target.json` and
`results/full/three_target_split.md`. The frozen `main.json` is not used for
Stage 1; it predates keylogger and puts most keylogger positives in test.

The label contract is in `src/label/contract.py` and
`docs/labeling_contract.md`. Weak negatives are mapped functions with no target
match; unlabeled functions and zero-rule samples are excluded from the loss.

## 5. Build the block-feature corpus

```bash
./venv/bin/python -m src.features.block_features
```

Outputs to `results/corpus_v2_three_targets/`:

- `block_feats.npy` — float16, 187 features per block;
- `graph_meta.npz` — offsets, `y` (n_functions × 3), `eligible`, addresses;
- `feature_spec.json` — feature layout and label names;
- `build_report.json` — counts and API-resolution coverage.

The builder always advances graph offsets. A zero-rule sample is retained with
`eligible=0`; it is never dropped or treated as a negative.

## 6. Train Stage 1

```bash
./venv/bin/python -m src.train.stage1 \
  --corpus-dir results/corpus_v2_three_targets \
  --out-dir results/train/stage1 \
  --splits data/versions/v2/splits/three_target.json \
  --epochs 20 --patience 5 --batch-graphs 8 \
  --dropout 0.5 --weight-decay 0.005 \
  --edge-dropout 0.20 --feature-dropout 0.10 \
  --pos-weight-cap 300 --no-test
```

Model selection uses the validation split only. The test split is evaluated once
after the best epoch. Outputs `best.pt`, `metrics.json`, and `report.md`.

For a quick smoke run:

```bash
./venv/bin/python -m src.train.stage1 \
  --limit-train 20 --limit-val 10 --epochs 2 \
  --out-dir /tmp/opencode/stage1_smoke
```

## 7. Evaluation

Evaluate the held-out test once, using the thresholds stored in the checkpoint:

```bash
./venv/bin/python -m src.eval.stage1_test \
  --checkpoint results/train/stage1/best.pt \
  --corpus-dir results/corpus_v2_three_targets \
  --splits data/versions/v2/splits/three_target.json \
  --split test --out-dir results/train/stage1
```

The current held-out result is anti_debug F1 **0.6522** (AP 0.4836), keylogger
F1 **0.3376** (AP 0.2477), and injection F1 **0.4774** (AP 0.3327). Macro F1 is
**0.4890**; any-target F1 is **0.4948**; background F1 is **0.9976**.

Stage 1 report:

- per-target precision, recall, F1, average precision;
- any-target selection precision/recall/F1;
- background (not-selected) precision/recall/F1;
- eligible-function counts and support per target.

The headline is per-target F1 and the any-target F1. The background metric
measures how often the model leaves unrelated functions alone.

## 8. Stage 2

Block labels are built from CAPA evidence locations and import-resolved API-call
blocks inside positive functions. The Stage 2 trainer reuses the Stage 1 trunk
(frozen by default) and adds a per-block head. Metrics are block-level
precision, recall, F1, IoU, and average precision, plus a function hit rate.

```bash
./venv/bin/python -m src.data.build_block_labels \
  --labels data/labels/stage1_full_three_targets.parquet \
  --corpus-dir results/corpus_v2_three_targets

./venv/bin/python -m src.train.stage2 \
  --corpus-dir results/corpus_v2_three_targets \
  --stage1-checkpoint results/train/stage1/best.pt \
  --out-dir results/train/stage2 \
  --splits data/versions/v2/splits/three_target.json \
  --epochs 15 --patience 4 --batch-graphs 8 \
  --dropout 0.5 --lr 1e-3 --weight-decay 1e-4 \
  --edge-dropout 0.10 --feature-dropout 0.05 \
  --pos-weight-cap 50 --no-test
```

The block labels cover 120,319 blocks in 3,044 positive functions. Positive
block supports are anti_debug 1,432, keylogger 9,504, injection 15,263; API-call
seeds account for most keylogger/injection positives. The held-out test has
14,051 masked blocks (anti_debug 136, keylogger 1,344, injection 2,094).

Oracle-function test: macro block F1 **0.4586**, macro IoU **0.3373**. Per
target F1/IoU: anti_debug **0.1111/0.0588**, keylogger **0.4983/0.3318**,
injection **0.7663/0.6212**. The anti-debug threshold (0.94) is conservative
and yields low recall on 27 test functions; its block AP is 0.336.

End-to-end test (Stage 1 selected functions): macro block F1 **0.3723**, macro
IoU **0.2375**. Full tables are in `results/train/stage2/report.md`.

Evaluate test once with:

```bash
./venv/bin/python -m src.eval.stage2_test \
  --checkpoint results/train/stage2/best.pt \
  --split test --out-dir results/train/stage2
./venv/bin/python -m src.eval.stage2_end_to_end \
  --stage1-checkpoint results/train/stage1/best.pt \
  --stage2-checkpoint results/train/stage2/best.pt \
  --split test --out-dir results/train/stage2
```

## 9. Single-binary inference

The frozen checkpoints can be applied to one x86 PE with the same feature and
model code used above:

```bash
./venv/bin/python -m src.infer.run \
  --binary data/raw/antidebug/<sample_id>.exe
```

Outputs are written to `workspace/<sha256>/report.json` and
`workspace/<sha256>/report.pdf`; the PDF opens automatically. `--graph
<graph.npz>` skips angr for an already-extracted graph; `--no-stage2` returns
function scores only. Non-x86 inputs and extraction failures exit with code 2
instead of being mapped to a negative. The JSON schema and failure modes are
documented in [`docs/inference.md`](inference.md).

## 10. Reproducibility rules

- Never reuse the test split for early stopping or hyper-parameter selection.
- Never move a sample across splits.
- Report per-cluster support for every target; keylogger and anti-debug are
  concentrated.
- Keep raw samples, CAPA JSON, graphs, and checkpoints out of git.
