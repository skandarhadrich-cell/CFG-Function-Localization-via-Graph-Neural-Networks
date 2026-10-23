# CFG-GNN: hierarchical malware function and block localisation

Function-level and basic-block-level localisation of malicious behaviour in x86
PE binaries, using control-flow graphs (CFGs) and graph neural networks.

```text
PE binary
   │
   ▼
angr CFG recovery
   │
   ▼
Stage 1 — GCN over each function's CFG
   │        anti_debug / keylogger / injection / not selected
   ▼
flagged functions only
   │
   ▼
Stage 2 — block head over the same CFG trunk
   │        which basic blocks carry the behaviour
   ▼
function ranking + block localisation report
```

**Status (2026-10-22):** the project has been reset to the original three-target
plan. The previous XOR/7-rule methodology detour and its checkpoints, evaluation
code, and reports were removed. The three-target label table, the 187-dimensional
block-feature corpus, the cluster-stratified split, and the Stage 1 trainer have
been rebuilt. Function-scope CAPA matches are localised through CAPA's reported
evidence locations, so an anti-debug rule is attached to the angr function that
contains the ``rdtsc``/``icebp`` instructions rather than to every function that
happens to share the CAPA function start. Stage 1 and the Stage 2 block
localiser have been trained and their held-out tests evaluated once. A
single-binary inference CLI now runs the frozen Stage 1 and Stage 2 models on
one x86 PE and writes function scores plus block addresses as JSON. The next
modelling step remains the GAT comparison, not a new label contract.

Final report (PDF): [`results/final_report.pdf`](results/final_report.pdf).
The reproducible source is `scripts/make_final_report.py` and the HTML
intermediate is `results/final_report.html`.

---

## 1. Task

**Stage 1 — function classification.** For every recovered function in a
malware sample, predict the three target behaviours:

| class | CAPA namespace | meaning |
|---|---|---|
| `anti_debug` | `anti-analysis/anti-debugging` | anti-debugging / anti-analysis rules |
| `keylogger` | `collection/keylog` | keystroke-collection rules |
| `injection` | `host-interaction/process/inject`, `load-code/pe/inject-` | process/PE injection rules |
| *(background)* | none of the above | not selected; **not** a benign sample |

The three targets are independent sigmoids: a function may match more than one.
A function with no target match is the background class. It is a **weak
negative**, not a benign function — the corpus is malware-only and there is no
benign control corpus.

**Stage 2 — block localisation.** For functions flagged by Stage 1, classify each
basic block as carrying the target behaviour or not, then map scores back to
virtual addresses. Evaluate with block-level precision, recall, F1, and IoU.

## 2. Data

| item | value |
|---|---|
| corpus | BODMAS v2 clean set, x86 PE |
| clean samples | 2,733 |
| graphs extracted | 2,729 (4 angr failures) |
| function labels | 2,712,053 mapped rows |
| target positives | anti_debug 448 · keylogger 1,255 · injection 1,349 |
| splits | `three_target.json`: 70/15/15 cluster-stratified |
| excluded | 855 x64 samples (all packed), see `docs/data/x64_scope.md` |

Labels are CAPA 9.1.0 namespace matches on static function and basic-block
scopes. The full contract is in [`docs/labeling_contract.md`](docs/labeling_contract.md).

**Label caveat.** The labels are observational, not ground truth. The audit in
[`results/audit/`](results/audit/) records the concentration: the keylogger label
is 75.7 % one cluster and is largely keyboard-state API presence; anti-debug is
61.2 % one cluster; injection is 32.9 %. Those figures are reported with every
result. They do not change the targets, but they limit what a held-out score can
mean. Function-scope evidence localisation keeps the anti-debug label at 448
functions (down from 534 when the whole CAPA function was inherited by every
contained angr function).

## 3. Features

Each basic block is a 187-dimensional vector:

| dims | feature |
|---|---|
| 0–114 | 114 opcode frequencies + `other` |
| 115–119 | log block size, log instructions, log in-degree, log out-degree, is-entry |
| 120–183 | 64 hashed API-reference buckets |
| 184–186 | log resolved API calls, log distinct buckets, has API call |

The opcode vocabulary includes anti-debug/system instructions (`rdtsc`, `icebp`,
`int1`, `cpuid`, `pushfd`/`popfd`, `in`/`out`, `sysenter`/`syscall`, ...), not
just general integer operations.

API references are resolved from the PE import table through import thunks and
through the import-reference instruction itself (`call/jmp dword ptr [IAT]`),
which covers calls that angr does not resolve to a call target. No CAPA rule
name or label value enters the model input. The layout is written to `results/corpus_v2_three_targets/feature_spec.json`.

## 4. Model

- GCN: two message-passing layers, residual skip, mean+max function pooling,
  small MLP head. Edges are intraprocedural only.
- Stage 1 head: three logits (multi-label BCE).
- Stage 2 head: per-block logits on the shared trunk.
- GAT: planned as the second encoder; it is not implemented yet.

The model is implemented directly in PyTorch. PyTorch Geometric is not a
dependency at this stage.

## 5. Repository layout

```text
configs/pilot_stage1.toml      three-target configuration
data/versions/v2/              frozen manifest + main/LOFO splits
data/graphs_v2/cfg/            one .npz CFG per sample (git-ignored)
data/labels/                   CAPA JSON, mapping, three-target parquet (git-ignored)
docs/                          contract, data scope, pipeline runbook
results/audit/                 label composition and concentration
results/corpus_v2_three_targets/  block features + labels (git-ignored)
results/train/stage1/          Stage 1 metrics/report (+ checkpoint, git-ignored)
results/train/stage2/          Stage 2 metrics/report (+ checkpoint, git-ignored)
src/collect/                   MalwareBazaar / theZoo collectors
src/data/                      manifest, repair, versioning
src/extract/                   angr CFG recovery and .npz store
src/features/block_features.py block features + corpus builder
src/label/                     CAPA parsing, mapping, merge, contract
src/models/gcn.py              GCN, node head, batching, standardizer
src/train/stage1.py            three-target function trainer
src/train/stage2.py            frozen-trunk block localiser
src/data/build_block_labels.py block labels from CAPA evidence + API seeds
src/eval/stage1_test.py        once-only Stage 1 test evaluation
src/eval/stage2_test.py        once-only Stage 2 test evaluation
src/eval/stage2_end_to_end.py  Stage 1 selected functions -> block metrics
src/eval/folds.py              cluster fold assignment
src/infer/                     one-binary CLI, feature/model path, JSON report
docs/inference.md              CLI usage, output schema, inference caveats
tests/                         unit and corpus invariants
```

## 6. Running

All commands use the pinned environment:

```bash
./venv/bin/python -m pytest tests/ -q

# 1. Map CAPA labels onto the stored angr graphs (no re-extraction).
./venv/bin/python -m src.label.build_labels \
  --manifest data/versions/v2/manifest.csv \
  --capa-dir data/labels/capa_raw \
  --out results/full/mapping_three_target.jsonl \
  --summary results/full/mapping_three_target_summary.json \
  --cfg-dir data/graphs_v2/cfg --workers 8

# 2. Flatten the mapping into the three-target label table.
./venv/bin/python -m src.label.merge_labels \
  --mapping results/full/mapping_three_target.jsonl \
  --manifest data/versions/v2/manifest.csv \
  --splits data/versions/v2/splits/three_target.json \
  --out-prefix data/labels/stage1_full_three_targets \
  --format parquet

# 3. Rebuild the cluster-stratified three-target split.
./venv/bin/python -m src.data.build_three_target_splits

# 4. Rebuild the block-feature corpus (API features included).
./venv/bin/python -m src.features.block_features

# 5. Train Stage 1 on the three-target split (no test during selection).
./venv/bin/python -m src.train.stage1 \
  --corpus-dir results/corpus_v2_three_targets \
  --out-dir results/train/stage1 \
  --splits data/versions/v2/splits/three_target.json \
  --epochs 20 --patience 5 --batch-graphs 8 \
  --dropout 0.5 --weight-decay 0.005 \
  --edge-dropout 0.20 --feature-dropout 0.10 \
  --pos-weight-cap 300 --no-test

# 6. Evaluate the held-out test once with the validation-selected model.
./venv/bin/python -m src.eval.stage1_test \
  --checkpoint results/train/stage1/best.pt \
  --corpus-dir results/corpus_v2_three_targets \
  --splits data/versions/v2/splits/three_target.json \
  --split test --out-dir results/train/stage1

# 7. Build block labels aligned to the flattened block order.
./venv/bin/python -m src.data.build_block_labels \
  --labels data/labels/stage1_full_three_targets.parquet \
  --corpus-dir results/corpus_v2_three_targets

# 8. Train Stage 2 with the Stage 1 trunk frozen.
./venv/bin/python -m src.train.stage2 \
  --corpus-dir results/corpus_v2_three_targets \
  --stage1-checkpoint results/train/stage1/best.pt \
  --out-dir results/train/stage2 \
  --splits data/versions/v2/splits/three_target.json \
  --epochs 15 --patience 4 --batch-graphs 8 \
  --dropout 0.5 --lr 1e-3 --weight-decay 1e-4 \
  --edge-dropout 0.10 --feature-dropout 0.05 \
  --pos-weight-cap 50 --no-test

# 9. Evaluate the held-out test once: oracle functions and end-to-end.
./venv/bin/python -m src.eval.stage2_test \
  --checkpoint results/train/stage2/best.pt \
  --split test --out-dir results/train/stage2
./venv/bin/python -m src.eval.stage2_end_to_end \
  --stage1-checkpoint results/train/stage1/best.pt \
  --stage2-checkpoint results/train/stage2/best.pt \
  --split test --out-dir results/train/stage2
```

Stage 1 writes `best.pt`, `metrics.json`, and `report.md`. Model selection uses
the validation split only; the test split is evaluated once after training. The
three-target split holds 394/27/27 anti-debug, 950/152/153 keylogger, and
944/203/202 injection positives in train/val/test; the low anti-debug support is
a property of the label's cluster concentration and is reported with every
result.

### Stage 1 result

The first held-out test (evaluated once, thresholds selected on validation):

| target | test support | precision | recall | F1 | AP |
|---|---:|---:|---:|---:|---:|
| `anti_debug` | 27 | 0.7895 | 0.5556 | **0.6522** | 0.4836 |
| `keylogger` | 153 | 0.3292 | 0.3464 | **0.3376** | 0.2477 |
| `injection` | 202 | 0.3761 | 0.6535 | **0.4774** | 0.3327 |

Macro F1 is **0.4890**; any-target selection F1 is **0.4948**; background
(not-selected) F1 is **0.9976**. The full table and caveats are in
`results/train/stage1/report.md`. The test supports are small because the labels
are clustered; do not read the macro F1 as a family-wide generalisation claim.

### Stage 2 result

The Stage 2 trunk is the frozen Stage 1 GCN; only the per-block head is
trained. The oracle-function test (all true positive functions) and the
end-to-end test (only Stage 1 selected functions) were evaluated once:

| target | block support | oracle P | oracle R | oracle F1 | oracle IoU | end-to-end P | end-to-end R | end-to-end F1 | end-to-end IoU |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `anti_debug` | 136 | 1.0000 | 0.0588 | **0.1111** | 0.0588 | 0.6667 | 0.1081 | **0.1860** | 0.1026 |
| `keylogger` | 1,344 | 0.4312 | 0.5900 | **0.4983** | 0.3318 | 0.2980 | 0.6598 | **0.4106** | 0.2583 |
| `injection` | 2,094 | 0.6462 | 0.9413 | **0.7663** | 0.6212 | 0.3585 | 0.9470 | **0.5202** | 0.3515 |

Macro oracle block F1 is **0.4586** (IoU **0.3373**); macro end-to-end block
F1 is **0.3723** (IoU **0.2375**). The anti-debug block threshold (0.94) was
selected on 27 validation functions and is very conservative; its test AP is
0.336, so the ranking is better than the thresholded recall suggests. Full
tables and caveats are in `results/train/stage2/report.md`.

### Single-binary inference

The frozen checkpoints can score one x86 PE and localise blocks inside the
functions selected by Stage 1:

```bash
./venv/bin/python -m src.infer.run \
  --binary data/raw/antidebug/<sample_id>.exe
```

The CLI extracts the CFG with the same timeout/RSS-protected angr worker used
by the corpus builder, rebuilds the exact 187 block features, loads
`results/train/stage1/best.pt` and `results/train/stage2/best.pt`, and writes
both outputs into `workspace/<sha256>/`:

- `report.json` — machine-readable function/block results;
- `report.pdf` — per-sample report, opened automatically.

The PDF is always generated; there is no JSON-only mode. `--graph <file.npz>`
skips extraction for a graph that already exists. `--no-stage2` produces
function scores only. `--workspace PATH` changes the workspace root. A non-x86
input or a failed extraction exits with code 2 and an explicit error; it is
never treated as a negative. The output contract is documented in
[`docs/inference.md`](docs/inference.md).

## 7. Evaluation

**Stage 1:** per-class precision, recall, F1, and average precision; any-target
selection precision/recall/F1; background (not-selected) precision/recall/F1.
Metrics are computed only on eligible functions — mapped functions in samples
with at least one CAPA rule. Unmapped functions and zero-rule samples are
excluded, not treated as negatives.

**Stage 2:** block-level precision, recall, F1, and IoU. The oracle-function
number uses all true positive functions; the end-to-end number uses only
functions selected by Stage 1, so Stage 1 false positives add block false
positives and missed functions add block false negatives. Addresses map back to
the extracted CFG.

The split is grouped by cluster, so near-duplicate samples do not cross
train/validation/test. The test split is frozen and is not used for model
selection. Family-held-out evaluation is reported separately when the held-out
family has enough positives.

## 8. Limitations

- **Weak labels.** CAPA rule matches are not ground-truth annotations. The
  three target names are shorthand for their namespaces, not proof of intent.
- **Malware only.** There is no benign corpus. Background means "no target rule
  matched", not "safe". A benign-vs-malicious claim is out of scope.
- **Keylogger and anti-debug concentration.** 75.7 % of keylogger positives and
  61.2 % of anti-debug positives come from one cluster each. Keylogger is largely
  keyboard-state API presence. Held-out scores for these two targets should be
  read per cluster, not as broad capability detection.
- **x86 PE only.** ELF, ARM, and x64 are not in this corpus. The 855 x64 BODMAS
  rows are packed and fail the v2 filter.
- **Static CFG recovery.** Packed binaries, indirect jumps, and missed code
  reduce recall. angr failures are recorded, not silently dropped.
- **Stage 2 labels** come from CAPA evidence and import-resolved API-call
  blocks. They are weaker than hand annotations; the metrics measure recovery
  of those seeds, not every malicious block. The anti-debug block threshold is
  unstable because validation has only 27 anti-debug functions. The Ghidra
  spot-check is still open (40 functions selected, 0 verdicts recorded).

## 9. Safety

The repository does not ship malware. Raw samples, per-sample CAPA JSON, and
serialized graphs are git-ignored. Do not commit samples, model checkpoints
derived from them, or reports that embed sample bytes. Analysis is static; no
sample is executed.

## 10. References

- BODMAS: Blue Hexagon / Whyisyoung, 2019.
- CAPA: Mandiant, 2020–.
- angr: Shoshitaishvili et al., S&P 2016.
- GCN: Kipf & Welling, ICLR 2017.
- GAT: Veličković et al., ICLR 2018.
