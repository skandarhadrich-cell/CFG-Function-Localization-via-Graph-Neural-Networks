# CFG-GNN: Function-Level Malware Capability Classification

Weakly supervised classification of PE binaries at the **function level**, using control-flow graphs
(CFGs), basic-block features, and graph neural networks.

**Status:** Phase 0 complete. The manifest and frozen splits cover **2,814 clean samples**;
all 2,814 load in angr and a 12-sample stratified CAPA smoke test returns exit 0. There are no
CAPA labels, extracted graphs, or trained models in the repository yet. The next step is the
pilot, not the full run. The original four-class/two-stage HTML plan is archived at
[`docs/archive/legacy-two-stage-plan.html`](docs/archive/legacy-two-stage-plan.html) and is not
current.

---

## 1. Scope

**What this project does**

- Takes an x86/x64 PE binary, recovers per-function CFGs with angr, and labels functions with
  CAPA-derived capabilities.
- Trains a GNN to assign three independent probabilities per function: `anti_debug`,
  `keylogger`, `injection`.
- Tests whether graph structure and opcode statistics alone can recover those labels when the
  Windows API features are removed (`no-API` ablation).

**What this project does not claim**

- It is **not** a benign-vs-malicious detector. There is no benign corpus; unmatched functions are
  "no targeted CAPA rule matched", not "safe".
- It is **not** family attribution. Source folders and family names are stratification metadata,
  not targets.
- It is **not** block-level ground truth. Stage 2 (block localization) is an optional extension
  built on weak CAPA block addresses.

The labels are CAPA's output. The model is therefore evaluated as **weak supervision**: the
interesting question is whether CFG structure and opcodes carry signal beyond the API calls that
CAPA itself keys on.

---

## 2. Design decisions

The original 14-day, four-class, two-stage plan is superseded. The current design:

| Decision | Choice | Reason |
|---|---|---|
| Task order | Single-stage function classifier first | Stage 2 is meaningless if Stage 1 is weak |
| Label shape | 3 independent sigmoids (multi-label) | A function can match keylog + injection; no invented priority order |
| "Class 0" | Removed | Unmatched is a weak negative, not a benign class; unmapped is unlabeled |
| Label inventory | `feature_counts.functions` + rule scopes | `layout.functions` only contains matched blocks, not all analyzed functions |
| Source folders | `source_bucket`, used only for stratification | The family-to-class mapping was heuristic and is not ground truth |
| Supervision | CAPA 9.1 rule namespaces | Weak labels, documented as such |
| Evaluation | Positive-only + weak-negative agreement | Weak negatives are not true negatives |
| API features | Full vs no-API vs API-dropout | Directly tests "does the model just re-learn CAPA?" |
| Splits | imphash/family-grouped | Near-duplicates must never cross train/test |
| Generalization | Main split + repeated LOFO for eligible families | One held-out family is not enough evidence |
| Scale | Full clean corpus, no compute caps | Filter only for data quality |
| Compute | CPU-first, pilot before full run | angr/CAPA dominate; GPU only helps training |
| Schedule | Phases and gates, no fixed dates | Throughput is measured, not guessed |

---

## 3. Dataset

BODMAS "disarmed" PE corpus, stored under `data/raw/` (git-ignored).

| Source bucket | Files on disk | Clean after Phase 0 | Families (clean) | Dominant clean family |
|---|---:|---:|---:|---|
| `keylogger` | 537 | 38 | 5 | lokibot (23) |
| `injection` | 1,529 | 1,359 | 6 | ceeinject (1,127) |
| `antidebug` | 2,408 | 1,417 | 7 | gandcrab (937) |
| **Total** | **4,474** | **2,814** | **18** | — |

The 4,470 BODMAS path-list IDs are all present. The extra 4 `.exe` files are nested TheZoo
samples outside the path lists; they are marked `non_bodmas` and excluded. `carberp` has no clean
samples, so 18 families remain represented.

**Data quality filters (no compute caps)**

| Flag | Files | Notes |
|---|---:|---|
| `packed` | 1,398 | UPX section names/signature, known packer strings, or high-entropy text with no imports |
| `dotnet` | 265 | COM descriptor or `mscoree`/`mscorlib` import |
| `non_bodmas` | 4 | nested TheZoo extras |
| `no_imports` | 8 | informational; not used to exclude unless also packed/high-entropy |
| **Clean** | **2,814** | flags overlap, so the excluded total is 1,660 |

The earlier 502 packed estimate was based on `file(1)` output and undercounted samples whose UPX
section names remain but whose UPX signature was stripped. No unpacking is attempted. The clean
set is therefore smaller than the pre-Phase 0 estimate of 3,600–3,800.

**Header disarmament.** 4,470 of 4,474 files need repair (`machine = 0`, `subsystem = 0`); the
4 nested extras are already valid. angr fails with `ArchNotFound` and CAPA exits 21 until the
fields are repaired (0x14c for PE32, 0x8664 for PE32+; subsystem 3 when zero). Repair is
deterministic and done into an ephemeral per-job copy; `data/raw/` is never modified. Sixteen
`injector` samples use a compact DOS header with `e_lfanew = 0x10`; the parser accepts them.

**Hashing caveat.** Filenames are the BODMAS altered-sample IDs. Their content SHA-256 is
**different** from the filename. Join labels on `sample_id` (filename stem), and store
`content_sha256` separately in the manifest.

**Buckets are not labels.** The family→bucket mapping is heuristic. Phase 1 reports a
`source_bucket × CAPA-label` cross-tab so this assumption is visible instead of hidden.

---

## 4. Labels

CAPA is the weak supervisor, not ground truth. The full operational contract is in
[`docs/labeling_contract.md`](docs/labeling_contract.md). The key point, verified against CAPA
9.1.0 and real JSON, is that **`meta.analysis.layout.functions` is not an exhaustive function
inventory**: it only contains functions with at least one matched basic block. In one clean
`gandcrab` sample, `feature_counts.functions` had 77 functions while `layout.functions` had 69.

CAPA 9.1 JSON is parsed as follows:

- `rules[rule].matches` is a **list** of `[address, match]` pairs, not a dict keyed by address.
- `meta.analysis.feature_counts.functions` is the analyzed-function inventory.
- `meta.analysis.layout.functions[].matched_basic_blocks` is used only to map matched blocks back
  to their parent functions.
- There is no `meta.function` on matches. Use `meta.scopes.static` (`function` or
  `basic block`), not `meta.scope` (often `null`).
- Function-scope target matches label the function address directly. Basic-block-scope target
  matches label the parent function. File/process/call-scope matches are ignored.
- Normalize CAPA and angr addresses using `meta.analysis.base_address` before matching.

| Label | CAPA namespace prefix | Examples |
|---|---|---|
| `anti_debug` | `anti-analysis/anti-debugging` | debugger detection, timing checks |
| `keylogger` | `collection/keylog` | keystroke capture, raw input, hooks |
| `injection` | `host-interaction/process/inject`, `load-code/pe/inject-*` | thread injection, shellcode injection |

Each angr function gets one of three states:

| State | Meaning | `label_mask` |
|---|---|---:|
| `positive` | A target CAPA rule matched and the address mapped to angr | 1 |
| `weak_negative` | CAPA observed the function, but no target rule matched | 1 |
| `unlabeled` | No successful CAPA-inventory mapping | 0 |

The weak-negative meaning is deliberately narrow:

> **No selected CAPA rule matched inside a function CAPA analyzed.**

It does **not** mean benign, safe, or "the capability is absent." Unlabeled functions are masked
out of the loss and evaluation; they are never silently converted to negatives. Positive and
weak-negative counts, exact/containment mapping, unresolved matches, and many-to-one collisions
are reported per sample. Mapping coverage and a Ghidra audit are pilot gates.

Training uses a masked `BCEWithLogitsLoss`. Evaluation reports positive-only metrics and
"agreement with CAPA weak negatives" separately; it does not call the latter specificity or
true-negative rate. A positive-unlabeled sensitivity analysis is optional, not the primary
pipeline. Label incidence is reported per label and per family; any label projecting below ~300
positive functions full-set is a stop-and-revisit condition.

---

## 5. Phases

No dates. Each phase has an exit gate; the next phase does not start until the gate passes.

### Phase 0 — Data foundation — complete

- `src/data/repair_pe.py`: deterministic PE header repair (machine, subsystem) into a scratch copy.
- `src/data/build_manifest.py`: manifest and frozen splits; quality flags, family metadata, and
  imphash/sha cluster keys.
- `src/data/validate_manifest.py`: angr load gate and stratified CAPA smoke test.
- `configs/phase0.toml`, `tests/test_phase0.py`: pinned filter/split settings and unit tests.
- `data/manifest.csv`: 4,474 rows; 2,814 marked clean.
- `data/splits/main.json`, `data/splits/lofo.json`: frozen assignments.
- `results/phase0_report.md`, `phase0_summary.json`, `phase0_validation.csv`,
  `phase0_capa_smoke.csv`: counts, integrity check, and gate evidence.
- **Gate:** met. All **2,814/2,814** clean rows load in angr; **12/12** stratified CAPA smoke samples
  return exit 0; zero imphash/sha clusters cross splits; counts documented. A full-set CAPA
  exit-code pass is the Phase 1 labeling run, not a Phase 0 step.

### Pilot — label contract + end-to-end on ~200 samples

Run Phases 1–4 on 200 clean samples drawn from the frozen main split, plus 20 known-bad samples
(10 .NET, 10 packed) to prove the filters reject them. Include all 26 keylogger train + 6 val
samples (not test); fill the remainder from injection and antidebug. A uniform random 200 would
not measure keylogger at all.

The pilot must first settle the label contract on real JSON. It should compare the old
`layout.functions` view with the `feature_counts.functions` + rule-scope view and quantify how
many positives and weak negatives change. It must not proceed to full labeling until that
comparison and the mapping audit are clean.

Pilot configuration: [`configs/pilot.toml`](configs/pilot.toml).

- **Gate:**
  - 100% repair success; CAPA/angr load all clean pilot samples.
  - ≥95% of CAPA-observed functions map to angr (exact or containment).
  - ≥95% of target rule matches map to an angr function/block; unresolved target matches <2% and
    individually logged.
  - Per-label positive counts and projected full-set counts; label census.
  - 30–50 functions audited in Ghidra, stratified by label, bucket, and label status.
  - Measured angr seconds/sample and RSS; block-count distribution; one measured training epoch
    (wall time, loader share, RSS); full-API vs no-API sanity signal.
- Abort or revise if any label projects below ~300 positive functions, if clean-sample failure
  exceeds 20%, or if mapping coverage misses the thresholds. Keylogger is the most likely label to
  trigger the stop condition.
- The full run is committed only after the pilot numbers replace the rough estimates.

The pilot is a pipeline and label-contract test, not a test-set evaluation. Do not tune on the
main test split.

### Phase 1 — CAPA labeling (full clean set)

- 4 workers, resume by `sample_id`, 240 s timeout, JSON to `data/labels/capa_raw/` (ignored).
- `src/label/run_capa.py`, `src/label/parse_capa.py`, `src/label/mapping.py`.
- Parse `feature_counts.functions` as the analyzed inventory; use rule scopes for function/block
  matches; use `layout.functions` only for block-to-function mapping.
- `data/labels/function_labels.parquet`: `sample_id`, `func_va`, `capa_func_va`, three binary
  labels, `label_status`, `label_mask`, matched rules, matched block addresses, mapping method,
  and collision flag.
- Record CAPA version, rules commit/dirty status, argv, sample SHA-256, extractor, and base
  address in label metadata.
- Report mapping coverage, unresolved matches, many-to-one collisions, label census, and
  `source_bucket × label` cross-tabs.
- **Gate:** label census (per label, per family); ≥300 projected positives per label; mapping
  coverage thresholds from the pilot; stop if any label is too sparse or mapping is unresolved.

### Phase 2 — CFG extraction

- `src/extract/angr_cfg.py`, `src/extract/batch_extract.py`.
- `CFGFast(normalize=True, resolve_indirect_jumps=True, data_references=False)`, 4 workers,
  size-aware queue, 300 s cap, RSS watchdog at 3 GB, resume by sample.
- Use **per-function** graphs. Message-passing edges must be intraprocedural: assert
  `func_id[src] == func_id[dst]` for every edge; drop and log cross-function edges. Calls are node
  features, not graph edges. Preserve edge direction in the baseline.
- Store per-sample packed arrays (node features not yet computed): block address/size,
  instructions, call targets, directed edges, `func_id`, function VA/size.
- **Gate:** ≥80% clean-sample extraction coverage; failures categorized; memory violations logged;
  zero cross-function edges in the training dataset.

### Phase 3 — Features and datasets

- Opcode 50-dim vocabulary (train split only), structural 5-dim, API 80-dim from angr-resolved call
  targets, architecture flag 1-dim → **136 dims**. No-API variant: 56 dims.
- Fit opcode/API vocabularies and all scalers on **train only**. In the no-API variant, remove API
  identities from every feature path, not just the 80-dim vector.
- Packed per-sample arrays: node features, `edge_index`, `func_id`, node labels, function labels,
  `label_mask`.
- Custom PyG `Dataset` with segment pooling by `func_id`; no per-function files, no `gpickle`.
- **Gate:** shapes, no NaN/Inf, split integrity (`sample_id` and cluster sets disjoint), no
  train/test vocabulary overlap, DataLoader batch test, no API leakage in the no-API build.

### Phase 4 — Stage 1 classifier

- GCN: 2 layers, 64 hidden, BatchNorm + ReLU + dropout 0.3, per-function mean+max pooling,
  3 output logits. GAT comparison: 4 heads × 16.
- Loss: masked `BCEWithLogitsLoss` with per-label `pos_weight`; Adam 1e-3; early stopping
  patience 15. Unlabeled functions are excluded by `label_mask`.
- Runs: full-API, no-API, API-dropout p=0.5; 3 seeds once the epoch cost is measured.
- Baselines and ablations:
  - majority per label;
  - MLP on pooled features (no graph);
  - GCN with CFG edges removed / MLP on node features (does message passing help?);
  - logistic regression or random forest on pooled features (does a simple model suffice?).
- **Gate:** report whether no-API retains signal and whether graph structure contributes anything
  beyond node features. A full-API-only win or a no-edge/MLP win is a negative result and is
  reported as such, not hidden.

### Phase 5 — Evaluation and write-up

- Primary positive-only metrics: per-label precision/recall/F1 at validation-tuned thresholds,
  AUROC/AP. Report "agreement with CAPA weak negatives" separately, never as true-negative rate.
- Calibration with the caveat that weak negatives bias it.
- Per-family breakdown and **repeated leave-one-family-out** results for eligible families;
  report the distribution across held-out families, not one number. Eligibility is per label:
  at least ~20 clean samples and ~30 positive functions in the held-out family. Keylogger remains
  a single-family case study because only `lokibot` is large enough to hold out.
- Confidence intervals by **cluster-level bootstrap** for the main split and binary-level
  bootstrap within held-out families for LOFO. Do not resample functions independently.
- Frozen test set; no tuning on test.
- Latency per stage.
- **Gate:** reproducible results from committed configs and seeds; CIs and held-out-family
  spread reported; no claim of benign detection.

### Phase 6 — Optional Stage 2 localization

Only if Phase 4 produces a usable Stage 1.

- Train on out-of-fold Stage 1 predictions (includes false positives).
- Node labels from **target-rule** `matched_basic_blocks`; block labels inherit the same weak-label
  and mapping caveats as function labels.
- Compare against a rule-based block baseline.
- Metrics: block IoU, precision@k, top-k recall; no-API variant.
- **Gate:** Stage 2 beats the rule baseline on held-out data, or the negative result is documented.

### Phase 7 — Optional extras

- GAT attention figures as an **appendix**, not proof.
- `run_pipeline.py` end-to-end demo; notebooks; final docs.

---

## 6. Splits

Two protocols, reported separately:

1. **Main:** group key = `imphash` (or `sha:<content>` when there are no imports), stratified by
   `source_bucket`, 70/15/15, greedy bin-packing per bucket. No cluster crosses splits. The largest
   cluster is placed in train; train is consequently dominated by near-duplicates, while val/test
   are cluster-diverse.
2. **Leave-one-family-out (LOFO):** hold out one mid-size family per bucket; train on the rest.
   This is the generalization test: unseen family, not just unseen binary. The frozen JSON is the
   initial single-fold test. Phase 5 repeats LOFO for each family with enough clean samples and
   enough positive functions for the label; report the distribution across held-out families.

| Protocol | Train | Val | Test | Clusters (train/val/test) |
|---|---:|---:|---:|---|
| Main | 1,969 | 423 | 422 | 112 / 95 / 103 |
| LOFO (initial) | 2,302 | 405 | 107 | 151 / 111 / 48 |

Main per bucket (train/val/test): keylogger 26/6/6, injection 951/204/204, antidebug
992/213/212. LOFO holds out `lokibot` (23), `emotet` (50), and `ursnif` (34); keylogger has only
13 train / 2 val after `lokibot` is removed. Keylogger cannot support a meaningful repeated-LOFO
distribution; it is reported as a case study and subject to the label-census stop condition.

All function- and block-level datasets inherit the sample split. Splits are frozen JSON files and
record the manifest SHA-256 (`fcd27780…`); regenerating them requires an explicit version bump.

Reported counts: files, imphash clusters, families. Metrics are always per family. Because one
890-sample cluster is 45% of train, report cluster-level or family-held-out metrics alongside
sample-level metrics; sample accuracy alone will overstate generalization. Confidence intervals
use imphash-cluster resampling on main and binary-level resampling within held-out families on
LOFO; functions are never treated as independent observations.

---

## 7. Compute

Kali VM: 16 GB RAM, 4 physical cores / 8 threads (i7-1165G7), CPU-only PyTorch.

| Work | Workers | Measured / rough wall clock |
|---|---:|---|
| Phase 0 manifest + splits | 1 | ~1–2 min |
| Phase 0 angr load gate (2,814) | 4 | 184 CPU-s → ~46 s wall |
| Phase 0 CAPA smoke (12) | 1 | 193 s |
| Pilot (200 + 20) | 4 | 2–4 h |
| CAPA full set (2,814) | 4 | 7–11 h |
| angr full set (2,814) | 4 (3 if RSS >3 GB) | 12–18 h |
| Features + dataset | 4 | 1–2 h |
| Stage 1 | 4 torch threads | measured by pilot |

Phase 0 numbers are measured on this VM. The remaining figures are rough extrapolations; the pilot
replaces them. CAPA and angr are single-threaded, so 4 physical cores cap real parallelism. Keep
the phases sequential. Repeated LOFO reuses extracted features and retrains only; budget it as
`eligible_folds × Stage 1`, not as another extraction pass.

**GPU:** the installed wheel is `torch 2.14.0+cpu`; `torch.cuda.is_available()` is `False`,
`get_arch_list()` is empty, and there is no `nvidia-smi`. The MX350 lives on the Windows host and
VMware Workstation does not expose it to the guest. It is GP107 (sm_61, 2 GB). A CUDA build is only
worth trying if `'sm_61'` appears in that build's `torch.cuda.get_arch_list()`; even then, 2 GB VRAM
streams batches and the gain on a 2×64 model is likely small. Decision is deferred until the pilot
measures a CPU epoch. Packed arrays are portable, so training can move to WSL2/Windows without
changing extraction.

---

## 8. Repository layout

Current:

```
configs/phase0.toml         Phase 0 filters and split configuration
configs/pilot.toml          pilot sampling, mapping gates, CAPA pin
docs/labeling_contract.md   operational weak-label contract
docs/archive/               superseded legacy plan, kept for history
src/collect/mb_fetch.py     legacy sample-collection script; not used by the pipeline
src/data/repair_pe.py       deterministic machine/subsystem repair
src/data/build_manifest.py  manifest + frozen splits
src/data/validate_manifest.py  angr load gate + CAPA smoke test
tests/test_phase0.py        repair and split-integrity tests
data/raw/                   BODMAS binaries (ignored)
data/bodmas/                BODMAS metadata and npz (ignored)
data/manifest.csv           4,474 rows; 2,814 clean
data/splits/main.json       frozen main split
data/splits/lofo.json       frozen leave-one-family-out split
data/labels/                empty until Phase 1
data/graphs/                reserved (ignored)
results/phase0_report.md    counts, split integrity, gate status
results/phase0_summary.json
results/phase0_validation.csv
results/phase0_validation_summary.json
results/phase0_capa_smoke.csv
```

Planned:

```
configs/                   full.toml (pilot.toml already exists)
src/data/                  repair_pe.py, build_manifest.py, dataset.py
src/label/                 run_capa.py, parse_capa.py, mapping.py
src/extract/               angr_cfg.py, batch_extract.py
src/features/              opcode_features.py, api_features.py, structural_features.py, compose.py
src/models/                stage1_gcn.py, stage1_gat.py
src/train/                 trainer_s1.py
src/eval/                  evaluate_s1.py, plots.py
src/run_pilot.py
notebooks/                 cfg inspection, feature validation, results
data/manifest.csv
data/splits/main.json, lofo.json
data/labels/function_labels.parquet
data/labels/capa_raw/      raw CAPA JSON (ignored)
data/processed/            ephemeral repaired copies and packed arrays (ignored)
```

---

## 9. Reproducibility

- Python 3.14 virtualenv; `requirements.txt` pins direct dependencies; `requirements.lock.txt`
  freezes the environment.
- CAPA **9.1.0** with rules commit `805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5`; the rules
  repository working tree was clean when pinned. Every label run records the actual CAPA version,
  rules commit/dirty status, argv, sample SHA-256, extractor, and base address. A rules change is a
  new label version.
- CPU-only PyTorch is intentional.
- Seeds fixed per run; configs in TOML; resume state and failure logs kept.
- Raw data is not committed. Labels, splits, manifests, configs, and small result tables are.

Setup:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 10. Limitations and risks

- **Weak labels.** CAPA rules are the target. The no-API ablation is the only defense against
  simply learning CAPA's API logic; it may still fail.
- **No benign class.** All-zero means "no selected CAPA rule matched in a function CAPA analyzed",
  not "safe" or "capability absent". These are weak negatives.
- **Negative-label uncertainty.** CAPA's layout is match-oriented; `layout.functions` is not an
  inventory. The label contract uses `feature_counts.functions` plus rule scopes, but unmatched
  functions may still be false negatives. Positive-only metrics and the optional PU sensitivity
  analysis are the defense; do not report weak-negative agreement as true specificity.
- **Mapping uncertainty.** CAPA and angr may recover different function boundaries, and addresses
  must be base-normalized. Exact/containment coverage, unresolved matches, and many-to-one
  collisions are reported and gated in the pilot; unmapped angr functions stay unlabeled.
- **Family skew.** The clean set is dominated by ceeinject (1,127) and gandcrab (937); keylogger
  has only 38 clean samples. A random file split would leak; grouped splits are mandatory.
- **Clean-set erosion.** Only 2,814/4,474 files survive quality filters (1,398 packed, 265 .NET,
  4 non-BODMAS). Results do not cover the excluded 37%. Only 9 clean samples are x64, so the
  architecture flag is nearly constant and x64 generalization is not established.
- **Keylogger sparsity.** 38 clean samples (23 lokibot) produce 26/6/6 main train/val/test and
  13/2 train/val under LOFO. The keylogger label census may fall below the ~300-function stop
  threshold; the pilot should be allowed to fail here rather than force a three-label result.
- **CAPA coverage.** Many functions have no target match; target-positive counts may be sparse even
  when CAPA analyzes the sample. Label census may fail for keylogger and injection.
- **Tiny graphs.** Median ~5 blocks per function; the GNN has limited structure to exploit.
- **Near-duplicates.** imphash is a coarse proxy. The largest clean cluster has 890 samples and is
  45% of train; LOFO and cluster-level reporting are the stronger generalization tests.
- **Disarmed headers.** Any tool that trusts the PE machine field needs the repair step.
- **No GPU in the VM.** Training is CPU-bound; measure before committing epochs.

---

## 11. Safety

The repository contains live malware samples under `data/raw/` (git-ignored). Never execute them.
Analyse only inside an isolated VM with no network access and no shared clipboard or host mounts
beyond the dedicated data folder. Do not commit samples, CAPA outputs derived from them, or
anything that bypasses the licence terms.

---

## 12. References

- BODMAS: An Open Dataset for Learning based Temporal Analysis of PE Malware (IEEE S&P Workshops,
  2021).
- Mandiant CAPA: <https://github.com/mandiant/capa>
- angr: Shoshitaishvili et al., "SOK: (State of) The Art of War: Offensive Techniques in Binary
  Analysis" (IEEE S&P, 2016).
- PyTorch Geometric: Fey & Lenssen, "Fast Graph Representation Learning with PyTorch Geometric"
  (ICLR Workshop, 2019).
- GCN: Kipf & Welling, "Semi-Supervised Classification with Graph Convolutional Networks" (ICLR,
  2017).
- GAT: Veličković et al., "Graph Attention Networks" (ICLR, 2018).
