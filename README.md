# CFG-GNN: Function-Level Malware Capability Classification

Weakly supervised classification of PE binaries at the **function level**, using control-flow graphs
(CFGs), basic-block features, and graph neural networks.

**Status:** pre-Phase 0. The plan below is frozen; Phase 0 (data foundation) is the next
implementation step. There are no CAPA labels, extracted graphs, or trained models in the
repository yet.

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
| "Class 0" | Removed | Unmatched = all-zero label vector, not a benign class |
| Source folders | `source_bucket`, used only for stratification | The family-to-class mapping was heuristic and is not ground truth |
| Supervision | CAPA 9.1 rule namespaces | Weak labels, documented as such |
| API features | Full vs no-API vs API-dropout | Directly tests "does the model just re-learn CAPA?" |
| Splits | imphash/family-grouped | Near-duplicates must never cross train/test |
| Scale | Full clean corpus, no compute caps | Filter only for data quality |
| Compute | CPU-first, pilot before full run | angr/CAPA dominate; GPU only helps training |
| Schedule | Phases and gates, no fixed dates | Throughput is measured, not guessed |

---

## 3. Dataset

BODMAS "disarmed" PE corpus, stored under `data/raw/` (git-ignored).

| Source bucket | Files in path lists | Families | Dominant family |
|---|---:|---:|---|
| `keylogger` | 536 | 5 | bladabindi (491) |
| `injection` | 1,528 | 7 | ceeinject (1,169) |
| `antidebug` | 2,406 | 7 | gandcrab (957), smokeloader (868) |
| **Total** | **4,470** | **19** | — |

There are 4,474 `.exe` files on disk: the extra 4 are nested TheZoo samples outside the BODMAS
path lists.

**Data quality filters (no compute caps)**

| Filter | Approx. count |
|---|---:|
| .NET assemblies (`mscoree` import) | 263 |
| Packed / UPX-section samples | 502 |
| Corrupt (no PE header) | 1 |
| Non-BODMAS / legacy extras | 2 |
| Non-`.exe` archives and metadata | 44 |

The exact clean count is produced by Phase 0; expected range is **3,600–3,800**. .NET and packed
samples are excluded rather than unpacked; unpacking is a separate project.

**Header disarmament.** 4,469 of 4,472 inspected binaries have `machine = 0` and
`subsystem = 0`. angr fails with `ArchNotFound` and CAPA exits 21 until the `machine` field is
repaired (0x14c for PE32, 0x8664 for PE32+). Repair is deterministic and done into an ephemeral
per-job copy; `data/raw/` is never modified.

**Hashing caveat.** Filenames are the BODMAS altered-sample IDs. Their content SHA-256 is
**different** from the filename. Join labels on `sample_id` (filename stem), and store
`content_sha256` separately in the manifest.

**Buckets are not labels.** The family→bucket mapping is heuristic. Phase 1 reports a
`source_bucket × CAPA-label` cross-tab so this assumption is visible instead of hidden.

---

## 4. Labels

CAPA 9.1 JSON is parsed as follows:

- `rules[rule].matches` is a **list** of `[address, match]` pairs, not a dict keyed by address.
- There is no `meta.function` on matches. Function attribution uses
  `meta.analysis.layout.functions[].address` and `matched_basic_blocks`.
- File/process-scope matches are not function labels.

| Label | CAPA namespace prefix | Examples |
|---|---|---|
| `anti_debug` | `anti-analysis/anti-debugging` | debugger detection, timing checks |
| `keylogger` | `collection/keylog` | keystroke capture, raw input, hooks |
| `injection` | `host-interaction/process/inject`, `load-code/pe/inject-*` | thread injection, shellcode injection |

- Unit: one angr-recovered function.
- Label vector: 3 binary values; all-zero when CAPA parsed the function but no targeted rule matched.
- Functions CAPA never parsed are unlabeled and excluded from Stage 1.
- Optional Stage 2 block labels come from `matched_basic_blocks` and inherit the same caveats.

Label incidence is reported per label and per family. Any label with fewer than ~300 functions
full-set is a stop-and-revisit condition.

---

## 5. Phases

No dates. Each phase has an exit gate; the next phase does not start until the gate passes.

### Phase 0 — Data foundation

- `src/data/repair_pe.py`: deterministic PE header repair (machine, subsystem) into a scratch copy.
- `src/data/build_manifest.py`: manifest with `sample_id`, `content_sha256`, `imphash`, `family`,
  `source_bucket`, `arch`, `is_dotnet`, `is_packed`, `size`, `quality_flags`.
- `data/manifest.csv`: one row per sample; small enough to track.
- `data/splits/main.json`, `data/splits/lofo.json`: frozen assignments.
- **Gate:** all clean rows load in angr and return CAPA exit 0; zero imphash-cluster overlap
  between splits; counts documented.

### Pilot — end-to-end on ~200 samples

Run Phases 1–4 on 200 clean samples drawn from the frozen main split, plus 20 known-bad samples
(10 .NET, 10 packed) to prove the filters reject them.

- **Gate:** 100% repair success; CAPA/angr load all clean pilot samples; per-label hit rate and
  projected full-set positive counts; measured angr seconds/sample and RSS; block-count
  distribution; one measured training epoch (wall time, loader share, RSS); full-API vs no-API
  sanity signal.
- Abort or revise if any label projects below ~300 functions, or if clean-sample failure exceeds
  20%.

The full run is committed only after the pilot numbers replace the rough estimates.

### Phase 1 — CAPA labeling (full clean set)

- 4 workers, resume by `sample_id`, 240 s timeout, JSON to `data/labels/capa_raw/` (ignored).
- `src/label/parse_capa.py`, `src/label/mapping.py`.
- `data/labels/function_labels.parquet`: `sample_id`, `func_va`, three binary labels,
  matched rules, matched block addresses.
- Label census and `source_bucket × label` cross-tab.
- **Gate:** label census (per label, per family); stop if any label is too sparse.

### Phase 2 — CFG extraction

- `src/extract/angr_cfg.py`, `src/extract/batch_extract.py`.
- `CFGFast(normalize=True, resolve_indirect_jumps=True, data_references=False)`, 4 workers,
  size-aware queue, 300 s cap, RSS watchdog at 3 GB, resume by sample.
- Store per-sample packed arrays (node features not yet computed): block address/size,
  instructions, call targets, edges, `func_id`, function VA/size.
- **Gate:** ≥80% clean-sample extraction coverage; failures categorized; memory violations logged.

### Phase 3 — Features and datasets

- Opcode 50-dim vocabulary (train split only), structural 5-dim, API 80-dim from angr-resolved call
  targets, architecture flag 1-dim → **136 dims**. No-API variant: 56 dims.
- Packed per-sample arrays: node features, `edge_index`, `func_id`, node labels, function labels.
- Custom PyG `Dataset` with segment pooling by `func_id`; no per-function files, no `gpickle`.
- **Gate:** shapes, no NaN/Inf, split integrity (`sample_id` and cluster sets disjoint), DataLoader
  batch test.

### Phase 4 — Stage 1 classifier

- GCN: 2 layers, 64 hidden, BatchNorm + ReLU + dropout 0.3, per-function mean+max pooling,
  3 output logits.
- GAT comparison: 4 heads × 16.
- Loss: `BCEWithLogitsLoss` with per-label `pos_weight`; Adam 1e-3; early stopping patience 15.
- Runs: full-API, no-API, API-dropout p=0.5; 3 seeds once the epoch cost is measured.
- Baselines: majority per label; MLP on pooled features (no graph).
- **Gate:** report whether no-API retains signal. A full-API-only win is a negative result and is
  reported as such, not hidden.

### Phase 5 — Evaluation and write-up

- Per-label precision/recall/F1 at tuned thresholds, AUROC/AP, calibration, per-family breakdown,
  bootstrap confidence intervals.
- Frozen test set; no tuning on test.
- Latency per stage.
- **Gate:** reproducible results from committed configs and seeds.

### Phase 6 — Optional Stage 2 localization

Only if Phase 4 produces a usable Stage 1.

- Train on out-of-fold Stage 1 predictions (includes false positives).
- Node labels from CAPA `matched_basic_blocks`.
- Compare against a rule-based block baseline.
- Metrics: block IoU, precision@k, top-k recall; no-API variant.
- **Gate:** Stage 2 beats the rule baseline on held-out data, or the negative result is documented.

### Phase 7 — Optional extras

- GAT attention figures as an **appendix**, not proof.
- `run_pipeline.py` end-to-end demo; notebooks; final docs.

---

## 6. Splits

Two protocols, reported separately:

1. **Main:** group key = `imphash`, stratified by `source_bucket`, 70/15/15, greedy bin-packing so
   no cluster crosses splits and no split is dominated by one huge cluster. The largest cluster is
   placed in train.
2. **Leave-one-family-out (LOFO):** hold out one mid-size family per label; train on the rest.
   This is the generalization test: unseen family, not just unseen binary.

All function- and block-level datasets inherit the sample split. Splits are frozen JSON files;
regenerating them requires an explicit version bump.

Reported counts: files, imphash clusters, families. Metrics are always per family.

---

## 7. Compute

Kali VM: 16 GB RAM, 4 physical cores / 8 threads (i7-1165G7), CPU-only PyTorch.

| Work | Workers | Rough wall clock |
|---|---:|---|
| Phase 0 manifest/repair/splits | 8 (I/O) | 20–40 min |
| Pilot (200 + 20) | 4 | 2–4 h |
| CAPA full set | 4 | 7–11 h |
| angr full set | 4 (3 if RSS >3 GB) | 12–18 h |
| Features + dataset | 4 | 1–2 h |
| Stage 1 | 4 torch threads | measured by pilot |

These are rough figures from 20–45 sample measurements; the pilot replaces them. CAPA and angr are
single-threaded, so 4 physical cores cap real parallelism. Keep the phases sequential.

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
src/collect/mb_fetch.py    legacy sample-collection script; not used by the pipeline
data/raw/                  BODMAS binaries (ignored)
data/bodmas/               BODMAS metadata and npz (ignored)
data/labels/               empty until Phase 1
data/graphs/               reserved (ignored)
results/                   empty until Phase 4
```

Planned:

```
configs/                   pilot.toml, full.toml
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
- **No benign class.** All-zero means "unmatched", not "safe".
- **Family skew.** 19 families, dominated by bladabindi, ceeinject, gandcrab, and smokeloader.
  A random file split would leak; grouped splits are mandatory.
- **Exclusion bias.** .NET and packed samples are dropped, so results do not cover them.
- **CAPA coverage.** Some samples yield 0–2 functions; label census may be sparse for keylogger and
  injection.
- **Tiny graphs.** Median ~5 blocks per function; the GNN has limited structure to exploit.
- **Near-duplicates.** imphash is a coarse proxy; LOFO is the stronger generalization test.
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
