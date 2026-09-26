# CFG-Function-Localization-via-Graph-Neural-Networks
RESEARCH PROJECT · X86 MALWARE · GNN

Execution plan — environment setup through trained model with evaluation. Each day is a concrete unit of work with specific deliverables.

Phase 1 · Data

Phase 2 · CFG Extraction

Phase 3 · Feature Engineering

Phase 4 · Model Training

Phase 5 · Evaluation

**Week 1** · Environment · Data · CFG Extraction

Day 01 Environment Setup & Project Skeleton DATA ›

Goal: Fully reproducible Python environment + project structure committed to Git

- Set up VS Code Remote-SSH into Kali VM — install the Remote-SSH extension, add VM host entry to `~/.ssh/config`, confirm terminal opens inside KaliTest: open a file on Kali filesystem from Windows VS Code
- Create project directory `~/cfg-gnn/` and initialize Git repo with a `.gitignore` (exclude `data/raw/`, `*.pkl`, `__pycache__`)Push initial commit to GitHub (skandarhadrich-cell)
- Create `environment.yml` or `requirements.txt` — install: `angr`, `capstone`, `pyvex`, `networkx`, `torch`, `torch-geometric`, `torch-scatter`, `torch-sparse`, `pandas`, `numpy`, `scikit-learn`, `matplotlib`, `tqdm`Use a dedicated virtualenv: `python3 -m venv venv && source venv/bin/activate`
- Verify angr installs cleanly — run `import angr; print(angr.__version__)` in a test scriptKnown issue: angr may need `pip install angr --no-build-isolation` if z3 fails
- Download CAPA binary (latest Linux release) from GitHub Releases, place in `~/tools/capa`, run `./capa --version`Also download CAPA rules repo: `git clone https://github.com/mandiant/capa-rules`
- Create project folder structure: `data/raw/`, `data/labels/`, `data/graphs/`, `src/extract/`, `src/features/`, `src/models/`, `src/eval/`, `notebooks/`, `results/`
- Submit BODMAS dataset access request at bodmas.org with ENIT affiliationKeep confirmation email — approval typically 2–4 days

**DELIVERABLE**Working SSH tunnel to Kali, activated venv with all packages, CAPA running, project skeleton pushed to GitHub

Day 02 Interim Sample Collection (TheZoo + MalwareBazaar) DATA ›

Goal: \~150–200 malware PE binaries on disk, organized by family, with benign baseline

- Clone TheZoo repo: `git clone https://github.com/ytisf/theZoo` — extract PE samples from `malwares/Binaries/` relevant families: Mirai (process injection), Agent Tesla (keylogger), NjRAT variantsDisable Windows Defender on the Kali VM's shared folders or work fully inside Kali
- Write script `src/collect/mb_fetch.py` to pull recent PE samples from MalwareBazaar API by tag: `keylogger`, `injector`, `antidebug`Use `https://mb-api.abuse.ch/api/v1/` with POST query_tag — free, no auth required for queries
- Collect \~100 benign PE binaries: copy non-critical Windows System32 DLLs from a clean Windows 10 ISO (mount ISO in Kali with `mount -o loop`) — `notepad.exe`, `calc.exe`, common DLLsLabel all benign files consistently: place in `data/raw/benign/`
- Write `src/collect/organize.py` — walks `data/raw/`, verifies PE magic bytes (`MZ` header), logs filename + family + source to `data/labels/raw_manifest.csv`Columns: `sha256, filepath, family, source, arch`
- Run `file` command on all samples, filter to x86 PE only (32-bit) — log and discard x64 for nowUse Python `subprocess` to batch-run `file` on all samples and parse output
- Verify sample count by family — target minimum: 40 samples per malware class, 100 benignPrint family distribution table to console

**DELIVERABLE**`data/raw/` populated, `raw_manifest.csv` with sha256 + family labels, x86 PE verified

Day 03 CAPA Labeling Pipeline DATA ›

Goal: Function-level ground truth labels for all samples, mapped to 4 classes

- Write `src/label/run_capa.py` — batch-runs CAPA on every sample in `raw_manifest.csv`, saves JSON output per sample to `data/labels/capa_raw/`CAPA command: `capa --rules ~/tools/capa-rules -j sample.exe > output.json`. Use `subprocess` with timeout=120s per sample
- Write `src/label/parse_capa.py` — parses CAPA JSON, extracts `matches` section, pulls function addresses and matched rule namesCAPA JSON structure: `result.rules[rule_name].matches[addr]` — each match has a function VA
- Write ATT&CK → class mapping dict in `src/label/mapping.py`: anti-debug rules → class 1 (e.g. "check for debugger via NtQueryInformationProcess", "timing check") keylogger rules → class 2 (e.g. "capture keystrokes", "SetWindowsHookEx") process injection rules → class 3 (e.g. "inject via WriteProcessMemory", "CreateRemoteThread") everything else → class 0 (benign/unknown function)
- Produce `data/labels/function_labels.csv` — columns: `sha256, func_va, class_id, class_name, capa_rule`
- Write `src/label/heuristics.py` — supplements CAPA with name-based heuristics for non-stripped samples: function names containing `Anti`, `Debug`, `Hook`, `Inject`, `Log`, `Key` → assign tentative labelOnly applied where CAPA gave no label — marks as `heuristic=True` in CSV
- Run full labeling on all samples, print class distribution — verify no severe imbalance (target: class 0 not more than 10× any other class combined)If severely imbalanced, note it — you'll handle via weighted loss in training

**DELIVERABLE**`function_labels.csv` with VA-level labels for all samples. Class distribution report printed.

Day 04 Ghidra Headless Disassembly & angr CFG Extraction EXTRACT ›

Goal: CFG extracted for 10 test samples — basic blocks, edges, function boundaries confirmed correct

- Write Ghidra headless script `src/extract/ghidra_analyze.sh` — runs `analyzeHeadless` on a single binary, exports function list + import table to JSON via a Ghidra Python scriptGhidra script path: `support/analyzeHeadlessScripts/`. Export: function start addresses, names (if present), called imports
- Write `src/extract/angr_cfg.py` — loads a PE binary with angr, runs `proj.analyses.CFGFast()`, iterates over all functions, extracts basic blocks and edges per functionKey angr objects: `cfg.functions` → function objects; `func.blocks` → basic blocks; `func.graph.edges()` → CFG edges
- Cross-reference angr function addresses with Ghidra output — merge to get: angr CFG structure + Ghidra import/API resolutionMatch by function start VA. Where names differ, prefer Ghidra's resolved symbol
- Test on 10 samples — manually inspect 2–3 CFGs using `networkx.draw()` in a Jupyter notebook to verify structure looks correctOpen `notebooks/01_cfg_inspection.ipynb` for this
- Handle common angr failure modes: `AngrCFGError` on packed samples (catch exception, log, skip), timeout on very large binaries (set `CFGFast` time limit)Log all failed samples to `data/logs/extraction_errors.log`

**DELIVERABLE**`angr_cfg.py` working on 10 test samples. Notebook showing visualized CFG of at least 2 binaries.

Day 05 Batch CFG Extraction Pipeline EXTRACT ›

Goal: All samples processed through CFG extraction, graphs serialized to disk

- Write `src/extract/batch_extract.py` — reads `raw_manifest.csv`, processes each binary through angr + Ghidra, saves per-binary NetworkX graph as `data/graphs/{sha256}.gpickle`Use `tqdm` progress bar. Implement resume logic: skip sha256 if `.gpickle` already exists
- Each saved graph stores: node attributes (`block_addr`, `block_size`, `raw_bytes`, `api_calls`: list), edge type (fall-through vs jump), function-level metadata (`func_va`, `func_name`)Store as NetworkX node/graph attributes before serializing
- Run batch extraction on all \~250 samples — expected time: 5–15 min on your i7 depending on sample complexityMonitor memory — angr can consume 1–2GB RAM per large binary. Kill and skip if RSS > 3GB
- Write `src/extract/graph_stats.py` — for each extracted graph: log node count, edge count, function count. Print summary statistics (mean/median nodes per graph)Flag outliers: graphs with >5000 nodes are likely full-binary CFGs leaking function boundaries
- Merge extracted graph data with `function_labels.csv` — annotate each function-subgraph with its class labelKey join: `sha256 + func_va`

**DELIVERABLE**All graphs serialized to `data/graphs/`. Stats report showing node/edge distribution. Labels merged.

Day 06 Node Feature Vector Engineering FEATURES ›

Goal: Each basic block node has a fixed-length numeric feature vector ready for GNN input

- Write `src/features/opcode_features.py` — uses capstone to disassemble each basic block's raw bytes, produces a 50-dim opcode frequency vector (top-50 x86 opcodes by frequency in your corpus)First pass: collect all opcodes across corpus to determine top-50. Save vocab to `data/opcode_vocab.json`
- Write `src/features/api_features.py` — binary indicator vector over a predefined API call list (Windows API functions relevant to malware: `CreateRemoteThread`, `VirtualAllocEx`, `SetWindowsHookEx`, `GetAsyncKeyState`, `IsDebuggerPresent`, etc.)Build API list from CAPA rules + common malware API reference. \~80 APIs = 80-dim binary vector
- Write `src/features/structural_features.py` — 5 additional scalar features per node: block size (bytes), instruction count, has_call (bool), has_ret (bool), has_loop_back_edge (bool)Loop back edge: check if any successor has a lower address than current block start
- Write `src/features/compose.py` — concatenates all feature vectors into a single node feature matrix. Final dim: `50 + 80 + 5 = 135` per nodeOutput: numpy array of shape `(num_nodes, 135)` per graph
- Validate on 5 graphs: print feature matrix shape, check for NaN/Inf, check opcode vector is not all-zero for non-trivial blocks

**DELIVERABLE**Feature extraction pipeline working. Per-node 135-dim vectors validated on sample graphs. Vocab files saved.

Day 07 PyG Dataset Class + Train/Val/Test Split FEATURES ›

Goal: A proper `torch_geometric.data.Dataset` class that yields ready-to-train graph Data objects

- Write `src/data/cfg_dataset.py` — subclasses `torch_geometric.data.Dataset`. Each item is a `Data` object with: `x` (node features), `edge_index` (COO edge list), `y` (per-node labels), `num_nodes`Process method: loads `.gpickle`, runs feature extraction, converts to PyG Data, saves `.pt` to `data/processed/`
- Implement `__len__` and `__getitem__` correctly — test that `DataLoader` batches multiple graphs without errorPyG batching concatenates graphs into a single disconnected graph with a `batch` vector — verify this works
- Implement stratified train/val/test split (70/15/15) at the binary level (not function level — avoid data leakage from same binary in train and test)Use `sklearn.model_selection.train_test_split` on sha256 list, stratified by majority class of binary
- Compute and log class weights for weighted cross-entropy loss: `n_samples / (n_classes * class_count)`Save weights to `data/class_weights.json`
- Run a full DataLoader test: load one batch, print shapes of `x`, `edge_index`, `y` — verify dimensions are correctExpected: `x` shape `(total_nodes_in_batch, 135)`
- Commit everything — Day 7 is end of Week 1. Tag commit as `v0.1-data-pipeline`Push to GitHub

**DELIVERABLE**Working PyG Dataset. DataLoader verified. Train/val/test splits saved. `v0.1` Git tag pushed.

**Week 2** · Model Training · Evaluation · Analysis

Day 08 GCN Baseline Model MODEL ›

Goal: GCN model training and running to completion — baseline metrics on val set

- Write `src/models/gcn.py` — 3-layer GCN (`GCNConv`) with: input dim 135 → hidden 256 → hidden 128 → output 4 (num classes). Add BatchNorm after each conv, ReLU, Dropout(0.3)Node-level classification: no global pooling layer — output is per-node logits
- Write `src/train/trainer.py` — training loop with: weighted CrossEntropyLoss (using saved class weights), Adam optimizer (lr=1e-3), epoch loop, val loss + accuracy logged per epochBatch size: 16 graphs. Train for 100 epochs initially.
- Add early stopping: monitor val loss, patience=15 epochs, save best checkpoint to `results/checkpoints/gcn_best.pt`
- Run training — watch first 10 epochs to confirm loss is decreasing. If loss is static or NaN: check learning rate, verify labels are not all-zero, check edge_index has no self-loops causing issuesLog to console: `Epoch {e} | Train Loss {:.4f} | Val Loss {:.4f} | Val Acc {:.3f}`
- Save training loss curve data to `results/gcn_training_log.csv` for later plotting

**DELIVERABLE**GCN trained to convergence. Best checkpoint saved. Training log CSV written.

Day 09 GAT Model + Hyperparameter Tuning MODEL ›

Goal: GAT model trained, attention heads working, initial GCN vs GAT comparison on val set

- Write `src/models/gat.py` — 3-layer GAT (`GATConv`) with: 4 attention heads in layers 1–2, single head in output layer. Dims: 135 → 64×4=256 → 64×4=256 → 4Set `dropout=0.3` on attention coefficients. Add BatchNorm same as GCN.
- Reuse `trainer.py` for GAT — make model an argument to trainer, same hyperparams for fair comparisonSave GAT checkpoint to `results/checkpoints/gat_best.pt`
- Run GCN hyperparameter sweep over: lr ∈ {1e-3, 5e-4}, hidden dims ∈ {128, 256}, dropout ∈ {0.2, 0.3}4 combinations — run each for 50 epochs, pick best val loss. Log to `results/hparam_sweep.csv`
- Re-train GCN with best hyperparams found. Compare GCN vs GAT val accuracy and per-class F1Print side-by-side table to console
- If BODMAS access arrived: begin downloading samples and add to corpus (they can be processed through the same pipeline)

**DELIVERABLE**GAT trained. Best GCN hyperparams identified. GCN vs GAT val comparison table printed.

Day 10 Test Set Evaluation + Confusion Matrix EVAL ›

Goal: Full test set evaluation with per-class precision/recall/F1, confusion matrices for both models

- Write `src/eval/evaluate.py` — loads best checkpoint for a given model, runs on test set, collects all predicted and true labelsAggregate node-level predictions across all graphs in test set
- Compute per-class metrics using `sklearn.metrics.classification_report` — print and save to `results/gcn_test_report.txt` and `results/gat_test_report.txt`
- Plot confusion matrices for both models using matplotlib — save to `results/figures/`Use `sklearn.metrics.ConfusionMatrixDisplay`. 4×4 matrix for 4 classes.
- Plot training loss curves for both models on the same axes — save to `results/figures/loss_curves.png`
- Identify worst-performing class — if a class has F1 \< 0.5, note the likely cause: label noise (heuristic labels), class imbalance, or insufficient samplesThis analysis goes in your README/report

**DELIVERABLE**Test metrics for both models. Confusion matrices and loss curves saved as figures.

Day 11 Attention Weight Visualization (GAT) EVAL ›

Goal: Visual proof that GAT attention focuses on semantically meaningful edges in malicious functions

- Modify `gat.py` to return attention coefficients: set `return_attention_weights=True` in the first GATConv layerReturns `(edge_index, alpha)` — `alpha` is shape `(num_edges, num_heads)`
- Write `src/eval/visualize_attention.py` — picks one confirmed malicious function (process injection), draws its CFG with edge widths proportional to mean attention across headsUse matplotlib + networkx. Color nodes by predicted class.
- Compare: do high-attention edges connect blocks that contain the key API calls (`VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread` sequence)?This is the qualitative result — document what you observe, even if partial
- Repeat for one keylogger function and one anti-debug functionSave figures to `results/figures/attention_{class}.png`
- Write a short markdown note in `results/attention_analysis.md` describing what the attention patterns show

**DELIVERABLE**3 attention visualization figures. Markdown analysis note. Qualitative interpretation of attention patterns.

Day 12 Error Analysis + Model Hardening EVAL ›

Goal: Understand where the model fails and apply targeted fixes to boost weakest metrics

- Write `src/eval/error_analysis.py` — finds all misclassified nodes in the test set, groups by (true class → predicted class), retrieves the original basic blocksSample 10 false positives and 10 false negatives per class for manual inspection
- For sampled errors: disassemble the block with capstone and print instructions — do they look malicious/benign? This tells you if the error is a model failure or a label noise issue
- If class imbalance is a major driver of errors: implement `WeightedRandomSampler` in the DataLoader to oversample minority classesAlternative: increase weight for minority classes in loss — try both
- If opcode features seem weak (inspect feature importance via gradient × input): consider adding n-gram bigrams (consecutive opcode pairs) as additional featuresExtend `opcode_features.py` — adds \~200 dims for top-200 bigrams
- Re-train best model with any fixes applied. Compare new test metrics to Day 10 baselineOnly keep the change if it improves F1 on the weakest class without degrading others

**DELIVERABLE**Error analysis report. At least one targeted fix applied and validated. Updated test metrics.

Day 13 Ablation Study + Results Table EVAL ›

Goal: Quantify contribution of each feature group — proves the engineering choices were justified

- Run 3 ablation variants — train GCN with each feature group removed: Variant A: opcode features only (50-dim) Variant B: API features only (80-dim) Variant C: structural features only (5-dim) Variant D: full 135-dim (baseline)
- Train each variant for 50 epochs (fast runs), record val F1 macroEach run takes \~10–20 min on your CPU. Can run sequentially.
- Produce results table: rows = feature set, columns = per-class F1 + macro F1. Save as `results/ablation_table.csv`
- Write `results/README.md` summarizing: dataset stats, model architectures, key results, ablation findings, limitationsThis becomes your GitHub repo README — write it clearly enough for someone unfamiliar with the project

**DELIVERABLE**Ablation results table. Project README.md completed.

Day 14 Cleanup, Documentation & Final Commit EVAL ›

Goal: Production-clean repo, reproducible from scratch, ready to put on CV

- Write `src/run_pipeline.py` — end-to-end script that takes a directory of PE binaries and runs: CAPA labeling → CFG extraction → feature engineering → inference with saved model → outputs a JSON report of malicious functions foundThis is the demo script — makes the project feel like a real tool, not just training code
- Clean up all notebooks — add markdown cells explaining each step, re-run all cells to confirm clean executionTarget: `01_cfg_inspection.ipynb`, `02_feature_validation.ipynb`, `03_results_visualization.ipynb`
- Write `requirements.txt` with pinned versions (`pip freeze > requirements.txt`) and a setup section in READMETest: create a fresh venv, install from requirements.txt, run `run_pipeline.py` on one sample
- Finalize GitHub repo: add `results/figures/` to repo, write a one-paragraph project description for the repo About section, add topics: `malware-analysis`, `graph-neural-networks`, `cybersecurity`, `pytorch-geometric`
- Tag final commit `v1.0` and pushVerify all paths in README are correct relative to repo root

**DELIVERABLE**Clean, documented, reproducible GitHub repo. End-to-end inference script working. `v1.0` tag pushed.
