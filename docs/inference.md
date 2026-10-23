# Single-binary inference

`src/infer/run.py` runs the frozen three-target models on one x86 PE and writes
a machine-readable JSON report plus a per-sample PDF report. It is a consumer of
the training contract, not a second feature implementation: the same
`graph_arrays()` / import-resolution code builds the 187-dimensional block
features, and the same `FunctionGCN` / `FunctionGCNWithNodeHead` classes run the
forward pass.

## Scope

- Input: a 32-bit x86 PE (PE32, machine `0x14c`).
- Labels: `anti_debug`, `keylogger`, `injection`. A function may match more than
  one; “not selected” is not a benign verdict.
- Output: function scores, Stage 1 flags, block addresses/scores inside flagged
  functions, and a per-sample PDF report. Both outputs are always written under
  `workspace/<sha256>/`.
- The models use CFG, opcode, and API-reference features only. CAPA is not
  needed at inference time.

The CLI rejects known non-x86 machines and PE32+ inputs before extraction. A
header with machine `0` is allowed through with a warning because the extraction
worker can repair it; the extracted architecture is checked afterwards. Packed
or malformed samples that angr cannot recover produce an explicit extraction
failure (exit code 2), not a zero score.

## Commands

Full extraction and scoring:

```bash
./venv/bin/python -m src.infer.run \
  --binary data/raw/antidebug/<sample_id>.exe
```

This writes:

```text
workspace/<sha256>/report.json
workspace/<sha256>/report.pdf
```

The PDF opens automatically. Score an already-extracted graph (still reads the
PE for import resolution):

```bash
./venv/bin/python -m src.infer.run \
  --binary data/raw/antidebug/<sample_id>.exe \
  --graph data/graphs_v2/cfg/<sample_id>.npz
```

Function scores only (the PDF still opens and shows the function-level result):

```bash
./venv/bin/python -m src.infer.run \
  --binary sample.exe --no-stage2
```

Useful flags:

| flag | meaning |
|---|---|
| `--stage1 PATH` | Stage 1 checkpoint, default `results/train/stage1/best.pt` |
| `--stage2 PATH` | Stage 2 checkpoint, default `results/train/stage2/best.pt` |
| `--no-stage2` | do not load Stage 2; no block localisation |
| `--graph PATH` | skip angr; use an existing `.npz` graph |
| `--keep-graph PATH` | copy the extracted graph for debugging |
| `--workspace PATH` | output root, default `workspace` |
| `--timeout SEC` | angr timeout, default 1800 |
| `--rss-limit-gb N` | extraction RSS watchdog, default 3.0 GiB |
| `--threads N` | PyTorch CPU threads |
| `--all-functions` | include unselected function scores in JSON |
| `--max-blocks-per-function N` | display cap per function; `0` = unlimited |
| `--quiet` | write JSON without printing the text summary |
| `--debug` | show a traceback for unexpected errors |

## Output contract

Every run writes both files under a folder named after the input file's
SHA-256:

```text
workspace/<sha256>/report.json
workspace/<sha256>/report.pdf
```

The PDF is a human-readable rendering of the same JSON; the JSON remains the
machine-readable source of truth. The PDF is always generated and opened. If a
desktop viewer is unavailable, the PDF is still written.

The JSON has `schema_version` `cfg-gnn.infer.v1`. Top-level fields:

```json
{
  "schema_version": "cfg-gnn.infer.v1",
  "generated_at": "2026-10-22T...",
  "sample": {
    "path": "...", "sha256": "...", "size_bytes": 71168,
    "arch": "X86", "base_address": 268435456,
    "base_address_hex": "0x10000000",
    "functions": 116, "blocks": 1912, "edges": 1674
  },
  "models": {
    "stage1_checkpoint": "...", "stage2_checkpoint": "...",
    "labels": ["anti_debug", "keylogger", "injection"],
    "stage1_thresholds": [0.95, 0.94, 0.95],
    "stage2_thresholds": [0.94, 0.50, 0.64],
    "stage2_enabled": true
  },
  "extraction": {
    "used_pre_extracted_graph": false,
    "elapsed_seconds": 8.4, "peak_mb": 312.0,
    "summary": {"arch": "X86", "function_count": 116, "block_count": 1912}
  },
  "api": {"loaded": true, "imports": 119, "thunks": 388},
  "summary": {"anti_debug": true, "keylogger": false, "injection": true},
  "targets": {
    "anti_debug": {
      "present": true,
      "max_function_score": 0.9989,
      "n_functions": 116,
      "n_flagged_functions": 1,
      "stage1_threshold": 0.95,
      "stage2_threshold": 0.94,
      "functions": [
        {
          "func_va": 268451360,
          "func_rva": "0x3e20",
          "score": 0.9989,
          "selected": true,
          "max_block_score": 0.8085,
          "blocks": []
        }
      ]
    }
  },
  "warnings": ["..."]
}
```

Only functions selected by Stage 1 receive block localization. Every selected
function entry includes:

- `func_va` and `func_rva` (hex string);
- Stage 1 `score` and `selected`;
- `max_block_score` for the target, even when no block crosses the Stage 2
  threshold;
- `blocks`, sorted by Stage 2 score, each with `block_va`, `block_rva` (hex),
  `size`, and `score`.

`--all-functions` adds unselected function entries (with empty block lists).
`max_block_score` should be read together with `stage2_threshold`; a selected
function with a high function score but no blocks above threshold has no
localized evidence at that threshold.

The PDF contains the three target cards, run metadata, selected-function tables,
all localized blocks, and warnings. It deliberately lists only Stage 1 selected
functions even when the JSON uses `--all-functions`; the JSON is the complete
record. The HTML is rendered internally to a temporary file and is not kept.

The JSON is written atomically. Text output is a human-readable rendering of the
same data. If PDF rendering fails, the JSON is already on disk and the process
exits with code 2 with an explicit error.

## Feature parity

`build_features()` calls the corpus feature builder directly, and
`predict_graph()` calls the training model classes directly. A parity test on a
held-out sample compares:

- all 36,649 block feature rows, addresses, function membership, and edges with
  the corpus slice (exact equality);
- Stage 1 and Stage 2 probabilities against a batch containing that one graph
  (maximum absolute difference 0.0);
- a freshly extracted graph against the stored corpus graph (exact equality).

The test is in `tests/test_infer.py` and skips when the corpus or checkpoints
are absent. A separate three-sample held-out smoke check compares selected
function sets against the corpus batch path and records the result in
`results/infer/inference_validation.json`.

## Thresholds and interpretation

The Stage 1 thresholds are validation-selected and stored in the checkpoint:
`anti_debug 0.95`, `keylogger 0.94`, `injection 0.95`. Stage 2 thresholds are
`anti_debug 0.94`, `keylogger 0.50`, `injection 0.64`.

The anti-debug Stage 2 threshold is conservative. It was selected on only 27
validation functions and has low test recall (0.0588 oracle, 0.1081 end-to-end).
A binary can therefore be flagged `anti_debug` while no block crosses that
threshold; the function-level score is still the model's ranking, but the block
list is empty. This is a known limitation, not a bug in the CLI.

## Failure modes

- `binary not found`, missing checkpoint: configuration error.
- known x64/ARM machine or PE32+: rejected before extraction.
- angr timeout, crash, or no recovered functions: exit code 2 with the worker
  status/error. Packed samples are expected to fail sometimes.
- import table unavailable: API features are zero and a warning is added. The
  CFG/opcode features still run.
- no API references resolved: warning added; keylogger/injection API evidence is
  missing.
- a target threshold is not crossed: `present` is false. This is not a claim of
  benignness.

## Static decode spot-check

`scripts/spotcheck_blocks.py` decodes the highest-scoring localised blocks with
Capstone and resolves their `call dword ptr [IAT]` targets. It is an address /
instruction-boundary check and a view of the API seeds, not a manual label
verdict. The saved artifact for the demo sample is
`results/infer/block_spotcheck.json`:

```bash
./venv/bin/python scripts/spotcheck_blocks.py \
  --binary <x86.exe> \
  --report workspace/<sha256>/report.json \
  --out results/infer/block_spotcheck.json \
  --functions 5 --per-function 2
```

## Reproduction

```bash
./venv/bin/python -m pytest tests/test_infer.py -q
./venv/bin/python -m src.infer.run --binary <x86.exe>
```

The final project report is generated from the committed metrics and inference
output by `scripts/make_final_report.py`:

```bash
./venv/bin/python scripts/make_final_report.py \
  --out results/final_report.pdf \
  --html results/final_report.html \
  --open
```
