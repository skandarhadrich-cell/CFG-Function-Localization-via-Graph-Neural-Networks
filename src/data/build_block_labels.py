#!/usr/bin/env python3
"""Build block-level localisation labels aligned to the corpus block order.

A block is labelled positive for a target when it belongs to a function that is
positive for that target and either:

* it contains one of CAPA's reported evidence locations
  (``matched_block_vas``, which may be instruction addresses); or
* it contains an import-resolved API reference (the API-call seed).

Every other block in a positive function is a negative block (mask=1).  Blocks
in weak-negative or unlabeled functions are excluded (mask=0).  Functions with
no localised block at all are excluded from Stage 2 and counted in the report.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
LABELS = ROOT / "data" / "labels" / "stage1_full_three_targets.parquet"
CORPUS = ROOT / "results" / "corpus_v2_three_targets"
GRAPH_DIR = ROOT / "data" / "graphs_v2" / "cfg"
SPLITS = ROOT / "data" / "versions" / "v2" / "splits" / "three_target.json"
LABEL_NAMES = ("anti_debug", "keylogger", "injection")


def _evidence_to_blocks(
    evidence: np.ndarray, starts: np.ndarray, sizes: np.ndarray
) -> set[int]:
    if len(starts) == 0:
        return set()
    order = np.argsort(starts)
    sorted_starts = starts[order]
    sorted_sizes = sizes[order]
    out: set[int] = set()
    for address in evidence:
        pos = int(np.searchsorted(sorted_starts, int(address), side="right") - 1)
        if pos < 0:
            continue
        if sorted_starts[pos] <= address < sorted_starts[pos] + sorted_sizes[pos]:
            out.add(int(order[pos]))
    return out


def build(labels_path: Path, corpus_dir: Path) -> dict:
    frame = pd.read_parquet(labels_path)
    by_sample = {str(sid): g for sid, g in frame.groupby("sample_id", sort=False)}
    meta = np.load(corpus_dir / "graph_meta.npz", allow_pickle=True)
    feats = np.load(corpus_dir / "block_feats.npy", mmap_mode="r")
    sample_ids = [str(x) for x in meta["sample_ids"]]
    n_blocks = int(meta["node_off"][-1])
    block_y = np.zeros((n_blocks, len(LABEL_NAMES)), dtype=np.uint8)
    block_mask = np.zeros(n_blocks, dtype=np.uint8)

    split = json.loads(SPLITS.read_text())["assignments"]
    coverage = Counter()
    localized = Counter()
    api_blocks = Counter()
    split_support = {
        s: {name: {"blocks": 0, "functions": 0} for name in LABEL_NAMES}
        for s in ("train", "val", "test")
    }

    for gi, sid in enumerate(sample_ids):
        group = by_sample.get(sid)
        if group is None:
            continue
        nb0, nb1 = int(meta["node_off"][gi]), int(meta["node_off"][gi + 1])
        nf0, nf1 = int(meta["func_off"][gi]), int(meta["func_off"][gi + 1])
        graph_path = GRAPH_DIR / f"{sid}.npz"
        if not graph_path.exists():
            continue
        graph = np.load(graph_path, allow_pickle=True)
        nf = np.asarray(meta["node_func"][nb0:nb1], dtype=np.int64)
        starts = np.asarray(graph["node_block_addr"], dtype=np.int64)
        sizes = np.asarray(graph["node_block_size"], dtype=np.int64)
        if len(starts) != nb1 - nb0:
            raise RuntimeError(
                f"block order mismatch for {sid}: {len(starts)} vs {nb1 - nb0}"
            )
        fva = np.asarray(meta["func_va"][nf0:nf1], dtype=np.int64)
        has_api = np.asarray(feats[nb0:nb1, -1]) > 0
        # local function id -> label row index
        row_by_va = {
            int(r.func_va): r for r in group.itertuples(index=False)
        }
        blocks_by_func: dict[int, list[int]] = {}
        for local in range(nf1 - nf0):
            blocks_by_func[local] = np.flatnonzero(nf == local).tolist()

        sp = split.get(sid)
        for local, block_ids in blocks_by_func.items():
            va = int(fva[local])
            row = row_by_va.get(va)
            if row is None:
                continue
            labels = [
                int(getattr(row, f"label_{name}")) for name in LABEL_NAMES
            ]
            if not any(labels):
                continue
            # Find positive blocks for each target.
            positive: dict[int, set[int]] = {}
            evidence = np.asarray(row.matched_block_vas, dtype=np.int64)
            for c, name in enumerate(LABEL_NAMES):
                if not labels[c]:
                    continue
                found = _evidence_to_blocks(evidence, starts, sizes)
                positive[c] = found
                coverage[name] += 1
                if found:
                    localized[name] += 1
            # API-call seeds are added only inside positive functions.
            for c, name in enumerate(LABEL_NAMES):
                if not labels[c]:
                    continue
                api_ids = [b for b in block_ids if bool(has_api[b])]
                if api_ids:
                    positive.setdefault(c, set()).update(api_ids)
                    api_blocks[name] += len(api_ids)
            use = set().union(*positive.values()) if positive else set()
            if not use:
                continue
            for b in block_ids:
                block_mask[nb0 + b] = 1
            for c, ids in positive.items():
                for b in ids:
                    block_y[nb0 + b, c] = 1
            if sp in split_support:
                for c, name in enumerate(LABEL_NAMES):
                    if labels[c]:
                        split_support[sp][name]["functions"] += 1
                        split_support[sp][name]["blocks"] += int(
                            block_y[
                                nb0 + np.asarray(block_ids, dtype=np.int64), c
                            ].sum()
                        )

    np.save(corpus_dir / "block_labels.npy", block_y)
    np.save(corpus_dir / "block_mask.npy", block_mask)
    report = {
        "blocks": int(n_blocks),
        "masked_blocks": int(block_mask.sum()),
        "positive_blocks": {
            name: int(block_y[:, c].sum()) for c, name in enumerate(LABEL_NAMES)
        },
        "positive_functions_with_localisation": {
            name: int(localized[name]) for name in LABEL_NAMES
        },
        "positive_functions_total": {
            name: int(coverage[name]) for name in LABEL_NAMES
        },
        "api_seed_blocks": {name: int(api_blocks[name]) for name in LABEL_NAMES},
        "split_support": split_support,
    }
    (corpus_dir / "block_label_report.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--labels", type=Path, default=LABELS)
    parser.add_argument("--corpus-dir", type=Path, default=CORPUS)
    args = parser.parse_args(argv)
    report = build(args.labels, args.corpus_dir)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
