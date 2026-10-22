#!/usr/bin/env python3
"""Evaluate a saved Stage 2 checkpoint on one split.

The test split is evaluated once, after model selection.  This script uses the
per-target block thresholds stored in the checkpoint (chosen on validation).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import torch

from src.models.gcn import FunctionGCNWithNodeHead, GraphCorpus, set_standardizer
from src.train.stage1 import DEFAULT_CORPUS, SPLITS, _split_graph_ids
from src.train.stage2 import (
    _block_metrics, _filter_positive_graphs, predict_blocks,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", type=Path,
                        default=Path("results/train/stage2/best.pt"))
    parser.add_argument("--corpus-dir", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--splits", type=Path, default=SPLITS)
    parser.add_argument("--split", choices=("val", "test"), default="test")
    parser.add_argument("--batch-graphs", type=int, default=8)
    parser.add_argument("--out-dir", type=Path)
    args = parser.parse_args(argv)

    checkpoint = torch.load(
        args.checkpoint, map_location="cpu", weights_only=False
    )
    model_cfg = checkpoint["model"]
    corpus = GraphCorpus(
        args.corpus_dir / "graph_meta.npz",
        args.corpus_dir / "block_feats.npy",
    )
    assignments = json.loads(args.splits.read_text())["assignments"]
    ids = _split_graph_ids(corpus, assignments)
    ids = {k: _filter_positive_graphs(corpus, v) for k, v in ids.items()}
    graph_ids = ids["val" if args.split == "val" else "test"]
    labels = [str(x) for x in corpus.label_names]

    std = checkpoint["standardizer"]
    set_standardizer(
        torch.tensor(std["mean"], dtype=torch.float32),
        torch.tensor(std["std"], dtype=torch.float32),
    )
    model = FunctionGCNWithNodeHead(
        int(model_cfg["in_dim"]),
        hidden=int(model_cfg["hidden"]),
        dropout=float(model_cfg["dropout"]),
        residual=bool(model_cfg.get("residual", True)),
        n_outputs=int(model_cfg["n_outputs"]),
    )
    model.load_state_dict(checkpoint["state_dict"])
    model.eval()

    pos_weight = torch.tensor(checkpoint["pos_weight"], dtype=torch.float32)
    prob, y, mask, fids = predict_blocks(
        model, corpus, graph_ids, batch_graphs=args.batch_graphs
    )
    metrics = _block_metrics(
        prob, y, mask, fids, labels, checkpoint["thresholds"],
        pos_weight=pos_weight,
    )
    metrics["split"] = args.split
    metrics["checkpoint"] = str(args.checkpoint)
    metrics["thresholds"] = checkpoint["thresholds"]
    metrics["best_epoch"] = checkpoint.get("best_epoch")

    out_dir = args.out_dir or args.checkpoint.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{args.split}_metrics.json"
    out.write_text(json.dumps(metrics, indent=2) + "\n")
    print(json.dumps(metrics, indent=2))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
