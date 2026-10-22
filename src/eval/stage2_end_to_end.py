#!/usr/bin/env python3
"""End-to-end Stage 1 + Stage 2 test evaluation.

Stage 1 selects functions with its validation-selected function thresholds.
Stage 2 scores every block in the selected, eligible functions with its
validation-selected block thresholds.  Blocks in Stage 1 false-positive
functions count as block false positives; blocks in missed true functions are
counted as block false negatives.  This is the deployment-shaped localisation
metric, in contrast to the oracle-function Stage 2 report.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import torch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.models.gcn import (  # noqa: E402
    FunctionGCN, FunctionGCNWithNodeHead, GraphCorpus, set_standardizer,
    symmetric_weights,
)
from src.train.stage1 import (  # noqa: E402
    DEFAULT_CORPUS, SPLITS, _split_graph_ids,
)

DEFAULT_STAGE1 = ROOT / "results" / "train" / "stage1" / "best.pt"
DEFAULT_STAGE2 = ROOT / "results" / "train" / "stage2" / "best.pt"


def _build_models(stage1_path: Path, stage2_path: Path):
    ck1 = torch.load(stage1_path, map_location="cpu", weights_only=False)
    ck2 = torch.load(stage2_path, map_location="cpu", weights_only=False)
    std1 = ck1["standardizer"]
    std2 = ck2["standardizer"]
    if not (
        np.allclose(std1["mean"], std2["mean"])
        and np.allclose(std1["std"], std2["std"])
    ):
        raise SystemExit("Stage 1 and Stage 2 standardizers differ")
    set_standardizer(
        torch.tensor(std1["mean"], dtype=torch.float32),
        torch.tensor(std1["std"], dtype=torch.float32),
    )
    m1 = FunctionGCN(
        int(ck1["model"]["in_dim"]),
        hidden=int(ck1["model"]["hidden"]),
        dropout=float(ck1["model"]["dropout"]),
        residual=bool(ck1["model"].get("residual", True)),
        n_outputs=int(ck1["model"]["n_outputs"]),
    )
    m1.load_state_dict(ck1["state_dict"])
    m1.eval()
    m2 = FunctionGCNWithNodeHead(
        int(ck2["model"]["in_dim"]),
        hidden=int(ck2["model"]["hidden"]),
        dropout=float(ck2["model"]["dropout"]),
        residual=bool(ck2["model"].get("residual", True)),
        n_outputs=int(ck2["model"]["n_outputs"]),
    )
    m2.load_state_dict(ck2["state_dict"])
    m2.eval()
    return m1, m2, ck1, ck2


def _prf(tp: int, fp: int, fn: int):
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    iou = tp / (tp + fp + fn) if tp + fp + fn else 0.0
    return {
        "tp": int(tp), "fp": int(fp), "fn": int(fn),
        "precision": precision, "recall": recall, "f1": f1, "iou": iou,
    }


@torch.no_grad()
def evaluate_end_to_end(corpus: GraphCorpus, graph_ids: list[int], m1, m2,
                        ck1, ck2, labels):
    th1 = ck1["thresholds"]
    th2 = ck2["thresholds"]
    targets = {
        name: {
            "function": {"tp": 0, "fp": 0, "fn": 0},
            "block": {"tp": 0, "fp": 0, "fn": 0},
            "selected_blocks": 0,
            "true_blocks_selected": 0,
            "true_blocks_total": 0,
            "selected_functions": 0,
            "true_functions": 0,
        }
        for name in labels
    }
    for g in graph_ids:
        x, edge_index, pool, n_funcs, y, elig = corpus.build_batch([g])
        if x.size(0) == 0:
            continue
        edge_index, ew = symmetric_weights(edge_index, x.size(0))
        p1 = torch.sigmoid(m1(x, edge_index, ew, pool, n_funcs)).numpy()
        p2 = torch.sigmoid(m2.forward_nodes(x, edge_index, ew)).numpy()
        y = y.numpy()
        elig = elig.numpy().astype(bool)
        (nb0, nb1), _e, _f = corpus.graph_slices(g)
        by = corpus.block_y[nb0:nb1]
        nf = corpus.node_func[nb0:nb1].astype(np.int64)
        for c, name in enumerate(labels):
            sel_func = (p1[:, c] >= th1[c]) & elig
            true_func = elig & (y[:, c] > 0)
            d = targets[name]
            d["selected_functions"] += int(sel_func.sum())
            d["true_functions"] += int(true_func.sum())
            d["function"]["tp"] += int(np.sum(sel_func & true_func))
            d["function"]["fp"] += int(np.sum(sel_func & ~true_func))
            d["function"]["fn"] += int(np.sum(~sel_func & true_func))
            block_sel = sel_func[nf]
            true_block = by[:, c] > 0
            pred_block = p2[:, c] >= th2[c]
            d["selected_blocks"] += int(block_sel.sum())
            d["true_blocks_selected"] += int(np.sum(block_sel & true_block))
            d["true_blocks_total"] += int(true_block.sum())
            d["block"]["tp"] += int(np.sum(block_sel & pred_block & true_block))
            d["block"]["fp"] += int(np.sum(block_sel & pred_block & ~true_block))
            d["block"]["fn"] += int(np.sum(block_sel & ~pred_block & true_block))
    out = {"per_class": {}}
    for name in labels:
        d = targets[name]
        out["per_class"][name] = {
            "function": _prf(**d["function"]),
            "block": _prf(**d["block"]),
            "selected_functions": d["selected_functions"],
            "true_functions": d["true_functions"],
            "selected_blocks": d["selected_blocks"],
            "true_blocks_selected": d["true_blocks_selected"],
            "true_blocks_total": d["true_blocks_total"],
        }
    out["macro_block_f1"] = float(
        np.mean([v["block"]["f1"] for v in out["per_class"].values()])
    )
    out["macro_block_iou"] = float(
        np.mean([v["block"]["iou"] for v in out["per_class"].values()])
    )
    out["stage1_thresholds"] = th1
    out["stage2_thresholds"] = th2
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage1-checkpoint", type=Path, default=DEFAULT_STAGE1)
    parser.add_argument("--stage2-checkpoint", type=Path, default=DEFAULT_STAGE2)
    parser.add_argument("--corpus-dir", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--splits", type=Path, default=SPLITS)
    parser.add_argument("--split", choices=("val", "test"), default="test")
    parser.add_argument("--out-dir", type=Path)
    args = parser.parse_args(argv)

    corpus = GraphCorpus(
        args.corpus_dir / "graph_meta.npz",
        args.corpus_dir / "block_feats.npy",
    )
    assignments = json.loads(args.splits.read_text())["assignments"]
    ids = _split_graph_ids(corpus, assignments)
    graph_ids = ids["val" if args.split == "val" else "test"]
    m1, m2, ck1, ck2 = _build_models(
        args.stage1_checkpoint, args.stage2_checkpoint
    )
    labels = [str(x) for x in corpus.label_names]
    metrics = evaluate_end_to_end(
        corpus, graph_ids, m1, m2, ck1, ck2, labels
    )
    metrics["split"] = args.split
    metrics["stage1_checkpoint"] = str(args.stage1_checkpoint)
    metrics["stage2_checkpoint"] = str(args.stage2_checkpoint)

    out_dir = args.out_dir or args.stage2_checkpoint.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"end_to_end_{args.split}.json"
    out.write_text(json.dumps(metrics, indent=2) + "\n")
    print(json.dumps(metrics, indent=2))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
