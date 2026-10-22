#!/usr/bin/env python3
"""Stage 2: intra-function block localisation for the three targets.

The Stage 1 trunk is seeded from ``results/train/stage1/best.pt``.  By default
the trunk is frozen and only the per-block head is trained, which keeps the
function classifier fixed and makes the localisation result a direct test of
the Stage 1 representation.

Training data are blocks inside functions that are positive for at least one
target.  A block is positive for a target when it contains CAPA evidence or an
import-resolved API reference (the same seed used to build the labels).  All
other blocks in those functions are negative blocks (mask=1); blocks in
weak-negative/unlabeled functions are excluded (mask=0).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F
from sklearn.metrics import average_precision_score

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.features.block_features import LABEL_NAMES, N_FEAT  # noqa: E402
from src.models.gcn import (  # noqa: E402
    FunctionGCNWithNodeHead, GraphCorpus, set_standardizer,
    symmetric_weights,
)
from src.train.stage1 import (  # noqa: E402
    DEFAULT_CORPUS, SPLITS, _fmt, _split_graph_ids, drop_edges,
)

DEFAULT_STAGE1 = ROOT / "results" / "train" / "stage1" / "best.pt"
DEFAULT_OUT = ROOT / "results" / "train" / "stage2"


def _block_slices(corpus: GraphCorpus, graph_ids: list[int]):
    by, bm, fids = [], [], []
    func_base = 0
    any_mask = False
    for g in graph_ids:
        (nb0, nb1), _e, (nf0, nf1) = corpus.graph_slices(g)
        by.append(corpus.block_y[nb0:nb1])
        b = corpus.block_mask[nb0:nb1]
        bm.append(b)
        if b.any():
            any_mask = True
        fids.append(corpus.node_func[nb0:nb1].astype(np.int64) + func_base)
        func_base += nf1 - nf0
    if not by:
        return (
            np.zeros((0, corpus.n_outputs), np.uint8),
            np.zeros(0, np.uint8),
            np.zeros(0, np.int64),
        )
    return np.concatenate(by), np.concatenate(bm), np.concatenate(fids)


def _filter_positive_graphs(corpus: GraphCorpus, graph_ids: list[int]):
    out = []
    for g in graph_ids:
        (nb0, nb1), _e, _f = corpus.graph_slices(g)
        if corpus.block_mask is not None and bool(corpus.block_mask[nb0:nb1].any()):
            out.append(g)
    return out


@torch.no_grad()
def predict_blocks(model, corpus: GraphCorpus, graph_ids: list[int], *,
                   batch_graphs: int):
    model.eval()
    probs, ys, masks, fids = [], [], [], []
    for i in range(0, len(graph_ids), batch_graphs):
        ids = graph_ids[i:i + batch_graphs]
        x, edge_index, _pool, _n_funcs, _y, _elig = corpus.build_batch(ids)
        if x.size(0) == 0:
            continue
        by, bm, f = _block_slices(corpus, ids)
        edge_index, ew = symmetric_weights(edge_index, x.size(0))
        logits = model.forward_nodes(x, edge_index, ew)
        probs.append(torch.sigmoid(logits).numpy())
        ys.append(by)
        masks.append(bm)
        fids.append(f)
    if not probs:
        return (
            np.zeros((0, corpus.n_outputs), np.float32),
            np.zeros((0, corpus.n_outputs), np.uint8),
            np.zeros(0, np.uint8),
            np.zeros(0, np.int64),
        )
    return (
        np.concatenate(probs), np.concatenate(ys),
        np.concatenate(masks), np.concatenate(fids),
    )


def _block_loss(logits, y, mask, pos_weight):
    bce = F.binary_cross_entropy_with_logits(
        logits, y, reduction="none", pos_weight=pos_weight
    )
    return (bce * mask[:, None]).sum() / (mask.sum() * y.size(1)).clamp(min=1)


def _tune_block_thresholds(prob, y, mask, labels, *, min_support=10):
    mask = np.asarray(mask, dtype=bool)
    p = prob[mask]
    t = y[mask].astype(np.int8)
    grid = np.linspace(0.05, 0.95, 91)
    thresholds = []
    for c, _name in enumerate(labels):
        support = int(t[:, c].sum())
        if support < min_support:
            thresholds.append(0.5)
            continue
        best_t, best_f1 = 0.5, -1.0
        for value in grid:
            pred = p[:, c] >= value
            tp = int(np.sum(pred & (t[:, c] == 1)))
            fp = int(np.sum(pred & (t[:, c] == 0)))
            fn = int(np.sum(~pred & (t[:, c] == 1)))
            precision = tp / (tp + fp) if tp + fp else 0.0
            recall = tp / (tp + fn) if tp + fn else 0.0
            f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
            if f1 > best_f1 + 1e-12:
                best_f1, best_t = f1, float(value)
        thresholds.append(best_t)
    return thresholds


def _block_metrics(prob, y, mask, fids, labels, thresholds, *,
                   pos_weight=None) -> dict:
    mask = np.asarray(mask, dtype=bool)
    p = prob[mask]
    t = y[mask].astype(np.int8)
    f = fids[mask]
    per_class = {}
    for c, name in enumerate(labels):
        pred = p[:, c] >= thresholds[c]
        true = t[:, c] == 1
        tp = int(np.sum(pred & true))
        fp = int(np.sum(pred & ~true))
        fn = int(np.sum(~pred & true))
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        iou = tp / (tp + fp + fn) if tp + fp + fn else 0.0
        ap = (
            float(average_precision_score(true, p[:, c]))
            if true.any() else None
        )
        true_funcs = np.unique(f[true])
        pred_funcs = np.unique(f[pred])
        hit = (
            len(np.intersect1d(true_funcs, pred_funcs)) / len(true_funcs)
            if len(true_funcs) else 0.0
        )
        per_class[name] = {
            "support_blocks": int(true.sum()),
            "predicted_blocks": int(pred.sum()),
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "iou": iou,
            "average_precision": ap,
            "threshold": float(thresholds[c]),
            "support_functions": int(len(true_funcs)),
            "function_hit_rate": hit,
        }
    out = {
        "n_blocks": int(mask.sum()),
        "per_class": per_class,
        "macro_f1": float(np.mean([v["f1"] for v in per_class.values()])),
        "macro_iou": float(np.mean([v["iou"] for v in per_class.values()])),
        "macro_function_hit_rate": float(
            np.mean([v["function_hit_rate"] for v in per_class.values()])
        ),
    }
    if pos_weight is not None and int(mask.sum()) > 0:
        logits = torch.from_numpy(
            np.log(np.clip(p, 1e-7, 1 - 1e-7) / np.clip(1 - p, 1e-7, 1))
        )
        bce = F.binary_cross_entropy_with_logits(
            logits, torch.from_numpy(t.astype(np.float32)),
            reduction="none", pos_weight=pos_weight,
        )
        out["loss"] = float(bce.mean())
    return out


def render_report(report: dict) -> str:
    lines = [
        "# Stage 2 — intra-function block localisation",
        "",
        f"- Corpus: `{report['corpus']}`",
        f"- Stage 1 checkpoint: `{report['stage1_checkpoint']}`",
        f"- Trunk frozen: **{report['freeze_trunk']}**",
        f"- Split: **{report['split']}** "
        f"(train={report['n_train']}, val={report['n_val']}, test={report['n_test']} graphs)",
        f"- Best epoch: **{report['best_epoch']}**",
        "",
        "A block is positive for a target when it contains CAPA evidence or an",
        "import-resolved API reference inside a function positive for that target.",
        "Blocks in weak-negative or unlabeled functions are excluded.",
        "",
    ]
    for split_name, key in (("Test", "test"), ("Validation", "validation")):
        m = report.get(key)
        if not m or not m.get("per_class"):
            continue
        lines += [
            f"## {split_name}",
            "",
            f"- Masked blocks: **{m['n_blocks']:,}**",
            "",
            "| label | support blocks | support funcs | threshold | precision | recall | F1 | IoU | AP | function hit |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
        for name, c in m["per_class"].items():
            lines.append(
                f"| `{name}` | {c['support_blocks']:,} | {c['support_functions']:,} | "
                f"{c['threshold']:.2f} | {_fmt(c['precision'])} | {_fmt(c['recall'])} | "
                f"**{_fmt(c['f1'])}** | {_fmt(c['iou'])} | "
                f"{_fmt(c['average_precision'])} | {_fmt(c['function_hit_rate'])} |"
            )
        lines += [
            "",
            f"- Macro block F1: **{_fmt(m['macro_f1'])}**",
            f"- Macro block IoU: **{_fmt(m['macro_iou'])}**",
            f"- Macro function hit rate: **{_fmt(m['macro_function_hit_rate'])}**",
            "",
        ]
    lines += [
        "## Caveat",
        "",
        "The block labels are weak supervision. Keylogger and injection positives",
        "are dominated by API-reference seeds; anti-debug positives are dominated by",
        "explicit instruction evidence. The metrics measure recovery of those seeds",
        "inside flagged functions, not every malicious block. The test split is",
        "cluster-grouped and was evaluated once with validation-selected thresholds.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train Stage 2 block localiser.")
    parser.add_argument("--corpus-dir", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--splits", type=Path, default=SPLITS)
    parser.add_argument("--stage1-checkpoint", type=Path, default=DEFAULT_STAGE1)
    parser.add_argument("--epochs", type=int, default=15)
    parser.add_argument("--patience", type=int, default=4)
    parser.add_argument("--hidden", type=int, default=64)
    parser.add_argument("--dropout", type=float, default=0.3)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--weight-decay", type=float, default=1e-4)
    parser.add_argument("--batch-graphs", type=int, default=8)
    parser.add_argument("--edge-dropout", type=float, default=0.10)
    parser.add_argument("--feature-dropout", type=float, default=0.05)
    parser.add_argument("--pos-weight-cap", type=float, default=50.0)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--threads", type=int, default=min(8, os.cpu_count() or 1))
    parser.add_argument("--limit-train", type=int, help="smoke test only")
    parser.add_argument("--limit-val", type=int, help="smoke test only")
    parser.add_argument("--no-test", action="store_true")
    parser.add_argument("--fine-tune-trunk", action="store_true")
    args = parser.parse_args(argv)

    torch.manual_seed(args.seed)
    np.random.seed(args.seed)
    torch.set_num_threads(args.threads)
    args.out_dir.mkdir(parents=True, exist_ok=True)

    spec = json.loads((args.corpus_dir / "feature_spec.json").read_text())
    if spec["n_features"] != N_FEAT:
        raise SystemExit(
            f"feature width mismatch: spec {spec['n_features']} vs code {N_FEAT}"
        )

    corpus = GraphCorpus(
        args.corpus_dir / "graph_meta.npz",
        args.corpus_dir / "block_feats.npy",
    )
    if corpus.block_y is None or corpus.block_mask is None:
        raise SystemExit(
            "block_labels.npy/block_mask.npy missing; run "
            "`python -m src.data.build_block_labels` first"
        )
    labels = [str(x) for x in corpus.label_names]
    assignments = json.loads(args.splits.read_text())["assignments"]
    ids = _split_graph_ids(corpus, assignments)
    ids = {k: _filter_positive_graphs(corpus, v) for k, v in ids.items()}
    if args.limit_train:
        ids["train"] = ids["train"][: args.limit_train]
    if args.limit_val:
        ids["val"] = ids["val"][: args.limit_val]
    if not ids["train"] or not ids["val"]:
        raise SystemExit("empty train or validation split")

    print(
        f"graphs with localisation labels: train={len(ids['train'])} "
        f"val={len(ids['val'])} test={len(ids['test'])}; labels={labels}",
        flush=True,
    )
    stage1 = torch.load(args.stage1_checkpoint, map_location="cpu", weights_only=False)
    std = stage1["standardizer"]
    set_standardizer(
        torch.tensor(std["mean"], dtype=torch.float32),
        torch.tensor(std["std"], dtype=torch.float32),
    )

    by_tr, bm_tr, _f_tr = _block_slices(corpus, ids["train"])
    pos = by_tr[bm_tr.astype(bool)].sum(axis=0)
    neg = (1 - by_tr[bm_tr.astype(bool)]).sum(axis=0)
    pw_np = np.clip(neg / np.maximum(pos, 1.0), 1.0, args.pos_weight_cap)
    pos_weight = torch.from_numpy(pw_np.astype(np.float32))
    print(
        "train masked blocks=%d positives=%s pos_weight=%s"
        % (
            int(bm_tr.sum()),
            {labels[i]: int(pos[i]) for i in range(len(labels))},
            np.round(pw_np, 2).tolist(),
        ),
        flush=True,
    )

    model_cfg = stage1["model"]
    if int(args.hidden) != int(model_cfg["hidden"]):
        raise SystemExit(
            "Stage 2 hidden width must match the Stage 1 trunk: "
            f"{args.hidden} vs {model_cfg['hidden']}"
        )
    model = FunctionGCNWithNodeHead(
        int(model_cfg["in_dim"]),
        hidden=int(model_cfg["hidden"]),
        dropout=float(args.dropout),
        residual=bool(model_cfg.get("residual", True)),
        n_outputs=int(model_cfg["n_outputs"]),
    )
    missing, unexpected = model.load_state_dict(stage1["state_dict"], strict=False)
    print(f"stage1 load: missing={list(missing)} unexpected={list(unexpected)}", flush=True)
    if not args.fine_tune_trunk:
        for module in (model.w1, model.w2, model.w_skip):
            if module is not None:
                for p in module.parameters():
                    p.requires_grad = False
    params = [p for p in model.parameters() if p.requires_grad]
    optim = torch.optim.Adam(params, lr=args.lr, weight_decay=args.weight_decay)

    best_f1 = -1.0
    best_epoch = -1
    best_state = None
    best_thresholds = None
    stale = 0
    history = []
    t0 = time.time()

    for epoch in range(1, args.epochs + 1):
        model.train()
        order = np.random.permutation(ids["train"])
        total_loss = 0.0
        n_batches = 0
        for i in range(0, len(order), args.batch_graphs):
            batch_ids = list(order[i:i + args.batch_graphs])
            x, edge_index, _pool, _n_funcs, _y, _elig = corpus.build_batch(batch_ids)
            if x.size(0) == 0:
                continue
            by, bm, _f = _block_slices(corpus, batch_ids)
            if bm.sum() == 0:
                continue
            x = F.dropout(x, p=args.feature_dropout, training=True)
            edge_index = drop_edges(edge_index, args.edge_dropout)
            edge_index, ew = symmetric_weights(edge_index, x.size(0))
            logits = model.forward_nodes(x, edge_index, ew)
            y_t = torch.from_numpy(by.astype(np.float32))
            m_t = torch.from_numpy(bm.astype(np.float32))
            loss = _block_loss(logits, y_t, m_t, pos_weight)
            optim.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(params, 5.0)
            optim.step()
            total_loss += float(loss.detach())
            n_batches += 1

        vp, vy, vm, vf = predict_blocks(
            model, corpus, ids["val"], batch_graphs=args.batch_graphs
        )
        val_thresholds = _tune_block_thresholds(vp, vy, vm, labels)
        val = _block_metrics(
            vp, vy, vm, vf, labels, val_thresholds, pos_weight=pos_weight
        )
        entry = {
            "epoch": epoch,
            "train_loss": total_loss / max(n_batches, 1),
            "val_loss": val.get("loss"),
            "val_macro_f1": val["macro_f1"],
            "val_macro_iou": val["macro_iou"],
            "val_thresholds": val_thresholds,
            "val_per_class": val["per_class"],
            "elapsed_seconds": round(time.time() - t0, 1),
        }
        history.append(entry)
        per_class = " ".join(
            f"{name}={_fmt(v['f1'])}/{_fmt(v['iou'])}"
            for name, v in val["per_class"].items()
        )
        print(
            f"epoch {epoch:02d} train_loss={entry['train_loss']:.4f} "
            f"val_loss={_fmt(entry['val_loss'])} "
            f"val_macro_f1={_fmt(entry['val_macro_f1'])} "
            f"val_macro_iou={_fmt(entry['val_macro_iou'])} [{per_class}] "
            f"({entry['elapsed_seconds']}s)",
            flush=True,
        )

        score = float(val["macro_f1"])
        if score > best_f1 + 1e-4:
            best_f1 = score
            best_epoch = epoch
            best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
            best_thresholds = val_thresholds
            stale = 0
        else:
            stale += 1
            if stale >= args.patience:
                print(f"early stop at epoch {epoch} (patience {args.patience})", flush=True)
                break

    if best_state is not None:
        model.load_state_dict(best_state)

    vp, vy, vm, vf = predict_blocks(
        model, corpus, ids["val"], batch_graphs=args.batch_graphs
    )
    thresholds = best_thresholds or _tune_block_thresholds(vp, vy, vm, labels)
    val = _block_metrics(
        vp, vy, vm, vf, labels, thresholds,
        pos_weight=pos_weight,
    )
    test = None
    if ids["test"] and not args.no_test:
        tp, ty, tm, tf = predict_blocks(
            model, corpus, ids["test"], batch_graphs=args.batch_graphs
        )
        test = _block_metrics(
            tp, ty, tm, tf, labels, thresholds,
            pos_weight=pos_weight,
        )

    checkpoint = {
        "format": "cfg-gnn.stage2.v1",
        "model": {
            "in_dim": N_FEAT,
            "hidden": args.hidden,
            "dropout": args.dropout,
            "residual": True,
            "n_outputs": len(labels),
        },
        "standardizer": std,
        "state_dict": model.state_dict(),
        "labels": labels,
        "best_epoch": best_epoch,
        "feature_spec": spec,
        "split": "three-target-v3",
        "epochs": args.epochs,
        "thresholds": thresholds,
        "pos_weight": pos_weight.tolist(),
        "freeze_trunk": not args.fine_tune_trunk,
        "stage1_checkpoint": str(args.stage1_checkpoint),
        "metrics": {"validation": val, "test": test},
    }
    torch.save(checkpoint, args.out_dir / "best.pt")

    report = {
        "corpus": str(args.corpus_dir),
        "stage1_checkpoint": str(args.stage1_checkpoint),
        "feature_width": N_FEAT,
        "labels": labels,
        "freeze_trunk": not args.fine_tune_trunk,
        "split": "three-target-v3",
        "n_train": len(ids["train"]),
        "n_val": len(ids["val"]),
        "n_test": len(ids["test"]),
        "best_epoch": best_epoch,
        "validation": val,
        "test": test,
        "thresholds": thresholds,
        "pos_weight": pos_weight.tolist(),
        "history": history,
        "elapsed_seconds": round(time.time() - t0, 1),
    }
    (args.out_dir / "metrics.json").write_text(json.dumps(report, indent=2) + "\n")
    (args.out_dir / "report.md").write_text(render_report(report))
    print(render_report(report))
    print(f"wrote {args.out_dir / 'best.pt'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
