#!/usr/bin/env python3
"""Stage 1: three-target function classification on the CFG-GCN.

Targets: ``anti_debug``, ``keylogger``, ``injection``.  A function with no
target match is the background class (not selected); it is not a benign sample.
Functions in samples with no CAPA rule at all are unlabeled and excluded from
the loss and from the metrics.

Split: the cluster-grouped three_target split (train/val/test).  Model
selection uses validation only; the test split is touched once at the end.
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
    FunctionGCN, GraphCorpus, compute_standardizer, set_standardizer,
    symmetric_weights,
)

SPLITS = ROOT / "data" / "versions" / "v2" / "splits" / "three_target.json"
DEFAULT_CORPUS = ROOT / "results" / "corpus_v2_three_targets"
DEFAULT_OUT = ROOT / "results" / "train" / "stage1"


def _split_graph_ids(corpus: GraphCorpus, assignments: dict[str, str]):
    by_sid = {sid: i for i, sid in enumerate(corpus.sample_ids)}
    out: dict[str, list[int]] = {"train": [], "val": [], "test": []}
    for sid, split in assignments.items():
        g = by_sid.get(sid)
        if g is None or split not in out:
            continue
        if corpus.function_count(g) == 0:
            continue
        out[split].append(g)
    return {k: sorted(v) for k, v in out.items()}


def _gather(corpus: GraphCorpus, graph_ids: list[int]):
    ys, elig = [], []
    for g in graph_ids:
        nf0, nf1 = int(corpus.func_off[g]), int(corpus.func_off[g + 1])
        ys.append(corpus.y[nf0:nf1])
        elig.append(corpus.eligible[nf0:nf1])
    y = np.concatenate(ys) if ys else np.zeros((0, corpus.n_outputs), np.float32)
    e = np.concatenate(elig) if elig else np.zeros(0, bool)
    return y, e


def _class_metrics(prob: np.ndarray, y: np.ndarray, mask: np.ndarray,
                   labels: list[str], threshold: float,
                   thresholds: list[float] | None = None) -> dict:
    p = prob[mask]
    t = y[mask].astype(np.int8)
    thresholds = thresholds or [threshold] * len(labels)
    per_class = {}
    for c, name in enumerate(labels):
        pc = p[:, c] >= thresholds[c]
        tc = t[:, c] == 1
        tp = int(np.sum(pc & tc))
        fp = int(np.sum(pc & ~tc))
        fn = int(np.sum(~pc & tc))
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        ap = (
            float(average_precision_score(tc, p[:, c]))
            if tc.any() else None
        )
        per_class[name] = {
            "support": int(tc.sum()),
            "predicted": int(pc.sum()),
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "average_precision": ap,
            "threshold": float(thresholds[c]),
        }

    pred_any = (p >= np.asarray(thresholds)).any(axis=1)
    true_any = (t > 0).any(axis=1)
    tp = int(np.sum(pred_any & true_any))
    fp = int(np.sum(pred_any & ~true_any))
    fn = int(np.sum(~pred_any & true_any))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    tn = int(np.sum(~pred_any & ~true_any))
    bg_precision = tn / (tn + fn) if tn + fn else 0.0
    bg_recall = tn / (tn + fp) if tn + fp else 0.0
    bg_f1 = (
        2 * bg_precision * bg_recall / (bg_precision + bg_recall)
        if bg_precision + bg_recall else 0.0
    )

    f1s = [v["f1"] for v in per_class.values() if v["support"] > 0]
    return {
        "n_eval": int(mask.sum()),
        "n_positive_any": int(true_any.sum()),
        "threshold": threshold,
        "thresholds": [float(x) for x in thresholds],
        "per_class": per_class,
        "macro_f1": float(np.mean(f1s)) if f1s else 0.0,
        "selected": {
            "precision": precision,
            "recall": recall,
            "f1": f1,
        },
        "background": {
            "support": int((~true_any).sum()),
            "precision": bg_precision,
            "recall": bg_recall,
            "f1": bg_f1,
        },
    }


@torch.no_grad()
def predict(model, corpus: GraphCorpus, graph_ids: list[int],
            *, batch_graphs: int):
    """Return ``(prob, y, eligible)`` for the supplied graphs."""
    model.eval()
    logits_all, y_all, elig_all = [], [], []
    for i in range(0, len(graph_ids), batch_graphs):
        ids = graph_ids[i:i + batch_graphs]
        x, edge_index, pool, n_funcs, y, elig = corpus.build_batch(ids)
        if x.size(0) == 0:
            continue
        edge_index, ew = symmetric_weights(edge_index, x.size(0))
        logits = model(x, edge_index, ew, pool, n_funcs)
        logits_all.append(logits)
        y_all.append(y)
        elig_all.append(elig)
    if not logits_all:
        return np.zeros((0, corpus.n_outputs), np.float32), np.zeros((0, corpus.n_outputs), np.float32), np.zeros(0, bool)
    prob = torch.sigmoid(torch.cat(logits_all)).numpy()
    return prob, torch.cat(y_all).numpy(), torch.cat(elig_all).numpy()


@torch.no_grad()
def evaluate(model, corpus: GraphCorpus, graph_ids: list[int],
             labels: list[str], *, batch_graphs: int, threshold: float = 0.5,
             pos_weight: torch.Tensor | None = None,
             thresholds: list[float] | None = None) -> dict:
    prob, y, elig = predict(
        model, corpus, graph_ids, batch_graphs=batch_graphs
    )
    if prob.shape[0] == 0:
        return {"n_eval": 0}
    out = _class_metrics(
        prob, y, elig, labels, threshold, thresholds=thresholds
    )
    out["loss"] = None
    if elig.any() and pos_weight is not None:
        # Recompute the masked loss without keeping an autograd graph.
        logits = torch.from_numpy(
            np.log(np.clip(prob, 1e-7, 1 - 1e-7) / np.clip(1 - prob, 1e-7, 1))
        )
        bce = F.binary_cross_entropy_with_logits(
            logits, torch.from_numpy(y), reduction="none",
            pos_weight=pos_weight,
        )
        e = torch.from_numpy(elig)
        out["loss"] = float((bce * e[:, None]).sum() / (e.sum() * y.shape[1]))
    return out


def tune_thresholds(prob: np.ndarray, y: np.ndarray, mask: np.ndarray,
                    labels: list[str], *, min_support: int = 10) -> list[float]:
    """Per-class F1-maximising thresholds, chosen on validation only."""
    p = prob[mask]
    t = y[mask].astype(np.int8)
    thresholds = []
    grid = np.linspace(0.05, 0.95, 91)
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


def _fmt(value) -> str:
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def render_report(report: dict) -> str:
    lines = [
        "# Stage 1 — three-target function localisation",
        "",
        f"- Corpus: `{report['corpus']}`",
        f"- Feature width: **{report['feature_width']}**",
        f"- Labels: **{', '.join(report['labels'])}**",
        f"- Split: **{report['split']}** "
        f"(train={report['n_train']}, val={report['n_val']}, test={report['n_test']} graphs)",
        f"- Best epoch: **{report['best_epoch']}**",
        "",
        "A function with no target match is the background class (not selected). "
        "It is not a benign sample; the corpus is malware-only.",
        "",
    ]
    for split in ("validation", "test"):
        m = report.get(split)
        if not m:
            continue
        lines += [
            f"## {split.title()}",
            "",
            f"- Eligible functions: **{m['n_eval']:,}**",
            f"- Functions with at least one target: **{m['n_positive_any']:,}**",
            "",
            "| label | support | threshold | precision | recall | F1 | AP |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
        for name in report["labels"]:
            c = m["per_class"][name]
            lines.append(
                f"| `{name}` | {c['support']:,} | {_fmt(c.get('threshold'))} | "
                f"{_fmt(c['precision'])} | {_fmt(c['recall'])} | "
                f"{_fmt(c['f1'])} | {_fmt(c['average_precision'])} |"
            )
        s = m["selected"]
        b = m["background"]
        lines += [
            "",
            f"- Macro F1 (targets with support): **{_fmt(m['macro_f1'])}**",
            f"- Any-target selection: P **{_fmt(s['precision'])}**, "
            f"R **{_fmt(s['recall'])}**, F1 **{_fmt(s['f1'])}**",
            f"- Background: P **{_fmt(b['precision'])}**, "
            f"R **{_fmt(b['recall'])}**, F1 **{_fmt(b['f1'])}**",
            "",
        ]
    lines += [
        "## Caveat",
        "",
        "The labels are CAPA rule matches. The label audit in `results/audit` "
        "documents that keylogger is concentrated in a few clusters and that "
        "the three names should not be read as ground-truth behaviour.",
        "",
    ]
    return "\n".join(lines)


def drop_edges(edge_index, p: float):
    if p <= 0:
        return edge_index
    keep = torch.rand(edge_index.size(1)) >= p
    return edge_index[:, keep]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train Stage 1 three-target GCN.")
    parser.add_argument("--corpus-dir", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--splits", type=Path, default=SPLITS)
    parser.add_argument("--epochs", type=int, default=30)
    parser.add_argument("--patience", type=int, default=8)
    parser.add_argument("--hidden", type=int, default=64)
    parser.add_argument("--dropout", type=float, default=0.2)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--weight-decay", type=float, default=1e-4)
    parser.add_argument("--batch-graphs", type=int, default=8)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--edge-dropout", type=float, default=0.10)
    parser.add_argument("--feature-dropout", type=float, default=0.05)
    parser.add_argument("--pos-weight-cap", type=float, default=300.0)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--threads", type=int, default=min(8, os.cpu_count() or 1))
    parser.add_argument("--limit-train", type=int, help="smoke test only")
    parser.add_argument("--limit-val", type=int, help="smoke test only")
    parser.add_argument("--no-test", action="store_true")
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
    if corpus.n_outputs != len(LABEL_NAMES):
        raise SystemExit(f"corpus has {corpus.n_outputs} labels, expected {len(LABEL_NAMES)}")
    labels = [str(x) for x in corpus.label_names]
    assignments = json.loads(args.splits.read_text())["assignments"]
    ids = _split_graph_ids(corpus, assignments)
    if args.limit_train:
        ids["train"] = ids["train"][: args.limit_train]
    if args.limit_val:
        ids["val"] = ids["val"][: args.limit_val]
    if not ids["train"] or not ids["val"]:
        raise SystemExit("empty train or validation split")

    print(
        f"graphs: train={len(ids['train'])} val={len(ids['val'])} "
        f"test={len(ids['test'])}; labels={labels}",
        flush=True,
    )

    mean, std = compute_standardizer(corpus, ids["train"])
    set_standardizer(mean, std)

    y_tr, e_tr = _gather(corpus, ids["train"])
    pos = y_tr[e_tr].sum(axis=0)
    neg = (1.0 - y_tr[e_tr]).sum(axis=0)
    pw_np = np.clip(neg / np.maximum(pos, 1.0), 1.0, args.pos_weight_cap)
    pos_weight = torch.from_numpy(pw_np.astype(np.float32))
    print(
        "train eligible=%d positives=%s pos_weight=%s"
        % (
            int(e_tr.sum()),
            {labels[i]: int(pos[i]) for i in range(len(labels))},
            np.round(pw_np, 2).tolist(),
        ),
        flush=True,
    )

    model = FunctionGCN(
        N_FEAT, hidden=args.hidden, dropout=args.dropout,
        n_outputs=len(labels),
    )
    optim = torch.optim.Adam(
        model.parameters(), lr=args.lr, weight_decay=args.weight_decay
    )

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
            batch_ids = order[i:i + args.batch_graphs]
            x, edge_index, pool, n_funcs, y, elig = corpus.build_batch(list(batch_ids))
            if x.size(0) == 0 or not elig.any():
                continue
            x = F.dropout(x, p=args.feature_dropout, training=True)
            edge_index = drop_edges(edge_index, args.edge_dropout)
            edge_index, ew = symmetric_weights(edge_index, x.size(0))
            logits = model(x, edge_index, ew, pool, n_funcs)
            bce = F.binary_cross_entropy_with_logits(
                logits, y, reduction="none", pos_weight=pos_weight
            )
            loss = (bce * elig[:, None]).sum() / (elig.sum() * y.size(1))
            optim.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 5.0)
            optim.step()
            total_loss += float(loss.detach())
            n_batches += 1

        val_default_epoch = evaluate(
            model, corpus, ids["val"], labels,
            batch_graphs=args.batch_graphs, threshold=0.5,
            pos_weight=pos_weight,
        )
        val_prob, val_y, val_elig = predict(
            model, corpus, ids["val"], batch_graphs=args.batch_graphs
        )
        val_thresholds = tune_thresholds(val_prob, val_y, val_elig, labels)
        val = _class_metrics(
            val_prob, val_y, val_elig, labels, 0.5,
            thresholds=val_thresholds,
        )
        val["loss"] = val_default_epoch.get("loss")
        entry = {
            "epoch": epoch,
            "train_loss": total_loss / max(n_batches, 1),
            "val_loss": val.get("loss"),
            "val_macro_f1": val.get("macro_f1"),
            "val_macro_f1_at_0.5": val_default_epoch.get("macro_f1"),
            "val_thresholds": val_thresholds,
            "val_per_class": val.get("per_class"),
            "elapsed_seconds": round(time.time() - t0, 1),
        }
        history.append(entry)
        per_class = " ".join(
            f"{name}={_fmt(v['f1'])}"
            for name, v in (entry["val_per_class"] or {}).items()
        )
        print(
            f"epoch {epoch:02d} train_loss={entry['train_loss']:.4f} "
            f"val_loss={_fmt(entry['val_loss'])} "
            f"val_macro_f1={_fmt(entry['val_macro_f1'])} "
            f"(0.5={_fmt(entry['val_macro_f1_at_0.5'])}) "
            f"[{per_class}] ({entry['elapsed_seconds']}s)",
            flush=True,
        )

        score = float(val.get("macro_f1") or 0.0)
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

    val_prob, val_y, val_elig = predict(
        model, corpus, ids["val"], batch_graphs=args.batch_graphs
    )
    thresholds = best_thresholds or tune_thresholds(
        val_prob, val_y, val_elig, labels
    )
    val = evaluate(
        model, corpus, ids["val"], labels,
        batch_graphs=args.batch_graphs, threshold=args.threshold,
        pos_weight=pos_weight, thresholds=thresholds,
    )
    val_default = evaluate(
        model, corpus, ids["val"], labels,
        batch_graphs=args.batch_graphs, threshold=0.5,
        pos_weight=pos_weight, thresholds=[0.5] * len(labels),
    )
    test = None
    if ids["test"] and not args.no_test:
        test = evaluate(
            model, corpus, ids["test"], labels,
            batch_graphs=args.batch_graphs, threshold=args.threshold,
            pos_weight=pos_weight, thresholds=thresholds,
        )

    checkpoint = {
        "format": "cfg-gnn.function.v2",
        "model": {
            "in_dim": N_FEAT,
            "hidden": args.hidden,
            "dropout": args.dropout,
            "residual": True,
            "n_outputs": len(labels),
        },
        "standardizer": {
            "mean": mean.tolist(),
            "std": std.tolist(),
        },
        "state_dict": model.state_dict(),
        "labels": labels,
        "best_epoch": best_epoch,
        "feature_spec": spec,
        "split": "three-target-v3",
        "epochs": args.epochs,
        "threshold": args.threshold,
        "thresholds": thresholds,
        "pos_weight": pos_weight.tolist(),
        "metrics": {"validation": val, "validation_at_0.5": val_default, "test": test},
    }
    torch.save(checkpoint, args.out_dir / "best.pt")

    report = {
        "corpus": str(args.corpus_dir),
        "feature_width": N_FEAT,
        "labels": labels,
        "best_epoch": best_epoch,
        "split": "three-target-v3",
        "n_train": len(ids["train"]),
        "n_val": len(ids["val"]),
        "n_test": len(ids["test"]),
        "validation": val,
        "validation_at_0.5": val_default,
        "test": test,
        "thresholds": thresholds,
        "pos_weight": pos_weight.tolist(),
        "history": history,
        "elapsed_seconds": round(time.time() - t0, 1),
    }
    (args.out_dir / "metrics.json").write_text(json.dumps(report, indent=2) + "\n")
    (args.out_dir / "report.md").write_text(render_report(report))
    print(f"wrote {args.out_dir / 'best.pt'} and {args.out_dir / 'report.md'}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
