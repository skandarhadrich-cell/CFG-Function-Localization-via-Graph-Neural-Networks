#!/usr/bin/env python3
"""Minimal function-level CFG-GCN.

Data flow (one binary graph at a time, batched by block-diagonal stacking):

    block features  ->  GCN layer  ->  GCN layer  ->  per-function pool
                    (CFG edges)                     (mean || max)
                    ->  small MLP  ->  one logit per function

The CFG edges stored in ``graphs_v2`` are intraprocedural only
(``dropped_cross_edges`` records everything that was removed), so message
passing can never cross a function boundary.  Pooling is keyed on
``node_func_id``; a function pools only its own blocks.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F


def scatter_mean(src: torch.Tensor, index: torch.Tensor, n: int) -> torch.Tensor:
    out = torch.zeros(n, src.size(1), dtype=src.dtype, device=src.device)
    out.index_add_(0, index, src)
    cnt = torch.zeros(n, dtype=src.dtype, device=src.device)
    cnt.index_add_(0, index, torch.ones_like(index, dtype=src.dtype))
    return out / cnt.clamp(min=1.0).unsqueeze(1)


def scatter_max(src: torch.Tensor, index: torch.Tensor, n: int) -> torch.Tensor:
    out = torch.full((n, src.size(1)), -1e9, dtype=src.dtype, device=src.device)
    out.scatter_reduce_(0, index.unsqueeze(1).expand_as(src), src, reduce="amax", include_self=True)
    return out


class FunctionGCN(nn.Module):
    def __init__(self, in_dim: int, hidden: int = 64, dropout: float = 0.2,
                 residual: bool = True, n_outputs: int = 1):
        super().__init__()
        self.n_outputs = n_outputs
        self.w1 = nn.Linear(in_dim, hidden, bias=False)
        self.w2 = nn.Linear(hidden, hidden, bias=False)
        # Residual path: keeps node-local instruction evidence from being
        # washed out by neighbourhood averaging.  Standard GCN practice.
        self.w_skip = nn.Linear(in_dim, hidden, bias=False) if residual else None
        self.dropout = dropout
        self.head = nn.Sequential(
            nn.Linear(2 * hidden, 64),
            nn.ReLU(),
            nn.Linear(64, n_outputs),
        )

    @staticmethod
    def _propagate(h: torch.Tensor, edge_index: torch.Tensor, weight: torch.Tensor) -> torch.Tensor:
        src, dst = edge_index[0], edge_index[1]
        msg = h[src] * weight.unsqueeze(1)
        out = torch.zeros_like(h)
        out.index_add_(0, dst, msg)
        return out

    def encode_nodes(self, x, edge_index, edge_weight):
        """Shared trunk: returns one ``hidden``-dim embedding per block."""
        h = self._propagate(self.w1(x), edge_index, edge_weight)
        h = F.relu(h)
        h = F.dropout(h, p=self.dropout, training=self.training)
        h = self._propagate(self.w2(h), edge_index, edge_weight)
        if self.w_skip is not None:
            h = h + self.w_skip(x)
        return F.relu(h)

    def forward(self, x, edge_index, edge_weight, pool_idx, n_funcs):
        h = self.encode_nodes(x, edge_index, edge_weight)

        pooled = torch.cat([scatter_mean(h, pool_idx, n_funcs),
                            scatter_max(h, pool_idx, n_funcs)], dim=1)
        return self.head(pooled)


class FunctionGCNWithNodeHead(FunctionGCN):
    """Function-level GCN plus a per-block head for Stage 2 localisation.

    The trunk is identical to :class:`FunctionGCN`, so a function checkpoint can
    seed a block model.  ``node_head`` maps each block embedding to one logit
    per target.
    """

    def __init__(self, in_dim: int, hidden: int = 64, dropout: float = 0.2,
                 residual: bool = True, n_outputs: int = 1):
        super().__init__(
            in_dim, hidden=hidden, dropout=dropout, residual=residual,
            n_outputs=n_outputs,
        )
        self.node_head = nn.Linear(hidden, n_outputs)

    def forward_nodes(self, x, edge_index, edge_weight):
        h = self.encode_nodes(x, edge_index, edge_weight)
        return self.node_head(h)


def collate_graphs(graphs, standardize=True):
    """Batch one or more graphs into the tensors the model expects.

    ``graphs`` is an iterable of mappings with ``x`` (blocks x features),
    ``edge_src``/``edge_dst`` (local node indices), ``node_func`` (local
    function id per block) and ``n_funcs``.  This is the single batching path
    shared by training and inference, so a binary scored at inference time is
    assembled exactly like a training batch.
    """
    xs, srcs, dsts, pools = [], [], [], []
    node_base = 0
    func_base = 0
    for g in graphs:
        x = np.asarray(g["x"], dtype=np.float32)
        xs.append(x)
        srcs.append(np.asarray(g["edge_src"], dtype=np.int64) + node_base)
        dsts.append(np.asarray(g["edge_dst"], dtype=np.int64) + node_base)
        pools.append(np.asarray(g["node_func"], dtype=np.int64) + func_base)
        node_base += x.shape[0]
        func_base += int(g["n_funcs"])

    if xs and sum(x.shape[0] for x in xs) > 0:
        x = torch.from_numpy(np.concatenate(xs))
        src = torch.from_numpy(np.concatenate(srcs))
        dst = torch.from_numpy(np.concatenate(dsts))
        pool = torch.from_numpy(np.concatenate(pools))
    else:
        in_dim = xs[0].shape[1] if xs else 0
        x = torch.zeros((0, in_dim), dtype=torch.float32)
        src = torch.zeros(0, dtype=torch.long)
        dst = torch.zeros(0, dtype=torch.long)
        pool = torch.zeros(0, dtype=torch.long)

    if standardize:
        x = standardize_features(x)

    n_nodes = x.size(0)
    loop = torch.arange(n_nodes)
    src = torch.cat([src, loop])
    dst = torch.cat([dst, loop])
    return x, torch.stack([src, dst]), pool, func_base


class GraphCorpus:
    """Random access over the flattened graph corpus."""

    def __init__(self, meta_path, feats_path):
        m = np.load(meta_path, allow_pickle=True)
        self.sample_ids = [str(s) for s in m["sample_ids"]]
        self.node_off = m["node_off"]
        self.edge_off = m["edge_off"]
        self.func_off = m["func_off"]
        self.edge_src = m["edge_src"]
        self.edge_dst = m["edge_dst"]
        self.node_func = m["node_func"]
        self.func_va = m["func_va"]
        self.func_rva = m["func_rva"]
        self.func_size = m["func_size"]
        y = m["y"]
        self.y = y.astype(np.float32) if y.ndim == 2 else y.reshape(-1, 1).astype(np.float32)
        self.eligible = m["eligible"].astype(bool)
        self.status = m.get("status", np.zeros(len(self.y), dtype=np.int8))
        self.label_names = [str(x) for x in m.get("label_names", ["label"])]
        self.feats = np.load(feats_path, mmap_mode="r")
        # Optional Stage 2 arrays, aligned with the flattened block order.
        root = Path(feats_path).parent
        block_labels = root / "block_labels.npy"
        block_mask = root / "block_mask.npy"
        self.block_y = np.load(block_labels) if block_labels.exists() else None
        self.block_mask = np.load(block_mask) if block_mask.exists() else None
        self.n_graphs = len(self.sample_ids)
        self.n_funcs = len(self.y)
        self.n_outputs = self.y.shape[1]

    # ---- per-graph accessors -------------------------------------------------
    def graph_slices(self, g):
        nb0, nb1 = int(self.node_off[g]), int(self.node_off[g + 1])
        ne0, ne1 = int(self.edge_off[g]), int(self.edge_off[g + 1])
        nf0, nf1 = int(self.func_off[g]), int(self.func_off[g + 1])
        return (nb0, nb1), (ne0, ne1), (nf0, nf1)

    def function_count(self, g):
        return int(self.func_off[g + 1] - self.func_off[g])

    # ---- batching ------------------------------------------------------------
    def build_batch(self, graph_ids, standardize=True):
        parts = []
        ys, elig = [], []
        for g in graph_ids:
            (nb0, nb1), (ne0, ne1), (nf0, nf1) = self.graph_slices(g)
            parts.append({
                "x": self.feats[nb0:nb1],
                "edge_src": self.edge_src[ne0:ne1],
                "edge_dst": self.edge_dst[ne0:ne1],
                "node_func": self.node_func[nb0:nb1],
                "n_funcs": nf1 - nf0,
            })
            ys.append(self.y[nf0:nf1])
            elig.append(self.eligible[nf0:nf1])

        x, edge_index, pool, n_funcs = collate_graphs(parts, standardize=standardize)
        if ys:
            y = torch.from_numpy(np.concatenate(ys))
            elig_t = torch.from_numpy(np.concatenate(elig))
        else:
            y = torch.zeros((0, self.n_outputs))
            elig_t = torch.zeros(0, dtype=torch.bool)
        return x, edge_index, pool, n_funcs, y, elig_t


_MEAN = None
_STD = None


def set_standardizer(mean, std):
    global _MEAN, _STD
    _MEAN, _STD = mean, std


def standardize_features(x):
    global _MEAN, _STD
    if _MEAN is None:
        return x
    return (x - _MEAN) / _STD


def symmetric_weights(edge_index, n_nodes, drop_edges=False):
    """D^-1/2 (A + I) D^-1/2, computed from the already self-looped edge list."""
    if drop_edges:
        # identity only: keeps every node, removes all message passing
        idx = torch.arange(n_nodes)
        edge_index = torch.stack([idx, idx])
    src, dst = edge_index[0], edge_index[1]
    deg = torch.zeros(n_nodes)
    deg.index_add_(0, dst, torch.ones_like(dst, dtype=torch.float32))
    dinv = deg.clamp(min=1.0).pow(-0.5)
    return edge_index, dinv[src] * dinv[dst]


def compute_standardizer(corpus, graph_ids, n_sample_blocks=200_000, seed=0):
    """Per-feature mean/std over blocks of the *supplied* graphs only.

    ``graph_ids`` are not assumed to be contiguous.  Sampling is weighted by
    each graph's block count, then a block is drawn inside that graph, so no
    block from a held-out graph can enter the statistics.
    """
    ids = np.asarray(list(graph_ids), dtype=np.int64)
    if not len(ids):
        raise ValueError("compute_standardizer needs at least one graph")
    counts = np.asarray(
        [int(corpus.node_off[g + 1] - corpus.node_off[g]) for g in ids],
        dtype=np.float64,
    )
    if counts.sum() == 0:
        raise ValueError("supplied graphs contain no blocks")
    rng = np.random.RandomState(seed)
    k = min(int(n_sample_blocks), int(counts.sum()))
    # Sample graphs proportionally to their block count, then a block inside
    # each chosen graph.  With replacement is fine for a moment estimate.
    gidx = rng.choice(len(ids), size=k, replace=True, p=counts / counts.sum())
    offsets = (rng.random(k) * counts[gidx]).astype(np.int64)
    take = corpus.node_off[ids[gidx]] + offsets
    sample = np.asarray(corpus.feats[take], dtype=np.float32)
    mean = torch.from_numpy(sample.mean(axis=0))
    std = torch.from_numpy(sample.std(axis=0))
    std[std < 1e-6] = 1.0
    return mean, std
