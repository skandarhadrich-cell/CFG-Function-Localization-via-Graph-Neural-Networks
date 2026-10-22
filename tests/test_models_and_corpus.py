"""Invariants for the three-target corpus and model.

These tests do not need the full 17.9M-block corpus.  The model and standardizer
tests use synthetic arrays; the builder test uses two real graphs when the v2
data is present and skips otherwise.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest
import torch

from src.features.block_features import (
    API_START, N_FEAT, api_bucket, build, graph_arrays, load_labels,
)
from src.models.gcn import (
    FunctionGCN, compute_standardizer, collate_graphs, set_standardizer,
    symmetric_weights,
)

ROOT = Path(__file__).resolve().parents[1]


class FakeCorpus:
    def __init__(self):
        # Three graphs, 4 blocks each.  Graph 1 is the held-out graph and its
        # blocks are filled with a huge value that would move the mean.
        self.node_off = np.array([0, 4, 8, 12], dtype=np.int64)
        feats = np.zeros((12, N_FEAT), dtype=np.float32)
        feats[4:8] = 1e6
        self.feats = feats


def test_standardizer_never_samples_held_out_graph():
    corpus = FakeCorpus()
    mean, _ = compute_standardizer(corpus, [0, 2], n_sample_blocks=10_000, seed=0)
    assert float(mean.abs().max()) < 1e-6


def test_api_bucket_is_stable_and_in_range():
    assert 0 <= api_bucket("kernel32.dll!VirtualAllocEx") < 64
    assert api_bucket("kernel32.dll!VirtualAllocEx") == api_bucket(
        "kernel32.dll!VirtualAllocEx"
    )


def test_import_reference_site_sets_api_feature_without_call_target():
    base = 0x400000
    name = "user32.dll!SetWindowsHookExW"
    graph = {
        "base_address": np.array([base]),
        "node_func_id": np.array([0]),
        "node_block_addr": np.array([base]),
        "node_block_size": np.array([6]),
        "mnemonic_offsets": np.array([0, 1]),
        "mnemonics": np.array(["call"], dtype=object),
        "edge_src": np.array([], dtype=np.int64),
        "edge_dst": np.array([], dtype=np.int64),
        "func_va": np.array([base]),
        "func_size": np.array([6]),
        "call_offsets": np.array([0, 0]),
        "call_targets": np.array([], dtype=np.int64),
        "insn_offsets": np.array([0, 1]),
        "insn_addrs": np.array([base + 0x10]),
    }
    block = graph_arrays(graph, {base + 0x10: name})["x"]
    assert block.shape == (1, N_FEAT)
    assert float(block[0, API_START + api_bucket(name)]) > 0
    assert float(block[0, -1]) == 1.0


def test_function_gcn_multilabel_shape():
    torch.manual_seed(0)
    set_standardizer(torch.zeros(N_FEAT), torch.ones(N_FEAT))
    graph = {
        "x": np.random.RandomState(0).randn(5, N_FEAT).astype(np.float32),
        "edge_src": np.array([0, 1, 2], dtype=np.int64),
        "edge_dst": np.array([1, 2, 3], dtype=np.int64),
        "node_func": np.array([0, 0, 1, 1, 1], dtype=np.int64),
        "n_funcs": 2,
    }
    x, edge_index, pool, n_funcs = collate_graphs([graph])
    edge_index, ew = symmetric_weights(edge_index, x.size(0))
    model = FunctionGCN(N_FEAT, hidden=8, n_outputs=3)
    logits = model(x, edge_index, ew, pool, n_funcs)
    assert logits.shape == (2, 3)


@pytest.mark.skipif(
    not (ROOT / "data/graphs_v2/cfg").exists()
    or not (ROOT / "data/labels/stage1_full_three_targets.parquet").exists(),
    reason="v2 graphs/labels not available",
)
def test_builder_keeps_zero_rule_sample_and_advances_offsets(tmp_path):
    zero = json.loads(
        (ROOT / "data/labels/zero_rule_samples.json").read_text()
    )["samples"]
    zero_ids = [s["sample_id"] for s in zero]
    have = {p.stem for p in (ROOT / "data/graphs_v2/cfg").glob("*.npz")}
    splits = json.loads(
        (ROOT / "data/versions/v2/splits/three_target.json").read_text()
    )["assignments"]
    normal = sorted(s for s in splits if s in have and s not in zero_ids)[:2]
    zero_id = next(s for s in zero_ids if s in have)
    ids = normal + [zero_id]

    labels = load_labels(ROOT / "data/labels/stage1_full_three_targets.parquet")
    build(ids, labels, set(zero_ids), out_dir=tmp_path)

    meta = np.load(tmp_path / "graph_meta.npz", allow_pickle=True)
    assert np.all(np.diff(meta["node_off"]) > 0)
    assert np.all(np.diff(meta["func_off"]) > 0)
    assert int(meta["eligible"][meta["func_off"][-2]:meta["func_off"][-1]].sum()) == 0
    assert meta["y"].shape[1] == 3
