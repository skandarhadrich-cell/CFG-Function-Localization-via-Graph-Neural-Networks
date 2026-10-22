"""Stage 2 block-label and metric invariants."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import torch

from src.models.gcn import FunctionGCNWithNodeHead, GraphCorpus
from src.train.stage2 import _block_metrics, _tune_block_thresholds

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "results" / "corpus_v2_three_targets"


def test_block_labels_align_with_corpus():
    by = np.load(CORPUS / "block_labels.npy", mmap_mode="r")
    bm = np.load(CORPUS / "block_mask.npy", mmap_mode="r")
    feats = np.load(CORPUS / "block_feats.npy", mmap_mode="r")
    meta = np.load(CORPUS / "graph_meta.npz", allow_pickle=True)
    assert by.shape == (feats.shape[0], 3)
    assert bm.shape == (feats.shape[0],)
    assert int(meta["node_off"][-1]) == feats.shape[0]
    assert np.all(bm[by.any(axis=1)] == 1)
    assert by.sum() > 0


def test_block_label_report_matches_arrays():
    by = np.load(CORPUS / "block_labels.npy", mmap_mode="r")
    bm = np.load(CORPUS / "block_mask.npy", mmap_mode="r")
    report = json.loads((CORPUS / "block_label_report.json").read_text())
    assert report["blocks"] == by.shape[0]
    assert report["masked_blocks"] == int(bm.sum())
    for c, name in enumerate(("anti_debug", "keylogger", "injection")):
        assert report["positive_blocks"][name] == int(by[:, c].sum())
        assert report["positive_blocks"][name] > 0
    assert sum(
        report["split_support"][s][name]["blocks"]
        for s in ("train", "val", "test")
        for name in ("anti_debug", "keylogger", "injection")
    ) > 0


def test_graph_corpus_exposes_block_arrays():
    corpus = GraphCorpus(CORPUS / "graph_meta.npz", CORPUS / "block_feats.npy")
    assert corpus.block_y is not None
    assert corpus.block_mask is not None
    assert corpus.block_y.shape[0] == corpus.block_mask.shape[0]


def test_block_metrics_iou_is_jaccard():
    prob = np.array([[0.9, 0.1], [0.1, 0.9], [0.05, 0.05], [0.05, 0.05]], np.float32)
    y = np.array([[1, 0], [0, 1], [0, 0], [0, 0]], np.uint8)
    mask = np.array([1, 1, 1, 1], np.uint8)
    fids = np.array([0, 0, 1, 1], np.int64)
    m = _block_metrics(prob, y, mask, fids, ["a", "b"], [0.5, 0.5])
    # target a: tp=1, fp=0, fn=0 -> F1=1, IoU=1
    assert m["per_class"]["a"]["f1"] == 1.0
    assert m["per_class"]["a"]["iou"] == 1.0
    # target b: tp=1, fp=0, fn=0 -> F1=1, IoU=1
    assert m["per_class"]["b"]["f1"] == 1.0
    assert m["per_class"]["b"]["iou"] == 1.0


def test_block_metrics_partial_overlap():
    prob = np.array([[0.9], [0.9], [0.1], [0.1]], np.float32)
    y = np.array([[1], [0], [1], [0]], np.uint8)
    mask = np.ones(4, np.uint8)
    fids = np.array([0, 0, 1, 1], np.int64)
    m = _block_metrics(prob, y, mask, fids, ["a"], [0.5])
    c = m["per_class"]["a"]
    assert c["precision"] == 0.5
    assert c["recall"] == 0.5
    assert c["f1"] == 0.5
    assert c["iou"] == 1 / 3


def test_tune_thresholds_respects_support():
    prob = np.array([[0.9], [0.8], [0.1]], np.float32)
    y = np.array([[1], [0], [1]], np.uint8)
    mask = np.ones(3, np.uint8)
    thresholds = _tune_block_thresholds(prob, y, mask, ["a"], min_support=10)
    assert thresholds == [0.5]


def test_node_head_shape():
    model = FunctionGCNWithNodeHead(187, hidden=16, n_outputs=3)
    x = torch.zeros(5, 187)
    edge_index = torch.arange(5).repeat(2, 1)
    edge_index = torch.stack([edge_index[0], edge_index[1]])
    logits = model.forward_nodes(x, edge_index, torch.ones(5))
    assert logits.shape == (5, 3)


def test_end_to_end_prf():
    from src.eval.stage2_end_to_end import _prf
    m = _prf(tp=2, fp=1, fn=1)
    assert m["precision"] == 2 / 3
    assert m["recall"] == 2 / 3
    assert m["f1"] == 2 / 3
    assert m["iou"] == 0.5
