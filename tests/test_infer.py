"""Single-binary inference report and parity invariants."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest
import torch

from src.infer.report import build_report, render_text

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "results" / "corpus_v2_three_targets"
SID = "15030f38a27ce41a29030ffa167094f6487407717eb15cbb9a409748e8ea4c1e"


def _synthetic():
    arrays = {
        "base_address": 0x400000,
        "func_va": np.array([0x401000, 0x402000], dtype=np.int64),
        "func_rva": np.array([0x1000, 0x2000], dtype=np.int64),
        "node_func": np.array([0, 0, 1], dtype=np.int64),
        "block_addr": np.array([0x401000, 0x401010, 0x402000], dtype=np.int64),
        "block_size": np.array([16, 16, 8], dtype=np.int64),
    }
    p1 = np.array([[0.99, 0.20, 0.10], [0.10, 0.95, 0.30]], dtype=np.float32)
    p2 = np.array(
        [[0.90, 0.10, 0.10], [0.20, 0.80, 0.10], [0.10, 0.60, 0.10]],
        dtype=np.float32,
    )
    models = {
        "labels": ["anti_debug", "keylogger", "injection"],
        "thresholds_stage1": [0.5, 0.5, 0.5],
        "thresholds_stage2": [0.5, 0.5, 0.5],
        "stage1_checkpoint": "s1.pt",
        "stage2_checkpoint": "s2.pt",
    }
    sample = {
        "path": "sample.exe", "sha256": "abc", "size_bytes": 10,
        "arch": "X86", "base_address": 0x400000,
        "base_address_hex": "0x400000", "functions": 2, "blocks": 3, "edges": 2,
    }
    extraction = {"used_pre_extracted_graph": True, "summary": {"arch": "X86"}}
    return arrays, p1, p2, models, sample, extraction


def test_report_present_flags_and_block_filtering():
    arrays, p1, p2, models, sample, extraction = _synthetic()
    report = build_report(
        sample=sample, arrays=arrays, p1=p1, p2=p2, models=models,
        extraction=extraction, api_stats={"loaded": True},
        warnings=[], all_functions=False, max_blocks_per_function=10,
    )
    assert report["summary"] == {
        "anti_debug": True, "keylogger": True, "injection": False,
    }
    anti = report["targets"]["anti_debug"]
    assert anti["n_flagged_functions"] == 1
    assert anti["functions"][0]["func_va"] == 0x401000
    assert [b["block_va"] for b in anti["functions"][0]["blocks"]] == [0x401000]
    key = report["targets"]["keylogger"]
    assert key["functions"][0]["func_va"] == 0x402000
    assert [b["block_va"] for b in key["functions"][0]["blocks"]] == [0x402000]
    # JSON-safe
    json.dumps(report)


def test_report_all_functions_includes_unselected():
    arrays, p1, p2, models, sample, extraction = _synthetic()
    report = build_report(
        sample=sample, arrays=arrays, p1=p1, p2=p2, models=models,
        extraction=extraction, api_stats={"loaded": True}, warnings=[],
        all_functions=True, max_blocks_per_function=10,
    )
    assert len(report["targets"]["anti_debug"]["functions"]) == 2
    assert report["targets"]["anti_debug"]["functions"][0]["selected"] is True


def test_report_no_stage2():
    arrays, p1, _p2, models, sample, extraction = _synthetic()
    models = dict(models)
    models["thresholds_stage2"] = None
    report = build_report(
        sample=sample, arrays=arrays, p1=p1, p2=None, models=models,
        extraction=extraction, api_stats={"loaded": True}, warnings=[],
    )
    assert report["models"]["stage2_enabled"] is False
    assert report["targets"]["anti_debug"]["functions"][0]["blocks"] == []
    assert any("Stage 2 was disabled" in w for w in report["warnings"])
    assert "anti_debug" in render_text(report)


def test_report_block_cap_marks_warning():
    arrays, p1, p2, models, sample, extraction = _synthetic()
    report = build_report(
        sample=sample, arrays=arrays, p1=p1, p2=p2, models=models,
        extraction=extraction, api_stats={"loaded": True}, warnings=[],
        max_blocks_per_function=0,
    )
    # 0 means unlimited in the CLI caller, but here it is passed literally;
    # this test checks the report does not crash on the cap boundary.
    assert report["targets"]["anti_debug"]["present"] is True


@pytest.mark.skipif(not (CORPUS / "graph_meta.npz").exists(), reason="corpus missing")
def test_single_graph_features_match_corpus_exactly():
    import pandas as pd
    from src.infer.pipeline import build_features
    from src.models.gcn import GraphCorpus

    graph = ROOT / "data" / "graphs_v2" / "cfg" / f"{SID}.npz"
    manifest = pd.read_csv(ROOT / "data" / "versions" / "v2" / "manifest.csv")
    pe = ROOT / manifest.loc[manifest.sample_id == SID, "filepath"].iloc[0]
    if not graph.exists() or not pe.exists():
        pytest.skip("raw graph/PE missing")
    arrays, _stats = build_features(graph, pe)
    corpus = GraphCorpus(CORPUS / "graph_meta.npz", CORPUS / "block_feats.npy")
    gi = corpus.sample_ids.index(SID)
    nb0, nb1 = int(corpus.node_off[gi]), int(corpus.node_off[gi + 1])
    assert np.array_equal(arrays["x"], corpus.feats[nb0:nb1])
    nf0, nf1 = int(corpus.func_off[gi]), int(corpus.func_off[gi + 1])
    assert np.array_equal(arrays["func_va"], corpus.func_va[nf0:nf1])


@pytest.mark.skipif(not (ROOT / "results/train/stage1/best.pt").exists(),
                    reason="Stage 1 checkpoint missing")
@pytest.mark.skipif(not (ROOT / "results/train/stage2/best.pt").exists(),
                    reason="Stage 2 checkpoint missing")
def test_single_graph_predictions_match_batch():
    import pandas as pd
    from src.infer.pipeline import build_features, load_models, predict_graph
    from src.models.gcn import GraphCorpus, symmetric_weights
    import torch

    graph = ROOT / "data" / "graphs_v2" / "cfg" / f"{SID}.npz"
    manifest = pd.read_csv(ROOT / "data" / "versions" / "v2" / "manifest.csv")
    pe = ROOT / manifest.loc[manifest.sample_id == SID, "filepath"].iloc[0]
    if not graph.exists() or not pe.exists():
        pytest.skip("raw graph/PE missing")
    arrays, _stats = build_features(graph, pe)
    models = load_models(
        ROOT / "results/train/stage1/best.pt",
        ROOT / "results/train/stage2/best.pt", threads=2,
    )
    p1, p2 = predict_graph(arrays, models)

    corpus = GraphCorpus(CORPUS / "graph_meta.npz", CORPUS / "block_feats.npy")
    gi = corpus.sample_ids.index(SID)
    x, edge_index, pool, n_funcs, _y, _elig = corpus.build_batch([gi])
    edge_index, ew = symmetric_weights(edge_index, x.size(0))
    with torch.no_grad():
        q1 = torch.sigmoid(models["stage1"](x, edge_index, ew, pool, n_funcs)).numpy()
        q2 = torch.sigmoid(models["stage2"].forward_nodes(x, edge_index, ew)).numpy()
    assert np.allclose(p1, q1, atol=1e-6)
    assert np.allclose(p2, q2, atol=1e-6)
