#!/usr/bin/env python3
"""Reusable single-binary inference path.

This module deliberately reuses the training feature builder and the training
models.  The goal is feature parity: a binary scored here must produce the same
187-dimensional block features and the same model outputs as the corpus path.
"""

from __future__ import annotations

import contextlib
import hashlib
import tempfile
import time
from pathlib import Path
from typing import Any, Iterator

import numpy as np
import torch

from src.extract.batch_extract import CfgSample, run_worker
from src.extract.cfg_store import load_cfg_summary
from src.features.block_features import (
    LABEL_NAMES, N_FEAT, graph_arrays, load_import_map,
)
from src.models.gcn import (
    FunctionGCN, FunctionGCNWithNodeHead, collate_graphs,
    set_standardizer, symmetric_weights,
)

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_STAGE1 = ROOT / "results" / "train" / "stage1" / "best.pt"
DEFAULT_STAGE2 = ROOT / "results" / "train" / "stage2" / "best.pt"
X86_MACHINE = 0x14C


class InferenceError(RuntimeError):
    """A user-facing inference failure."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_x86_pe(path: Path) -> dict[str, Any]:
    """Best-effort PE header check before paying for angr extraction."""
    try:
        import pefile
    except ImportError as exc:  # pragma: no cover - environment guard
        return {"checked": False, "warning": f"pefile unavailable: {exc}"}
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except Exception as exc:  # noqa: BLE001 - extraction may repair a broken PE
        return {
            "checked": False,
            "warning": f"PE header check failed: {type(exc).__name__}: {exc}",
        }
    machine = int(pe.FILE_HEADER.Machine)
    optional = int(getattr(pe.OPTIONAL_HEADER, "Magic", 0))
    out = {
        "checked": True,
        "machine": machine,
        "machine_hex": hex(machine),
        "optional_magic": hex(optional),
        "is_pe32": optional == 0x10B,
    }
    if machine == 0:
        out["warning"] = (
            "PE machine field is 0; extraction/repair will determine the "
            "actual architecture"
        )
    elif machine != X86_MACHINE:
        raise InferenceError(
            "this model is x86 PE only; input machine is "
            f"{hex(machine)} (expected {hex(X86_MACHINE)})"
        )
    if optional != 0x10B:
        raise InferenceError(
            "this model expects PE32 (32-bit x86); input optional-header magic is "
            f"{hex(optional)}"
        )
    return out


def _load_checkpoint(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise InferenceError(f"checkpoint not found: {path}")
    try:
        return torch.load(path, map_location="cpu", weights_only=False)
    except Exception as exc:  # noqa: BLE001
        raise InferenceError(f"could not load checkpoint {path}: {exc}") from exc


def _labels_from(ckpt: dict[str, Any], path: Path) -> list[str]:
    labels = [str(x) for x in ckpt.get("labels", [])]
    if labels != list(LABEL_NAMES):
        raise InferenceError(
            f"checkpoint {path} has labels {labels}, expected {list(LABEL_NAMES)}"
        )
    return labels


def _standardizer(ckpt: dict[str, Any], path: Path) -> tuple[torch.Tensor, torch.Tensor]:
    std = ckpt.get("standardizer")
    if not std or "mean" not in std or "std" not in std:
        raise InferenceError(f"checkpoint {path} has no standardizer")
    mean = torch.tensor(std["mean"], dtype=torch.float32)
    scale = torch.tensor(std["std"], dtype=torch.float32)
    if mean.numel() != N_FEAT or scale.numel() != N_FEAT:
        raise InferenceError(
            f"checkpoint {path} standardizer width does not match feature width {N_FEAT}"
        )
    return mean, scale


def load_models(stage1_path: Path = DEFAULT_STAGE1,
                stage2_path: Path | None = DEFAULT_STAGE2, *,
                threads: int = 8) -> dict[str, Any]:
    """Load Stage 1 and optional Stage 2 checkpoints."""
    torch.set_num_threads(max(1, int(threads)))
    ck1 = _load_checkpoint(stage1_path)
    labels = _labels_from(ck1, stage1_path)
    mean, scale = _standardizer(ck1, stage1_path)
    set_standardizer(mean, scale)

    m1cfg = ck1.get("model", {})
    if int(m1cfg.get("in_dim", -1)) != N_FEAT:
        raise InferenceError(
            f"Stage 1 in_dim {m1cfg.get('in_dim')} does not match feature width {N_FEAT}"
        )
    model1 = FunctionGCN(
        int(m1cfg["in_dim"]),
        hidden=int(m1cfg["hidden"]),
        dropout=float(m1cfg.get("dropout", 0.2)),
        residual=bool(m1cfg.get("residual", True)),
        n_outputs=int(m1cfg.get("n_outputs", len(labels))),
    )
    model1.load_state_dict(ck1["state_dict"])
    model1.eval()

    model2 = None
    ck2 = None
    th2: list[float] | None = None
    if stage2_path is not None:
        ck2 = _load_checkpoint(stage2_path)
        _labels_from(ck2, stage2_path)
        m2cfg = ck2.get("model", {})
        if int(m2cfg.get("in_dim", -1)) != N_FEAT:
            raise InferenceError(
                f"Stage 2 in_dim {m2cfg.get('in_dim')} does not match feature width {N_FEAT}"
            )
        model2 = FunctionGCNWithNodeHead(
            int(m2cfg["in_dim"]),
            hidden=int(m2cfg["hidden"]),
            dropout=float(m2cfg.get("dropout", 0.2)),
            residual=bool(m2cfg.get("residual", True)),
            n_outputs=int(m2cfg.get("n_outputs", len(labels))),
        )
        model2.load_state_dict(ck2["state_dict"])
        model2.eval()
        th2 = [float(x) for x in ck2.get("thresholds", [0.5] * len(labels))]

    th1 = [float(x) for x in ck1.get("thresholds", [0.5] * len(labels))]
    if len(th1) != len(labels):
        raise InferenceError("Stage 1 threshold count does not match label count")
    if th2 is not None and len(th2) != len(labels):
        raise InferenceError("Stage 2 threshold count does not match label count")
    return {
        "stage1": model1,
        "stage2": model2,
        "labels": labels,
        "thresholds_stage1": th1,
        "thresholds_stage2": th2,
        "stage1_checkpoint": str(stage1_path),
        "stage2_checkpoint": str(stage2_path) if stage2_path is not None else None,
    }


@contextlib.contextmanager
def extracted_graph(binary: Path, *, timeout: float = 1800.0,
                    rss_limit_gb: float = 3.0,
                    scratch_parent: Path | None = None) -> Iterator[dict[str, Any]]:
    """Extract one PE in the existing timeout/RSS-protected worker."""
    sid = sha256_file(binary)
    parent = str(scratch_parent) if scratch_parent is not None else None
    if parent is not None:
        Path(parent).mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cfg-gnn-infer-", dir=parent) as tmp:
        work = Path(tmp)
        graph_path = work / "graph.npz"
        sample = CfgSample(
            sample_id=sid,
            filepath=str(binary),
            source_bucket="inference",
            family="unknown",
        )
        started = time.time()
        result = run_worker(
            sample, binary, graph_path, work,
            timeout=float(timeout), rss_limit_gb=float(rss_limit_gb),
        )
        if not result.get("ok"):
            raise InferenceError(
                "CFG extraction failed "
                f"({result.get('status', 'error')}): {result.get('error', 'unknown')}"
            )
        summary = result.get("summary") or load_cfg_summary(graph_path)
        yield {
            "graph_path": graph_path,
            "summary": summary,
            "elapsed_seconds": round(time.time() - started, 3),
            "peak_mb": result.get("peak_mb"),
            "sample_id": sid,
        }


def build_features(graph_path: Path, binary: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build the exact training features for one extracted graph."""
    with np.load(graph_path, allow_pickle=True) as d:
        base = int(d["base_address"][0]) if "base_address" in d else 0
        api_map, api_stats = load_import_map(binary, base)
        try:
            arrays = graph_arrays(d, api_map)
        except Exception as exc:  # noqa: BLE001
            raise InferenceError(f"feature construction failed: {exc}") from exc
    arrays["n_funcs"] = int(len(arrays["func_va"]))
    if arrays["x"].shape[1] != N_FEAT:
        raise InferenceError(
            f"feature width {arrays['x'].shape[1]} does not match {N_FEAT}"
        )
    return arrays, api_stats


@torch.no_grad()
def predict_graph(arrays: dict[str, Any], models: dict[str, Any]) -> tuple[np.ndarray, np.ndarray | None]:
    """Return function probabilities and optional block probabilities."""
    n_funcs = int(arrays["n_funcs"])
    if n_funcs == 0 or len(arrays["x"]) == 0:
        raise InferenceError("the extracted graph has no functions or blocks")
    graph = {
        "x": arrays["x"],
        "edge_src": arrays["edge_src"],
        "edge_dst": arrays["edge_dst"],
        "node_func": arrays["node_func"],
        "n_funcs": n_funcs,
    }
    x, edge_index, pool, n_funcs_t = collate_graphs([graph], standardize=True)
    edge_index, ew = symmetric_weights(edge_index, x.size(0))
    logits1 = models["stage1"](x, edge_index, ew, pool, n_funcs_t)
    p1 = torch.sigmoid(logits1).cpu().numpy()
    p2 = None
    if models.get("stage2") is not None:
        logits2 = models["stage2"].forward_nodes(x, edge_index, ew)
        p2 = torch.sigmoid(logits2).cpu().numpy()
    return p1, p2
