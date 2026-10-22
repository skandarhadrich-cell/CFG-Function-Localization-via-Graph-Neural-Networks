#!/usr/bin/env python3
"""JSON/text report construction for single-binary inference."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import numpy as np


def _hex(value: int) -> str:
    return f"0x{int(value):x}"


def _block_entries(block_ids: np.ndarray, scores: np.ndarray,
                   addresses: np.ndarray, sizes: np.ndarray,
                   base: int, threshold: float, max_blocks: int | None):
    keep = scores >= threshold
    idx = block_ids[keep]
    if len(idx) == 0:
        return [], (round(float(scores.max()), 6) if len(scores) else None), False
    kept_scores = scores[keep]
    order = np.argsort(-kept_scores)
    truncated = max_blocks is not None and len(order) > max_blocks
    if truncated:
        order = order[:max_blocks]
    out = []
    for j in order:
        b = int(idx[j])
        out.append({
            "block_va": int(addresses[b]),
            "block_rva": _hex(int(addresses[b]) - base),
            "size": int(sizes[b]),
            "score": round(float(kept_scores[j]), 6),
        })
    return out, round(float(scores.max()), 6), truncated


def build_report(
    *,
    sample: dict[str, Any],
    arrays: dict[str, Any],
    p1: np.ndarray,
    p2: np.ndarray | None,
    models: dict[str, Any],
    extraction: dict[str, Any],
    api_stats: dict[str, Any],
    warnings: list[str] | None = None,
    all_functions: bool = False,
    max_blocks_per_function: int | None = 200,
) -> dict[str, Any]:
    labels = list(models["labels"])
    th1 = list(models["thresholds_stage1"])
    th2 = models.get("thresholds_stage2")
    base = int(arrays.get("base_address", 0))
    func_va = np.asarray(arrays["func_va"], dtype=np.int64)
    func_rva = np.asarray(arrays["func_rva"], dtype=np.int64)
    node_func = np.asarray(arrays["node_func"], dtype=np.int64)
    block_addr = np.asarray(arrays["block_addr"], dtype=np.int64)
    block_size = np.asarray(arrays["block_size"], dtype=np.int64)

    if p1.shape != (len(func_va), len(labels)):
        raise ValueError(
            f"Stage 1 output shape {p1.shape} does not match "
            f"({len(func_va)}, {len(labels)})"
        )
    if p2 is not None and p2.shape != (len(node_func), len(labels)):
        raise ValueError(
            f"Stage 2 output shape {p2.shape} does not match "
            f"({len(node_func)}, {len(labels)})"
        )

    targets: dict[str, Any] = {}
    total_flagged = 0
    truncated_any = False
    for c, name in enumerate(labels):
        scores = p1[:, c]
        selected_mask = scores >= th1[c]
        selected_idx = np.flatnonzero(selected_mask)
        selected_idx = selected_idx[np.argsort(-scores[selected_idx])]
        total_flagged += int(selected_idx.size)
        if all_functions:
            display_idx = np.argsort(-scores)
        else:
            display_idx = selected_idx
        functions = []
        for fid in display_idx:
            fid = int(fid)
            selected = bool(selected_mask[fid])
            entry = {
                "func_va": int(func_va[fid]),
                "func_rva": _hex(int(func_rva[fid])),
                "score": round(float(scores[fid]), 6),
                "selected": selected,
                "max_block_score": None,
                "blocks": [],
            }
            if selected and p2 is not None:
                bidx = np.flatnonzero(node_func == fid)
                bscore = p2[bidx, c]
                blocks, max_bscore, truncated = _block_entries(
                    bidx, bscore, block_addr, block_size, base,
                    th2[c], max_blocks_per_function,
                )
                entry["blocks"] = blocks
                entry["max_block_score"] = max_bscore
                truncated_any = truncated_any or truncated
            functions.append(entry)
        targets[name] = {
            "present": bool(selected_idx.size),
            "max_function_score": round(float(scores.max()), 6) if len(scores) else 0.0,
            "n_functions": int(len(scores)),
            "n_flagged_functions": int(selected_idx.size),
            "stage1_threshold": float(th1[c]),
            "stage2_threshold": float(th2[c]) if th2 is not None else None,
            "functions": functions,
        }

    warnings = list(warnings or [])
    if truncated_any:
        warnings.append(
            "some functions have more blocks above threshold than the display cap; "
            "raise --max-blocks-per-function to see all of them"
        )
    if p2 is None:
        warnings.append("Stage 2 was disabled; no block localisation was produced")
    if not total_flagged:
        warnings.append("no function crossed a Stage 1 target threshold")

    return {
        "schema_version": "cfg-gnn.infer.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sample": sample,
        "models": {
            "stage1_checkpoint": models.get("stage1_checkpoint"),
            "stage2_checkpoint": models.get("stage2_checkpoint"),
            "labels": labels,
            "stage1_thresholds": th1,
            "stage2_thresholds": th2,
            "stage2_enabled": p2 is not None,
        },
        "extraction": extraction,
        "api": api_stats,
        "summary": {name: targets[name]["present"] for name in labels},
        "targets": targets,
        "warnings": warnings,
    }


def render_text(report: dict[str, Any]) -> str:
    s = report["sample"]
    lines = [
        f"sample: {s.get('path')}",
        f"sha256: {s.get('sha256')}",
        f"arch: {s.get('arch')}  functions: {s.get('functions')}  "
        f"blocks: {s.get('blocks')}  base: {s.get('base_address_hex')}",
        "",
    ]
    for name, t in report["targets"].items():
        state = "PRESENT" if t["present"] else "absent"
        lines.append(
            f"{name:12s} {state:7s}  "
            f"{t['n_flagged_functions']}/{t['n_functions']} functions  "
            f"max={t['max_function_score']:.4f}  "
            f"(stage1 threshold {t['stage1_threshold']:.2f})"
        )
        for f in t["functions"]:
            if not f["selected"]:
                continue
            lines.append(
                f"  func {f['func_va']:#x} ({f['func_rva']})  score={f['score']:.4f}"
            )
            if f["max_block_score"] is not None:
                lines.append(f"    max block score={f['max_block_score']:.4f}")
            if not f["blocks"] and f["max_block_score"] is not None:
                lines.append(
                    f"    no block above stage2 threshold "
                    f"({t['stage2_threshold']:.2f})"
                )
            for b in f["blocks"]:
                lines.append(
                    f"    block {b['block_va']:#x} ({b['block_rva']})  "
                    f"size={b['size']}  score={b['score']:.4f}"
                )
    if report.get("warnings"):
        lines += ["", "warnings:"]
        lines += [f"  - {w}" for w in report["warnings"]]
    return "\n".join(lines) + "\n"
