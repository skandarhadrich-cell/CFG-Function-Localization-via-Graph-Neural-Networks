#!/usr/bin/env python3
"""Build a cluster-grouped, target-stratified train/val/test split.

The frozen v2 ``main.json`` was created before keylogger was a target.  Its test
split holds 1,026 of the 1,255 keylogger positives, while training holds 137;
that split cannot train or evaluate the three-target task.

This script keeps the v2 main split untouched and writes a new split:

    data/versions/v2/splits/three_target.json

Rules:

* every sample of a ``cluster_key`` goes to the same split;
* sample counts follow 70/15/15;
* target-positive functions follow 70/15/15 as closely as the cluster groups
  allow, with a minimum support penalty for validation and test;
* the assignment is deterministic (30 restarts, local search, seed 42).
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "data" / "versions" / "v2" / "manifest.csv"
LABELS = ROOT / "data" / "labels" / "stage1_full_three_targets.parquet"
OUT = ROOT / "data" / "versions" / "v2" / "splits" / "three_target.json"
REPORT = ROOT / "results" / "full" / "three_target_split.md"

LABELS_ORDER = ("anti_debug", "keylogger", "injection")
SPLITS = ("train", "val", "test")
TARGET = np.array([0.70, 0.15, 0.15])
MIN_POSITIVES = 20.0
N_RESTARTS = 30
SEED = 42


def _load_clusters() -> tuple[pd.DataFrame, np.ndarray, np.ndarray]:
    manifest = pd.read_csv(MANIFEST)
    clean = manifest[manifest["is_clean"] == 1].copy()
    labels = pd.read_parquet(LABELS)
    counts = (
        labels.groupby("sample_id")[[f"label_{x}" for x in LABELS_ORDER]]
        .sum()
        .reset_index()
    )
    frame = clean.merge(counts, on="sample_id", how="left")
    for name in LABELS_ORDER:
        frame[f"label_{name}"] = frame[f"label_{name}"].fillna(0).astype(int)
    frame = frame[frame["cluster_key"].notna()].copy()

    grouped = (
        frame.groupby("cluster_key")
        .agg(
            samples=("sample_id", "count"),
            **{f"label_{x}": (f"label_{x}", "sum") for x in LABELS_ORDER},
        )
        .reset_index()
    )
    pos = grouped[[f"label_{x}" for x in LABELS_ORDER]].to_numpy(float)
    samples = grouped["samples"].to_numpy(float)
    return frame, pos, samples, grouped


def _counts(assign: np.ndarray, pos: np.ndarray, samples: np.ndarray):
    cnt = np.zeros((len(SPLITS), len(LABELS_ORDER)), dtype=float)
    smp = np.zeros(len(SPLITS), dtype=float)
    for i, split in enumerate(assign):
        cnt[split] += pos[i]
        smp[split] += samples[i]
    return cnt, smp


def _loss(cnt: np.ndarray, smp: np.ndarray, totals: np.ndarray,
          total_samples: float) -> float:
    loss = 0.0
    for s in range(len(SPLITS)):
        loss += 8.0 * float(np.sum((cnt[s] / np.maximum(totals, 1) - TARGET[s]) ** 2))
        loss += 1.0 * float((smp[s] / total_samples - TARGET[s]) ** 2)
        if s > 0:
            short = np.maximum(0.0, MIN_POSITIVES - cnt[s]) / MIN_POSITIVES
            loss += 5.0 * float(short.sum())
    return loss


def _initial(samples: np.ndarray, seed: int) -> np.ndarray:
    """Fill the 70/15/15 sample quotas, largest clusters first."""
    rng = np.random.RandomState(seed)
    order = rng.permutation(len(samples))
    # Sort by size descending; the random permutation only breaks size ties.
    order = sorted(order, key=lambda i: -samples[i])
    target_counts = TARGET * samples.sum()
    current = np.zeros(len(SPLITS))
    assign = np.zeros(len(samples), dtype=np.int8)
    for i in order:
        split = int(np.argmax(target_counts - current))
        assign[i] = split
        current[split] += samples[i]
    return assign


def _local_search(assign: np.ndarray, pos: np.ndarray, samples: np.ndarray,
                  totals: np.ndarray, seed: int) -> tuple[float, np.ndarray]:
    cnt, smp = _counts(assign, pos, samples)
    current = _loss(cnt, smp, totals, samples.sum())
    rng = np.random.RandomState(seed)
    for _ in range(80):
        improved = False
        for i in rng.permutation(len(assign)):
            old = int(assign[i])
            best_split = old
            best_loss = current
            for split in range(len(SPLITS)):
                if split == old:
                    continue
                cnt[split] += pos[i]
                cnt[old] -= pos[i]
                smp[split] += samples[i]
                smp[old] -= samples[i]
                value = _loss(cnt, smp, totals, samples.sum())
                if value < best_loss - 1e-12:
                    best_loss = value
                    best_split = split
                cnt[split] -= pos[i]
                cnt[old] += pos[i]
                smp[split] -= samples[i]
                smp[old] += samples[i]
            if best_split != old:
                cnt[best_split] += pos[i]
                cnt[old] -= pos[i]
                smp[best_split] += samples[i]
                smp[old] -= samples[i]
                assign[i] = best_split
                current = best_loss
                improved = True
        if not improved:
            break
    return current, assign


def build() -> dict:
    frame, pos, samples, grouped = _load_clusters()
    totals = pos.sum(axis=0)
    best = None
    for restart in range(N_RESTARTS):
        assign = _initial(samples, SEED + restart)
        value, assign = _local_search(assign, pos, samples, totals, SEED + 1000 + restart)
        cnt_tmp, _ = _counts(assign, pos, samples)
        # Validation and test have the same target, so the loss is symmetric.
        # Break exact ties in favour of a larger held-out minimum support.
        test_min = float(cnt_tmp[-1].min())
        if (
            best is None
            or value < best[0] - 1e-9
            or (abs(value - best[0]) <= 1e-9 and test_min > best[2] + 1e-12)
        ):
            best = (value, assign.copy(), test_min)

    value, assign, _ = best
    cluster_to_split = {
        str(grouped.iloc[i]["cluster_key"]): SPLITS[int(assign[i])]
        for i in range(len(grouped))
    }
    sample_to_split = {
        str(row["sample_id"]): cluster_to_split[str(row["cluster_key"])]
        for _, row in frame.iterrows()
    }

    cnt, smp = _counts(assign, pos, samples)
    stats = {
        SPLITS[s]: {
            "samples": int(smp[s]),
            "clusters": int(np.sum(assign == s)),
            **{
                name: int(cnt[s, i]) for i, name in enumerate(LABELS_ORDER)
            },
        }
        for s in range(len(SPLITS))
    }

    payload = {
        "protocol": "three-target-cluster-stratified-v3",
        "created_utc": "2026-10-22",
        "seed": SEED,
        "restarts": N_RESTARTS,
        "target_fractions": {
            SPLITS[i]: float(TARGET[i]) for i in range(len(SPLITS))
        },
        "min_val_test_positives_penalty": int(MIN_POSITIVES),
        "optimizer_loss": round(float(value), 8),
        "source_manifest": str(MANIFEST.relative_to(ROOT)),
        "source_labels": str(LABELS.relative_to(ROOT)),
        "totals": {
            "samples": int(frame.shape[0]),
            **{name: int(totals[i]) for i, name in enumerate(LABELS_ORDER)},
        },
        "splits": stats,
        "cluster_assignments": cluster_to_split,
        "assignments": sample_to_split,
        "assignment_sha256": hashlib.sha256(
            "\n".join(f"{s}:{sample_to_split[s]}" for s in sorted(sample_to_split)).encode()
        ).hexdigest(),
    }
    return payload


def render(payload: dict) -> str:
    lines = [
        "# Three-target split",
        "",
        f"Protocol: `{payload['protocol']}`  ",
        f"Assignment SHA-256: `{payload['assignment_sha256']}`  ",
        f"Samples: **{payload['totals']['samples']}**; clusters: "
        f"**{sum(s['clusters'] for s in payload['splits'].values())}**; "
        f"optimizer loss: **{payload['optimizer_loss']}**",
        "",
        "| split | samples | clusters | anti_debug | keylogger | injection |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for split in SPLITS:
        s = payload["splits"][split]
        lines.append(
            f"| {split} | {s['samples']} | {s['clusters']} | "
            f"{s['anti_debug']} | {s['keylogger']} | {s['injection']} |"
        )
    lines += [
        "",
        "The split is grouped by `cluster_key`; every sample of a cluster is in "
        "one split. Sample counts follow 70/15/15 and target-positive functions "
        "follow the same proportions as closely as the cluster groups allow. "
        "The optimizer places the dominant keylogger cluster in train and keeps "
        "at least 20 positives per target in validation and test.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=OUT)
    parser.add_argument("--report", type=Path, default=REPORT)
    args = parser.parse_args(argv)

    payload = build()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2) + "\n")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(render(payload))
    print(render(payload))
    for split in SPLITS:
        for name in LABELS_ORDER:
            if payload["splits"][split][name] < MIN_POSITIVES:
                print(
                    f"warning: {split} has only "
                    f"{payload['splits'][split][name]} {name} positives"
                )
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
