#!/usr/bin/env python3
"""Cluster-grouped fold assignment and the frozen v2 split loader.

Near-duplicate samples share a ``cluster_key``.  Folds are assigned over the
clusters, never over individual samples, so a cluster cannot cross a fold
boundary.  The same helper is used by the Stage 1 split checks.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
N_FOLDS = 5
SEED = 42


def fold_assignment(
    cluster_keys: list[str], n_folds: int = N_FOLDS, seed: int = SEED
) -> list[set[str]]:
    """Return ``n_folds`` disjoint sets of cluster keys."""
    uniq = sorted(set(cluster_keys))
    if len(uniq) < n_folds:
        raise ValueError(f"only {len(uniq)} clusters for {n_folds} folds")
    perm = np.random.RandomState(seed).permutation(uniq)
    size = len(perm) // n_folds
    folds = []
    for i in range(n_folds):
        start = i * size
        end = (i + 1) * size if i < n_folds - 1 else len(perm)
        folds.append(set(str(c) for c in perm[start:end]))
    return folds


def fold_of_cluster(
    cluster_keys: list[str], n_folds: int = N_FOLDS, seed: int = SEED
) -> dict[str, int]:
    folds = fold_assignment(cluster_keys, n_folds, seed)
    return {c: i for i, fold in enumerate(folds) for c in fold}


def fold_sizes(
    cluster_keys: list[str], n_folds: int = N_FOLDS, seed: int = SEED
) -> dict[str, int]:
    folds = fold_assignment(cluster_keys, n_folds, seed)
    return {
        f"fold_{i}": sum(1 for c in cluster_keys if c in fold)
        for i, fold in enumerate(folds)
    }


def manifest_splits() -> dict[str, str]:
    path = ROOT / "data" / "versions" / "v2" / "splits" / "three_target.json"
    return json.loads(path.read_text())["assignments"]
