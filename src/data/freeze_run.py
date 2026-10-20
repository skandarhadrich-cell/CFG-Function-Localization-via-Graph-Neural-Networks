"""Freeze a run's inputs so downstream work cannot silently drift.

Writes a single JSON record describing exactly what a run consumes:
manifest and split hashes, the effective config, the git commit, the label
contract, tool identity, and the full clean sample ID list.  Later stages can
assert against this file instead of trusting live paths.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


def _resolve(path: str | Path) -> Path:
    path = Path(path).expanduser()
    return path if path.is_absolute() else ROOT / path


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(*args: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(ROOT), *args], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception as exc:  # noqa: BLE001
        return f"error: {type(exc).__name__}: {exc}"


def build_freeze(
    manifest: Path,
    splits: Path,
    config: Path,
    *,
    run_name: str,
) -> dict[str, Any]:
    rows = list(csv.DictReader(manifest.open(newline="")))
    clean = [row for row in rows if row.get("is_clean") == "1"]

    main = json.loads((splits / "main.json").read_text())
    lofo = json.loads((splits / "lofo.json").read_text())

    from src.label.contract import (
        ACTIVE_LABELS,
        ALL_LABELS,
        LABEL_CONTRACT_VERSION,
        MAX_SINGLE_BINARY_SHARE,
        MAX_SINGLE_CLUSTER_SHARE,
        MIN_POSITIVE_BINARIES,
        MIN_POSITIVE_CLUSTERS,
        MIN_POSITIVE_FAMILIES,
        MIN_POSITIVE_FUNCTIONS,
    )

    return {
        "run_name": run_name,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "git_commit": _git("rev-parse", "HEAD"),
        "git_dirty": bool(_git("status", "--porcelain")),
        "manifest": str(manifest),
        "manifest_sha256": _sha256(manifest),
        "manifest_rows": len(rows),
        "clean_rows": len(clean),
        "clean_sample_ids": sorted(row["sample_id"] for row in clean),
        "clean_clusters": len({row["cluster_key"] for row in clean}),
        "splits_dir": str(splits),
        "main_sha256": _sha256(splits / "main.json"),
        "lofo_sha256": _sha256(splits / "lofo.json"),
        "main_manifest_sha256": main.get("manifest_sha256"),
        "lofo_manifest_sha256": lofo.get("manifest_sha256"),
        "lofo_held_out_families": lofo.get("held_out_families"),
        "config": str(config),
        "config_sha256": _sha256(config),
        "label_contract": {
            "version": LABEL_CONTRACT_VERSION,
            "active_labels": list(ACTIVE_LABELS),
            "all_labels": list(ALL_LABELS),
            "keylogger_in_stage1": False,
            "outputs": len(ACTIVE_LABELS),
            "loss": "BCEWithLogitsLoss",
        },
        "diversity_criteria": {
            "min_positive_functions": MIN_POSITIVE_FUNCTIONS,
            "min_positive_binaries": MIN_POSITIVE_BINARIES,
            "min_positive_clusters": MIN_POSITIVE_CLUSTERS,
            "min_positive_families": MIN_POSITIVE_FAMILIES,
            "max_single_binary_share": MAX_SINGLE_BINARY_SHARE,
            "max_single_cluster_share": MAX_SINGLE_CLUSTER_SHARE,
        },
        "split_counts": {
            "main": main.get("counts"),
            "lofo": lofo.get("counts"),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "data/versions/v2/manifest.csv")
    parser.add_argument("--splits", type=Path, default=ROOT / "data/versions/v2/splits")
    parser.add_argument("--config", type=Path, default=ROOT / "configs/pilot_stage1.toml")
    parser.add_argument("--run-name", default="stage1_full_v2")
    parser.add_argument("--out", type=Path, default=ROOT / "results/full/frozen_run.json")
    parser.add_argument("--check", type=Path, help="verify against an existing freeze and exit")
    args = parser.parse_args(argv)

    manifest = _resolve(args.manifest)
    splits = _resolve(args.splits)
    config = _resolve(args.config)
    freeze = build_freeze(manifest, splits, config, run_name=args.run_name)

    if args.check:
        existing = json.loads(_resolve(args.check).read_text())
        mismatches = {
            key: {"expected": existing.get(key), "actual": freeze.get(key)}
            for key in (
                "manifest_sha256",
                "main_sha256",
                "lofo_sha256",
                "config_sha256",
                "clean_rows",
            )
            if existing.get(key) != freeze.get(key)
        }
        if mismatches:
            print(json.dumps({"ok": False, "mismatches": mismatches}, indent=2))
            return 1
        print(json.dumps({"ok": True, "run_name": freeze["run_name"]}, indent=2))
        return 0

    out = _resolve(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(freeze, indent=2) + "\n")
    print(
        json.dumps(
            {
                "out": str(out),
                "run_name": freeze["run_name"],
                "git_commit": freeze["git_commit"],
                "clean_rows": freeze["clean_rows"],
                "clean_clusters": freeze["clean_clusters"],
                "manifest_sha256": freeze["manifest_sha256"],
                "active_labels": freeze["label_contract"]["active_labels"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
