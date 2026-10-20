"""Flatten per-sample mapping payloads into the function-label table.

The mapping JSONL stores one sample per line with a nested ``rows`` list.  This
step is kept separate so the angr extraction can resume without rewriting the
final table, and so label-table metadata can be regenerated cheaply.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

import pandas as pd

from src.label.contract import ACTIVE_LABELS, LABEL_CONTRACT_VERSION

ROOT = Path(__file__).resolve().parents[2]
LIST_FIELDS = ("capa_func_vas", "matched_rules", "matched_block_vas")


def _resolve(path: str | Path) -> Path:
    path = Path(path).expanduser()
    return path if path.is_absolute() else ROOT / path


def _manifest(manifest: Path) -> dict[str, dict[str, str]]:
    with manifest.open(newline="") as fh:
        return {row["sample_id"]: row for row in csv.DictReader(fh)}


def _splits(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    return json.loads(path.read_text()).get("assignments", {})


def load_rows(mapping_path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in mapping_path.read_text().splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        sample_rows = payload.get("rows") or payload.get("mapping", {}).get("rows", [])
        rows.extend(sample_rows)
    return rows


def build_table(
    mapping_path: Path,
    manifest_path: Path,
    splits_path: Path,
    *,
    active_labels: tuple[str, ...] = ACTIVE_LABELS,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    rows = load_rows(mapping_path)
    manifest = _manifest(manifest_path)
    assignments = _splits(splits_path)
    for row in rows:
        meta = manifest.get(row["sample_id"], {})
        row["sample_sha256"] = meta.get("content_sha256")
        row["source_bucket"] = meta.get("source_bucket")
        row["family"] = meta.get("family")
        row["cluster_key"] = meta.get("cluster_key")
        row["split"] = assignments.get(row["sample_id"])
        for field in LIST_FIELDS:
            value = row.get(field)
            if value is None:
                row[field] = []
            elif not isinstance(value, list):
                row[field] = [value]

    raw_frame = pd.DataFrame(rows)
    for label in active_labels:
        column = f"label_{label}"
        raw_frame[column] = pd.to_numeric(
            raw_frame[column] if column in raw_frame else 0, errors="coerce"
        ).fillna(0).astype(int)
    mapped = raw_frame.get("mapping_method", "").astype(str) != "unmapped"
    any_active = raw_frame[[f"label_{label}" for label in active_labels]].sum(axis=1) > 0
    raw_frame["label_status"] = "weak_negative"
    raw_frame.loc[~mapped, "label_status"] = "unlabeled"
    raw_frame.loc[mapped & any_active, "label_status"] = "positive"
    raw_frame["label_mask"] = 0
    for bit, label in enumerate(active_labels):
        raw_frame.loc[raw_frame[f"label_{label}"] > 0, "label_mask"] |= 1 << bit

    columns = [
        "sample_id",
        "func_va",
        "capa_func_va",
        "capa_func_vas",
        *[f"label_{label}" for label in active_labels],
        "label_status",
        "label_mask",
        "matched_rules",
        "matched_block_vas",
        "mapping_method",
        "mapping_collision",
        "source_bucket",
        "family",
        "cluster_key",
        "split",
    ]
    frame = raw_frame.copy()
    for column in columns:
        if column not in frame:
            frame[column] = None
    frame = frame[columns].sort_values(["sample_id", "func_va"]).reset_index(drop=True)

    label_summary: dict[str, dict[str, Any]] = {}
    for label in active_labels:
        positive = frame[frame[f"label_{label}"] > 0]
        total = int(positive[f"label_{label}"].sum())
        by_binary = positive.groupby("sample_id")[f"label_{label}"].sum()
        by_cluster = positive.groupby("cluster_key")[f"label_{label}"].sum()
        by_family = positive.groupby("family")[f"label_{label}"].sum()
        label_summary[label] = {
            "positive_functions": total,
            "positive_binaries": int(by_binary.shape[0]),
            "positive_clusters": int(by_cluster.shape[0]),
            "positive_families": int(by_family.shape[0]),
            "top_binary_share": (
                float(by_binary.max() / total) if total and len(by_binary) else 0.0
            ),
            "top_cluster_share": (
                float(by_cluster.max() / total) if total and len(by_cluster) else 0.0
            ),
        }

    summary = {
        "samples": int(frame["sample_id"].nunique()),
        "functions": int(len(frame)),
        "active_labels": list(active_labels),
        "status_counts": {
            str(key): int(value)
            for key, value in frame["label_status"].value_counts().items()
        },
        "label_counts": {
            label: int(frame[f"label_{label}"].sum())
            for label in active_labels
        },
        "label_diversity": label_summary,
        "keylogger_evidence_functions": (
            int(pd.to_numeric(raw_frame.get("label_keylogger", 0), errors="coerce").fillna(0).sum())
            if "label_keylogger" in raw_frame
            else 0
        ),
        "mapping_method_counts": {
            str(key): int(value)
            for key, value in frame["mapping_method"].value_counts().items()
        },
        "collisions": int(frame["mapping_collision"].sum()),
        "by_bucket": {
            str(bucket): {
                "functions": int(len(group)),
                "positive": int((group["label_status"] == "positive").sum()),
                "weak_negative": int((group["label_status"] == "weak_negative").sum()),
                "unlabeled": int((group["label_status"] == "unlabeled").sum()),
            }
            for bucket, group in frame.groupby("source_bucket", dropna=False)
        },
    }
    return frame, summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Flatten mapping JSONL into the label table.")
    parser.add_argument("--mapping", type=Path, default=ROOT / "results/pilot/mapping.jsonl")
    parser.add_argument("--manifest", type=Path, default=ROOT / "data/versions/v2/manifest.csv")
    parser.add_argument("--splits", type=Path, default=ROOT / "data/versions/v2/splits/main.json")
    parser.add_argument("--out-prefix", type=Path, default=ROOT / "data/labels/function_labels")
    parser.add_argument("--format", choices=("csv", "parquet", "both"), default="both")
    args = parser.parse_args(argv)

    mapping_path = _resolve(args.mapping)
    out_prefix = _resolve(args.out_prefix)
    out_prefix.parent.mkdir(parents=True, exist_ok=True)
    frame, summary = build_table(
        mapping_path,
        _resolve(args.manifest),
        _resolve(args.splits),
    )

    if args.format in {"csv", "both"}:
        csv_path = out_prefix.with_suffix(".csv")
        csv_frame = frame.copy()
        for field in LIST_FIELDS:
            csv_frame[field] = csv_frame[field].map(json.dumps)
        csv_frame.to_csv(csv_path, index=False)
        summary["csv"] = str(csv_path)

    if args.format in {"parquet", "both"}:
        parquet_path = out_prefix.with_suffix(".parquet")
        try:
            frame.to_parquet(parquet_path, index=False)
            summary["parquet"] = str(parquet_path)
        except ImportError as exc:
            summary["parquet_error"] = f"{type(exc).__name__}: {exc}"
            print(f"warning: parquet not written: {exc}", file=sys.stderr)

    meta_path = out_prefix.with_suffix(".meta.json")
    meta = {
        "label_contract_version": LABEL_CONTRACT_VERSION,
        "active_labels": list(ACTIVE_LABELS),
        "keylogger_in_stage1": False,
        "label_normalization": "capa addresses normalized to RVA; angr func_va/mapped_block_vas absolute",
        "source_mapping": str(mapping_path),
        **summary,
    }
    meta_path.write_text(json.dumps(meta, indent=2) + "\n")
    print(json.dumps(meta, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
