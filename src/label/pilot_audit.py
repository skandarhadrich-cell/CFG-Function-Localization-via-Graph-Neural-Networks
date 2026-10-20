"""Prepare the pilot audit artifacts needed before the full run.

Two things happen here, both read-only with respect to labels:

1. **Collision inspection.**  From ``mapping.jsonl`` we select representative
   many-to-one collisions (one CAPA function merged into an angr function that
   already holds another) and dump enough context (angr func_va/span, the CAPA
   RVAs/rule names, matched block VAs) to judge whether unioning labels is
   safe.  A handful of pathological samples are included.

2. **Ghidra spot-check sheet.**  We pick 30-50 functions stratified by label,
   bucket, and status, and write a CSV/JSON sheet listing the angr function VA,
   the CAPA rules that matched, the mapping method, and the sample file path.
   A human then opens those functions in Ghidra and records agreement.

Nothing here runs Ghidra itself; it produces the worklist.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


def _resolve(path: str | Path) -> Path:
    path = Path(path).expanduser()
    return path if path.is_absolute() else ROOT / path


def _load_mapping(path: Path) -> list[dict[str, Any]]:
    payloads = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        payloads.append(json.loads(line))
    return payloads


def _manifest(path: Path) -> dict[str, dict[str, str]]:
    with path.open(newline="") as fh:
        return {row["sample_id"]: row for row in csv.DictReader(fh)}


def select_collisions(
    payloads: list[dict[str, Any]],
    manifest: dict[str, dict[str, str]],
    limit: int = 25,
) -> dict[str, Any]:
    samples_with_collisions: list[dict[str, Any]] = []
    for payload in payloads:
        rows = payload.get("mapping", {}).get("rows", [])
        collisions = [row for row in rows if row.get("mapping_collision")]
        if not collisions:
            continue
        positive_collisions = [
            row for row in collisions if row.get("label_status") == "positive"
        ]
        samples_with_collisions.append(
            {
                "sample_id": payload["sample_id"],
                "source_bucket": manifest.get(payload["sample_id"], {}).get("source_bucket"),
                "family": manifest.get(payload["sample_id"], {}).get("family"),
                "collisions": len(collisions),
                "positive_collisions": len(positive_collisions),
            }
        )
    samples_with_collisions.sort(
        key=lambda item: (-item["positive_collisions"], -item["collisions"])
    )

    representative: list[dict[str, Any]] = []
    for payload in payloads:
        for row in payload.get("mapping", {}).get("rows", []):
            if not row.get("mapping_collision"):
                continue
            representative.append(
                {
                    "sample_id": payload["sample_id"],
                    "source_bucket": manifest.get(payload["sample_id"], {}).get("source_bucket"),
                    "family": manifest.get(payload["sample_id"], {}).get("family"),
                    "func_va": row.get("func_va"),
                    "capa_func_va": row.get("capa_func_va"),
                    "capa_func_vas": row.get("capa_func_vas"),
                    "label_status": row.get("label_status"),
                    "label_anti_debug": row.get("label_anti_debug"),
                    "label_injection": row.get("label_injection"),
                    "matched_rules": row.get("matched_rules"),
                    "matched_block_vas": row.get("matched_block_vas"),
                    "mapping_method": row.get("mapping_method"),
                }
            )
    # Prefer collisions whose rows carry positive labels.
    representative.sort(
        key=lambda item: (
            item["label_status"] != "positive",
            -len(item.get("matched_rules") or []),
        )
    )

    total_collision_rows = sum(item["collisions"] for item in samples_with_collisions)
    return {
        "samples_with_collisions": len(samples_with_collisions),
        "total_collision_rows": total_collision_rows,
        "top_samples": samples_with_collisions[:limit],
        "representative_collisions": representative[:limit],
    }


def build_audit_sheet(
    payloads: list[dict[str, Any]],
    manifest: dict[str, dict[str, str]],
    *,
    size: int = 40,
    seed: int = 42,
    active_labels: tuple[str, ...] = ("anti_debug", "injection"),
) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    pools: dict[str, list[dict[str, Any]]] = defaultdict(list)
    per_sample_positive: Counter[str] = Counter()

    for payload in payloads:
        sample_id = payload["sample_id"]
        meta = manifest.get(sample_id, {})
        for row in payload.get("mapping", {}).get("rows", []):
            labels = [
                label
                for label in active_labels
                if int(row.get(f"label_{label}", 0) or 0) > 0
            ]
            status = row.get("label_status")
            if labels:
                per_sample_positive[sample_id] += 1
                for label in labels:
                    pools[f"positive:{label}"].append(
                        {
                            "sample_id": sample_id,
                            "func_va": row.get("func_va"),
                            "labels": labels,
                            "matched_rules": row.get("matched_rules"),
                            "mapping_method": row.get("mapping_method"),
                        }
                    )
            elif status == "weak_negative":
                pools[f"weak_negative:{meta.get('source_bucket')}"].append(
                    {
                        "sample_id": sample_id,
                        "func_va": row.get("func_va"),
                        "labels": [],
                        "matched_rules": [],
                        "mapping_method": row.get("mapping_method"),
                    }
                )
        for row in payload.get("mapping", {}).get("rows", []):
            if row.get("mapping_method") == "containment":
                pools["containment"].append(
                    {
                        "sample_id": sample_id,
                        "func_va": row.get("func_va"),
                        "labels": [
                            label
                            for label in active_labels
                            if int(row.get(f"label_{label}", 0) or 0) > 0
                        ],
                        "matched_rules": row.get("matched_rules"),
                        "mapping_method": "containment",
                    }
                )
                break

    categories = [
        "positive:anti_debug",
        "positive:injection",
        "weak_negative:keylogger",
        "weak_negative:injection",
        "weak_negative:antidebug",
        "containment",
    ]
    selected: list[dict[str, Any]] = []
    used: set[tuple[str, Any]] = set()
    per_category = max(1, size // len(categories))
    for category in categories:
        pool = pools.get(category) or []
        rng.shuffle(pool)
        taken = 0
        for item in pool:
            key = (item["sample_id"], item["func_va"])
            if key in used:
                continue
            used.add(key)
            meta = manifest.get(item["sample_id"], {})
            selected.append(
                {
                    "category": category,
                    "sample_id": item["sample_id"],
                    "filepath": meta.get("filepath"),
                    "source_bucket": meta.get("source_bucket"),
                    "family": meta.get("family"),
                    "cluster_key": meta.get("cluster_key"),
                    "func_va": item["func_va"],
                    "labels": item["labels"],
                    "matched_rules": item["matched_rules"],
                    "mapping_method": item["mapping_method"],
                    "audit_verdict": "",
                    "audit_notes": "",
                }
            )
            taken += 1
            if taken >= per_category:
                break

    # Fill to `size` from remaining positives first, then weak negatives.
    all_pools = [item for pool in pools.values() for item in pool]
    rng.shuffle(all_pools)
    for item in all_pools:
        if len(selected) >= size:
            break
        key = (item["sample_id"], item["func_va"])
        if key in used:
            continue
        used.add(key)
        meta = manifest.get(item["sample_id"], {})
        selected.append(
            {
                "category": "fill",
                "sample_id": item["sample_id"],
                "filepath": meta.get("filepath"),
                "source_bucket": meta.get("source_bucket"),
                "family": meta.get("family"),
                "cluster_key": meta.get("cluster_key"),
                "func_va": item["func_va"],
                "labels": item["labels"],
                "matched_rules": item["matched_rules"],
                "mapping_method": item["mapping_method"],
                "audit_verdict": "",
                "audit_notes": "",
            }
        )
    return selected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mapping", type=Path, default=ROOT / "results/stage1/mapping.jsonl")
    parser.add_argument("--manifest", type=Path, default=ROOT / "data/versions/v2/manifest.csv")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "results/stage1")
    parser.add_argument("--audit-size", type=int, default=40)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)

    mapping_path = _resolve(args.mapping)
    if not mapping_path.exists():
        raise SystemExit(f"mapping not found: {mapping_path}")
    payloads = _load_mapping(mapping_path)
    manifest = _manifest(_resolve(args.manifest))
    out_dir = _resolve(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    collisions = select_collisions(payloads, manifest)
    (out_dir / "collision_inspection.json").write_text(
        json.dumps(collisions, indent=2) + "\n"
    )

    sheet = build_audit_sheet(payloads, manifest, size=args.audit_size, seed=args.seed)
    sheet_path = out_dir / "ghidra_audit_sheet.csv"
    fields = [
        "category",
        "sample_id",
        "filepath",
        "source_bucket",
        "family",
        "cluster_key",
        "func_va",
        "labels",
        "matched_rules",
        "mapping_method",
        "audit_verdict",
        "audit_notes",
    ]
    with sheet_path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for row in sheet:
            row = dict(row)
            row["labels"] = ";".join(row["labels"] or [])
            row["matched_rules"] = ";".join(row["matched_rules"] or [])
            writer.writerow(row)
    (out_dir / "ghidra_audit_sheet.json").write_text(json.dumps(sheet, indent=2) + "\n")

    print(
        json.dumps(
            {
                "mapping_samples": len(payloads),
                "collision_samples": collisions["samples_with_collisions"],
                "collision_rows": collisions["total_collision_rows"],
                "audit_functions": len(sheet),
                "sheet": str(sheet_path),
                "collisions": str(out_dir / "collision_inspection.json"),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
