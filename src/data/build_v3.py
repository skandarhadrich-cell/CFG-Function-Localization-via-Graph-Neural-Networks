"""Build the v3 manifest and splits: frozen v2 clean set + accepted external samples.

Design constraints, in priority order:

1. **v2 is immutable.** The v2 manifest and splits are read, never written. v3
   is a new versioned directory.
2. **The v2 test set is frozen byte-identical.** Every sample that v2 assigns to
   ``test`` keeps that assignment, and no external sample may enter test.
3. **External samples go to train/val only.** They extend coverage for training;
   they must never change the evaluation set, so previously reported numbers
   stay comparable.
4. **Near-duplicates never cross splits.** An external sample whose imphash
   cluster already appears in the v2 *test* set is **dropped** (logged as
   ``cluster_conflict_test``) rather than placed in train, which would leak a
   near-duplicate of a test sample into training.
5. **No presumed labels.** External ``source_bucket`` is ``external`` for every
   row. Bucket is stratification metadata and must not smuggle in a guess about
   which capability a family implements.
6. **Provenance is preserved.** A ``source`` column records
   ``bodmas`` / ``malwarebazaar`` / ``thezoo`` per sample.

Usage::

    python -m src.data.build_v3 --external malwarebazaar --dry-run
    python -m src.data.build_v3 --external malwarebazaar --write
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from src.collect.common import EXTERNAL_ROOT
from src.data.build_manifest import (
    ROOT,
    QualityConfig,
    analyze_file,
    load_bodmas_ids,
    load_families,
)

V3_DIR = ROOT / "data" / "versions" / "v3"
V2_DIR = ROOT / "data" / "versions" / "v2"

MANIFEST_FIELDS = [
    "sample_id",
    "filepath",
    "source",
    "source_bucket",
    "family",
    "in_bodmas",
    "content_sha256",
    "imphash",
    "cluster_key",
    "arch",
    "original_machine",
    "original_subsystem",
    "optional_magic",
    "repair_needed",
    "is_dotnet",
    "is_packed",
    "packer_reason",
    "text_entropy",
    "num_sections",
    "num_imports",
    "size",
    "quality_flags",
    "is_clean",
]


def _quality_config() -> QualityConfig:
    """The v2 quality settings, with the BODMAS-only gate disabled."""

    return QualityConfig(
        exclude_dotnet=True,
        exclude_packed=True,
        exclude_non_bodmas=False,
        high_entropy_threshold=7.5,
        packed_entropy_threshold=7.8,
        packed_max_imports=20,
    )


def load_v2_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with (V2_DIR / "manifest.csv").open(newline="") as fh:
        for row in csv.DictReader(fh):
            row["source"] = "bodmas"
            rows.append(dict(row))
    return rows


def load_v2_splits() -> tuple[dict[str, str], dict[str, str]]:
    main = json.loads((V2_DIR / "splits" / "main.json").read_text())
    lofo = json.loads((V2_DIR / "splits" / "lofo.json").read_text())
    return main["assignments"], lofo["assignments"]


def collect_external(sources: list[str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    bodmas_ids = load_bodmas_ids(ROOT / "data" / "bodmas")
    families = load_families(ROOT / "data" / "bodmas")
    quality = _quality_config()

    rows: list[dict[str, Any]] = []
    stats: dict[str, Any] = {"total": 0, "clean": 0, "excluded": 0, "by_source": {}}

    for source in sources:
        root = EXTERNAL_ROOT / source
        if not root.exists():
            continue
        source_stats = {"total": 0, "clean": 0}
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.name.startswith("."):
                continue
            rel = path.relative_to(root)
            family_hint = rel.parts[0] if len(rel.parts) > 1 else "unknown"

            row = analyze_file(path, root, bodmas_ids, families, quality)
            row["source"] = source
            # Stratification bucket is deliberately neutral for external data.
            row["source_bucket"] = "external"
            row["family"] = family_hint

            stats["total"] += 1
            source_stats["total"] += 1
            if row["is_clean"]:
                rows.append(row)
                stats["clean"] += 1
                source_stats["clean"] += 1
            else:
                stats["excluded"] += 1
        stats["by_source"][source] = source_stats

    return rows, stats


def assign_external_splits(
    external_rows: list[dict[str, Any]],
    v2_rows: list[dict[str, Any]],
    v2_main: dict[str, str],
) -> tuple[dict[str, str], dict[str, Any]]:
    """Assign external samples to train/val, cluster-safely.

    A cluster that already exists in the v2 test set causes the external sample
    to be dropped: placing it in train would put a near-duplicate of a test
    sample into the training set.
    """

    v2_by_sample = {row["sample_id"]: row for row in v2_rows}
    test_clusters = {
        v2_by_sample[sid]["cluster_key"]
        for sid, split in v2_main.items()
        if split == "test" and sid in v2_by_sample
    }

    # Existing v2 clusters and the split they live in, for cluster-safe joining.
    cluster_split: dict[str, str] = {}
    for sid, split in v2_main.items():
        row = v2_by_sample.get(sid)
        if row is None:
            continue
        cluster_split.setdefault(row["cluster_key"], split)

    assignments: dict[str, str] = {}
    dropped_test_conflict: list[str] = []
    joined_existing: Counter[str] = Counter()

    by_cluster: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in external_rows:
        by_cluster[row["cluster_key"]].append(row)

    # Split external clusters into: conflicts with test (drop), joins of an
    # existing v2 train/val cluster (follow it), and genuinely new clusters.
    new_clusters: list[tuple[str, list[dict[str, Any]]]] = []
    for key, members in sorted(by_cluster.items()):
        if key in test_clusters:
            dropped_test_conflict.extend(row["sample_id"] for row in members)
            continue
        if key in cluster_split and cluster_split[key] in {"train", "val"}:
            for row in members:
                assignments[row["sample_id"]] = cluster_split[key]
            joined_existing[cluster_split[key]] += len(members)
            continue
        new_clusters.append((key, members))

    # Assign new clusters 70/15/0 across train/val only. The largest cluster
    # goes to train, matching the v2 assigner's behaviour.
    ratios = {"train": 0.70, "val": 0.15}
    total = sum(len(members) for _, members in new_clusters)
    current = {"train": 0, "val": 0}
    ordered = sorted(new_clusters, key=lambda kv: (-len(kv[1]), kv[0]))
    for index, (_, members) in enumerate(ordered):
        if index == 0:
            split = "train"
        else:
            split = max(ratios, key=lambda name: ratios[name] * total - current[name])
        for row in members:
            assignments[row["sample_id"]] = split
        current[split] += len(members)

    summary = {
        "external_assigned": len(assignments),
        "external_dropped_cluster_conflict_with_test": len(dropped_test_conflict),
        "dropped_sample_ids": dropped_test_conflict,
        "joined_existing_v2_cluster": dict(joined_existing),
        "new_clusters_assigned": len(ordered),
        "split_counts": dict(current),
        "test_clusters_locked": len(test_clusters),
    }
    return assignments, summary


def verify_no_leak(rows: list[dict[str, Any]], assignments: dict[str, str]) -> None:
    by_sample = {row["sample_id"]: row for row in rows}
    seen: dict[str, set[str]] = defaultdict(set)
    for sid, split in assignments.items():
        row = by_sample.get(sid)
        if row is None:
            raise ValueError(f"assignment for unknown sample {sid}")
        seen[row["cluster_key"]].add(split)
    leaking = {key: splits for key, splits in seen.items() if len(splits) > 1}
    if leaking:
        raise ValueError(
            f"{len(leaking)} clusters cross splits, e.g. {next(iter(leaking.items()))}"
        )


def verify_v2_test_frozen(
    v2_rows: list[dict[str, Any]],
    v2_main: dict[str, str],
    v3_assignments: dict[str, str],
) -> dict[str, Any]:
    v2_test = {sid for sid, split in v2_main.items() if split == "test"}
    v3_test = {sid for sid, split in v3_assignments.items() if split == "test"}
    if v2_test != v3_test:
        missing = v2_test - v3_test
        extra = v3_test - v2_test
        raise ValueError(
            f"v2 test set changed: missing={len(missing)} extra={len(extra)}"
        )
    return {"v2_test_size": len(v2_test), "identical": True}


def write_manifest(rows: list[dict[str, Any]], path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=MANIFEST_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in MANIFEST_FIELDS})
    os.replace(tmp, path)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(
    external_sources: list[str],
    *,
    write: bool,
) -> dict[str, Any]:
    v2_rows = load_v2_rows()
    v2_main, v2_lofo = load_v2_splits()
    v2_clean = [row for row in v2_rows if row["is_clean"] == "1"]

    external_all, ext_stats = collect_external(external_sources)
    ext_assign, ext_summary = assign_external_splits(external_all, v2_rows, v2_main)

    # External samples that were dropped for test-cluster conflict are excluded
    # from the manifest entirely, so they cannot be trained on.
    kept_external = [row for row in external_all if row["sample_id"] in ext_assign]
    dropped = set(row["sample_id"] for row in external_all) - set(ext_assign)

    all_rows = v2_rows + kept_external
    # Clean set = v2 clean + kept external (all of which passed the gate).
    clean_rows = [row for row in v2_clean if row["is_clean"] == "1"] + kept_external

    v3_main = dict(v2_main)
    v3_main.update(ext_assign)
    v3_lofo = dict(v2_lofo)
    v3_lofo.update(ext_assign)

    verify_no_leak(all_rows, v3_main)
    test_check = verify_v2_test_frozen(v2_rows, v2_main, v3_main)

    # LOFO held-out families must stay test-only.
    lofo_held = json.loads((V2_DIR / "splits" / "lofo.json").read_text()).get(
        "held_out_families", {}
    )
    bad = [
        sid
        for sid, split in v3_lofo.items()
        if split != "test" and _family_of(all_rows, sid) in set(lofo_held.values())
    ]
    if bad:
        raise ValueError(f"{len(bad)} held-out-family samples not in test")

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    main_payload = {
        "protocol": "main",
        "version": 1,
        "created_utc": now,
        "base_version": "v2",
        "external_sources": external_sources,
        "counts": dict(Counter(v3_main.values())),
        **ext_summary,
        "assignments": dict(sorted(v3_main.items())),
    }
    lofo_payload = {
        "protocol": "lofo",
        "version": 1,
        "created_utc": now,
        "base_version": "v2",
        "external_sources": external_sources,
        "held_out_families": lofo_held,
        "counts": dict(Counter(v3_lofo.values())),
        **ext_summary,
        "assignments": dict(sorted(v3_lofo.items())),
    }

    if write:
        V3_DIR.mkdir(parents=True, exist_ok=True)
        _write_json(V3_DIR / "splits" / "main.json", main_payload)
        _write_json(V3_DIR / "splits" / "lofo.json", lofo_payload)

        # Manifest is written last; splits reference this hash.
        main_sha = hashlib.sha256(
            (V3_DIR / "splits" / "main.json").read_bytes()
        ).hexdigest()
        lofo_sha = hashlib.sha256(
            (V3_DIR / "splits" / "lofo.json").read_bytes()
        ).hexdigest()
        for payload in (main_payload, lofo_payload):
            payload["v3_splits_main_sha256"] = main_sha
            payload["v3_splits_lofo_sha256"] = lofo_sha

        manifest_sha = write_manifest(all_rows, V3_DIR / "manifest.csv")
        _write_json(
            V3_DIR / "build_summary.json",
            {
                "created_utc": now,
                "base_version": "v2",
                "v2_clean_rows": len(v2_clean),
                "external_gate_stats": ext_stats,
                "external_assignment": ext_summary,
                "external_dropped_total": len(dropped),
                "v2_test_frozen": test_check,
                "manifest_rows": len(all_rows),
                "clean_rows": len(clean_rows),
                "clean_clusters": len({row["cluster_key"] for row in clean_rows}),
                "main_counts": dict(Counter(v3_main.values())),
                "manifest_sha256": manifest_sha,
                "splits_main_sha256": main_sha,
                "splits_lofo_sha256": lofo_sha,
            },
        )

    return {
        "v2_clean": len(v2_clean),
        "external_candidates": len(external_all),
        "external_kept": len(kept_external),
        "external_dropped": len(dropped),
        "external_assignment": ext_summary,
        "v2_test_frozen": test_check,
        "clean_rows": len(clean_rows),
        "clean_clusters": len({row["cluster_key"] for row in clean_rows}),
        "main_counts": dict(Counter(v3_main.values())),
        "by_source": dict(Counter(row["source"] for row in clean_rows)),
        "written": write,
    }


def _family_of(rows: list[dict[str, Any]], sample_id: str) -> str:
    for row in rows:
        if row["sample_id"] == sample_id:
            return row.get("family") or "unknown"
    return "unknown"


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n")
    os.replace(tmp, path)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--external",
        nargs="+",
        default=["malwarebazaar"],
        help="external sources to include (thezoo is not viable; see PROBE_FINDINGS.md)",
    )
    parser.add_argument("--write", action="store_true", help="write data/versions/v3")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    result = build(args.external, write=args.write)
    print(json.dumps(result, indent=2))
    if not args.write:
        print("\n[dry-run] nothing written; pass --write to create data/versions/v3")
    return 0


if __name__ == "__main__":
    sys.exit(main())
