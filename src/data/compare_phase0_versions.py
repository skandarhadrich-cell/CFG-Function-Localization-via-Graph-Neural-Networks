"""Compare frozen Phase 0 v1 and the v2 packed-filter revision.

This records every change needed to justify the revision: removed sample IDs,
cluster changes, split membership changes, and integrity checks.  v1 is never
modified; the script only reads it.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


def _resolve(path: str | Path) -> Path:
    path = Path(path).expanduser()
    return path if path.is_absolute() else ROOT / path


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rows(path: Path) -> dict[str, dict[str, str]]:
    with path.open(newline="") as fh:
        return {row["sample_id"]: row for row in csv.DictReader(fh)}


def _splits(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def _clean(rows: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    return {k: v for k, v in rows.items() if v.get("is_clean") == "1"}


def _bucket_counts(rows: dict[str, dict[str, str]]) -> dict[str, int]:
    return dict(Counter(row["source_bucket"] for row in rows.values()))


def _family_counts(rows: dict[str, dict[str, str]]) -> dict[str, int]:
    return dict(
        Counter(row["family"] or "unknown" for row in rows.values()).most_common()
    )


def _cluster_counts(rows: dict[str, dict[str, str]]) -> dict[str, int]:
    return dict(Counter(row["cluster_key"] for row in rows.values()))


def _split_change(
    v1_assign: dict[str, str], v2_assign: dict[str, str]
) -> dict[str, Any]:
    common = sorted(set(v1_assign) & set(v2_assign))
    same = [s for s in common if v1_assign[s] == v2_assign[s]]
    changed = [s for s in common if v1_assign[s] != v2_assign[s]]
    changed_pairs = Counter(
        f"{v1_assign[s]}->{v2_assign[s]}" for s in changed
    )
    v1_only = sorted(set(v1_assign) - set(v2_assign))
    v2_only = sorted(set(v2_assign) - set(v1_assign))
    v1_test = {s for s, split in v1_assign.items() if split == "test"}
    v2_test = {s for s, split in v2_assign.items() if split == "test"}
    return {
        "v1_assignments": len(v1_assign),
        "v2_assignments": len(v2_assign),
        "common_samples": len(common),
        "same_split": len(same),
        "changed_split": len(changed),
        "changed_pairs": dict(sorted(changed_pairs.items())),
        "v1_only_samples": v1_only,
        "v2_only_samples": v2_only,
        "test_overlap": len(v1_test & v2_test),
        "v1_test_only": len(v1_test - v2_test),
        "v2_test_only": len(v2_test - v1_test),
    }


def _cluster_integrity(
    rows: dict[str, dict[str, str]], assignments: dict[str, str]
) -> dict[str, Any]:
    split_by_cluster: dict[str, set[str]] = defaultdict(set)
    for sample_id, split in assignments.items():
        row = rows.get(sample_id)
        if row:
            split_by_cluster[row["cluster_key"]].add(split)
    crossing = {
        cluster: sorted(splits)
        for cluster, splits in sorted(split_by_cluster.items())
        if len(splits) > 1
    }
    return {
        "clusters": len(split_by_cluster),
        "crossing_clusters": crossing,
        "clean": not crossing,
    }


def build_report(v1_manifest: Path, v2_manifest: Path, v1_splits_dir: Path, v2_splits_dir: Path) -> dict[str, Any]:
    v1 = _rows(v1_manifest)
    v2 = _rows(v2_manifest)
    v1_clean = _clean(v1)
    v2_clean = _clean(v2)

    removed_ids = sorted(set(v1_clean) - set(v2_clean))
    added_ids = sorted(set(v2_clean) - set(v1_clean))
    removed = []
    for sample_id in removed_ids:
        old = v1_clean[sample_id]
        new = v2.get(sample_id, {})
        removed.append(
            {
                "sample_id": sample_id,
                "source_bucket": old.get("source_bucket"),
                "family": old.get("family"),
                "cluster_key": old.get("cluster_key"),
                "text_entropy": float(old.get("text_entropy") or 0),
                "num_imports": int(old.get("num_imports") or 0),
                "v2_packer_reason": new.get("packer_reason") or "",
                "v2_quality_flags": new.get("quality_flags") or "",
            }
        )

    v1_clusters = _cluster_counts(v1_clean)
    v2_clusters = _cluster_counts(v2_clean)
    clusters_lost = sorted(set(v1_clusters) - set(v2_clusters))
    clusters_partial = sorted(
        cluster
        for cluster in set(v1_clusters) & set(v2_clusters)
        if v1_clusters[cluster] != v2_clusters[cluster]
    )

    v1_main = _splits(v1_splits_dir / "main.json")
    v2_main = _splits(v2_splits_dir / "main.json")
    v1_lofo = _splits(v1_splits_dir / "lofo.json")
    v2_lofo = _splits(v2_splits_dir / "lofo.json")

    split_changes = {
        "main": _split_change(v1_main["assignments"], v2_main["assignments"]),
        "lofo": _split_change(v1_lofo["assignments"], v2_lofo["assignments"]),
    }
    integrity = {
        "main": _cluster_integrity(v2_clean, v2_main["assignments"]),
        "lofo": _cluster_integrity(v2_clean, v2_lofo["assignments"]),
    }

    v2_manifest_sha = _sha256(v2_manifest)
    split_sha_ok = all(
        payload.get("manifest_sha256") == v2_manifest_sha
        for payload in (v2_main, v2_lofo)
    )

    held_out_leak = {}
    for protocol, payload in (("main", v2_main), ("lofo", v2_lofo)):
        held = set((payload.get("held_out_families") or {}).values())
        if not held:
            held_out_leak[protocol] = {"held_out": [], "leaks": [], "clean": True}
            continue
        leaks = []
        for split in ("train", "val"):
            for sample_id, assigned in payload["assignments"].items():
                row = v2_clean.get(sample_id)
                if row and assigned == split and (row.get("family") or "") in held:
                    leaks.append({"sample_id": sample_id, "split": split})
        held_out_leak[protocol] = {
            "held_out": sorted(held),
            "leaks": leaks,
            "clean": not leaks,
        }

    return {
        "v1": {
            "manifest": str(v1_manifest),
            "manifest_sha256": _sha256(v1_manifest),
            "clean_samples": len(v1_clean),
            "clusters": len(v1_clusters),
            "buckets": _bucket_counts(v1_clean),
            "families": _family_counts(v1_clean),
        },
        "v2": {
            "manifest": str(v2_manifest),
            "manifest_sha256": v2_manifest_sha,
            "clean_samples": len(v2_clean),
            "clusters": len(v2_clusters),
            "buckets": _bucket_counts(v2_clean),
            "families": _family_counts(v2_clean),
            "main_counts": v2_main["counts"],
            "lofo_counts": v2_lofo["counts"],
            "lofo_held_out_families": v2_lofo.get("held_out_families"),
            "split_sha_matches_manifest": split_sha_ok,
        },
        "filter_change": {
            "rule": "text_entropy >= 7.8 and num_imports <= 20 (PE-only); CAPA packer rules are audit-only",
            "removed_samples": len(removed_ids),
            "added_samples": len(added_ids),
            "removed_ids": removed_ids,
            "added_ids": added_ids,
            "removed": removed,
            "removed_by_bucket": dict(Counter(item["source_bucket"] for item in removed)),
            "removed_by_family": dict(
                Counter(item["family"] or "unknown" for item in removed).most_common()
            ),
            "clusters_lost": clusters_lost,
            "clusters_partially_reduced": clusters_partial,
        },
        "split_changes": split_changes,
        "v2_cluster_integrity": integrity,
        "v2_held_out_leak_check": held_out_leak,
        "checks": {
            "v1_untouched_reference_sha256": _sha256(v1_manifest),
            "v2_splits_bind_to_v2_manifest": split_sha_ok,
            "v2_main_no_cluster_crossing": integrity["main"]["clean"],
            "v2_lofo_no_cluster_crossing": integrity["lofo"]["clean"],
            "v2_no_held_out_family_in_train_val": all(
                item["clean"] for item in held_out_leak.values()
            ),
            "v2_no_duplicate_content_sha256": len(
                {row.get("content_sha256") for row in v2_clean.values()}
            )
            == len(v2_clean),
        },
    }


def render_markdown(report: dict[str, Any]) -> str:
    v1 = report["v1"]
    v2 = report["v2"]
    fc = report["filter_change"]
    lines = [
        "# Phase 0 v1 -> v2 change report",
        "",
        "v1 is frozen and was not modified. v2 changes only the packed-sample",
        "quality filter; no compute-driven caps were added.",
        "",
        "## Corpus counts",
        "",
        "| Version | Clean samples | Clusters | SHA-256 |",
        "|---|---:|---:|---|",
        f"| v1 | {v1['clean_samples']} | {v1['clusters']} | `{v1['manifest_sha256'][:16]}...` |",
        f"| v2 | {v2['clean_samples']} | {v2['clusters']} | `{v2['manifest_sha256'][:16]}...` |",
        "",
        f"- v2 clean change: **{v2['clean_samples'] - v1['clean_samples']:+d}**",
        f"- Removed clean samples: **{fc['removed_samples']}**",
        f"- Added clean samples: **{fc['added_samples']}**",
        f"- Filter rule: `{fc['rule']}`",
        "",
        "### Removed by bucket",
        "",
        "| Bucket | Removed |",
        "|---|---:|",
    ]
    for bucket, count in sorted(fc["removed_by_bucket"].items()):
        lines.append(f"| `{bucket}` | {count} |")
    lines += [
        "",
        "### Removed by family (top 15)",
        "",
        "| Family | Removed |",
        "|---|---:|",
    ]
    for family, count in list(fc["removed_by_family"].items())[:15]:
        lines.append(f"| `{family}` | {count} |")
    lines += [
        "",
        f"- Clusters wholly removed: **{len(fc['clusters_lost'])}**",
        f"- Clusters reduced in size: **{len(fc['clusters_partially_reduced'])}**",
        "",
        "## Splits",
        "",
        "| Protocol | v1 counts | v2 counts | Common samples | Same split | Changed | Test overlap |",
        "|---|---|---|---:|---:|---:|---:|",
    ]
    for protocol in ("main", "lofo"):
        change = report["split_changes"][protocol]
        v1_counts = (
            json.loads((ROOT / "data/versions/v1" / "splits" / f"{protocol}.json").read_text())
            .get("counts", {})
        )
        v2_counts = (
            json.loads((ROOT / "data/versions/v2" / "splits" / f"{protocol}.json").read_text())
            .get("counts", {})
        )
        lines.append(
            f"| {protocol} | `{v1_counts}` | `{v2_counts}` | "
            f"{change['common_samples']} | {change['same_split']} | "
            f"{change['changed_split']} | {change['test_overlap']} |"
        )
    lines += [
        "",
        "## v2 integrity checks",
        "",
        f"- v2 splits bind to v2 manifest SHA: **{report['checks']['v2_splits_bind_to_v2_manifest']}**",
        f"- Main no cluster crossing splits: **{report['checks']['v2_main_no_cluster_crossing']}**",
        f"- LOFO no cluster crossing splits: **{report['checks']['v2_lofo_no_cluster_crossing']}**",
        f"- Held-out family only in test: **{report['checks']['v2_no_held_out_family_in_train_val']}**",
        f"- No duplicate content hashes among clean samples: **{report['checks']['v2_no_duplicate_content_sha256']}**",
        "",
        "LOFO held-out families (v2): "
        + ", ".join(
            f"`{bucket}={family}`"
            for bucket, family in (v2.get("lofo_held_out_families") or {}).items()
        ),
        "",
        "The keylogger LOFO entry is retained only for future work; keylogger is not",
        "an active Stage 1 target and is excluded from Stage 1 training/loss.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v1-manifest", type=Path, default=ROOT / "data/versions/v1/manifest.csv")
    parser.add_argument("--v2-manifest", type=Path, default=ROOT / "data/versions/v2/manifest.csv")
    parser.add_argument("--v1-splits", type=Path, default=ROOT / "data/versions/v1/splits")
    parser.add_argument("--v2-splits", type=Path, default=ROOT / "data/versions/v2/splits")
    parser.add_argument("--json-out", type=Path, default=ROOT / "results/phase0_v2/change_report.json")
    parser.add_argument("--md-out", type=Path, default=ROOT / "results/phase0_v2/change_report.md")
    args = parser.parse_args(argv)

    report = build_report(
        _resolve(args.v1_manifest),
        _resolve(args.v2_manifest),
        _resolve(args.v1_splits),
        _resolve(args.v2_splits),
    )
    json_out = _resolve(args.json_out)
    md_out = _resolve(args.md_out)
    json_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(report, indent=2) + "\n")
    md_out.write_text(render_markdown(report))
    print(json.dumps(report["checks"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
