"""Evaluate the external collection probe against the frozen v2 quality gate.

Applies exactly the v2 Phase 0 filter (same thresholds, same code path) to the
external candidates, then reports the yield that matters for the anti_debug
diversity decision:

* how many candidates survive the data-quality gate;
* how many CAPA rules hit anti_debug / injection;
* how many of those fall in *previously unseen* imphash clusters;
* per-family and per-source breakdowns.

The go/no-go thresholds are pre-registered in the dataset contract and are not
adjusted here.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from src.collect.common import EXTERNAL_ROOT
from src.data.build_manifest import QualityConfig, analyze_file, load_bodmas_ids, load_families

ROOT = Path(__file__).resolve().parents[2]

# Pre-registered go/no-go for the anti_debug collection.
GO_MIN_NEW_POSITIVES = 75
GO_MIN_NEW_CLUSTERS = 5


def _existing_clusters() -> dict[str, str]:
    """cluster_key -> family, from the frozen v2 manifest."""

    path = ROOT / "data" / "versions" / "v2" / "manifest.csv"
    clusters: dict[str, str] = {}
    with path.open(newline="") as fh:
        for row in csv.DictReader(fh):
            if row.get("is_clean") != "1":
                continue
            clusters.setdefault(row["cluster_key"], row.get("family") or "unknown")
    return clusters


def evaluate(source_filter: str | None = None) -> dict[str, Any]:
    bodmas_ids = load_bodmas_ids(ROOT / "data" / "bodmas")
    families = load_families(ROOT / "data" / "bodmas")
    # v2 quality settings, unchanged.
    quality = QualityConfig(
        exclude_dotnet=True,
        exclude_packed=True,
        exclude_non_bodmas=False,  # external samples are expected here
        high_entropy_threshold=7.5,
        packed_entropy_threshold=7.8,
        packed_max_imports=20,
    )

    known_clusters = _existing_clusters()
    sources = [source_filter] if source_filter else ["malwarebazaar", "thezoo"]

    results: dict[str, Any] = {
        "existing_clean_clusters": len(known_clusters),
        "sources": {},
        "go_criteria": {
            "min_new_positives": GO_MIN_NEW_POSITIVES,
            "min_new_clusters": GO_MIN_NEW_CLUSTERS,
        },
    }

    all_new_positive_families: Counter[str] = Counter()
    all_new_positive_clusters: dict[str, set[str]] = defaultdict(set)
    all_positive_by_family: Counter[str] = Counter()
    all_clean_by_family: Counter[str] = Counter()
    all_total_by_family: Counter[str] = Counter()

    for source in sources:
        root = EXTERNAL_ROOT / source
        if not root.exists():
            results["sources"][source] = {"error": "no files"}
            continue

        total = 0
        clean = 0
        flags: Counter[str] = Counter()
        clean_rows: list[dict[str, Any]] = []

        for path in sorted(root.rglob("*.exe")):
            total += 1
            rel = path.relative_to(root)
            family_hint = rel.parts[0] if len(rel.parts) > 1 else "unknown"
            row = analyze_file(path, root, bodmas_ids, families, quality)
            row["family"] = family_hint
            row["source"] = source
            all_total_by_family[family_hint] += 1
            for flag in str(row["quality_flags"]).split(";"):
                if flag:
                    flags[flag] += 1
            if row["is_clean"]:
                clean += 1
                clean_rows.append(row)
                all_clean_by_family[family_hint] += 1

        clean_clusters = Counter(row["cluster_key"] for row in clean_rows)
        novel_clusters = {
            key for key in clean_clusters if key not in known_clusters
        }

        results["sources"][source] = {
            "total": total,
            "clean": clean,
            "pass_rate": round(clean / total, 4) if total else 0.0,
            "flags": dict(flags.most_common()),
            "clean_clusters": len(clean_clusters),
            "novel_clusters": len(novel_clusters),
            "families": len({row["family"] for row in clean_rows}),
            "top_clusters": [
                [key, count] for key, count in clean_clusters.most_common(5)
            ],
        }

    # CAPA hits are measured separately (see src/collect/probe_capa.py).

    results["clean_by_family"] = dict(all_clean_by_family.most_common())
    results["total_by_family"] = dict(all_total_by_family.most_common())
    return results


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", help="restrict to one source")
    parser.add_argument(
        "--out",
        type=Path,
        default=ROOT / "results" / "collect" / "probe_quality.json",
    )
    args = parser.parse_args(argv)

    payload = evaluate(args.source)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2) + "\n")
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
