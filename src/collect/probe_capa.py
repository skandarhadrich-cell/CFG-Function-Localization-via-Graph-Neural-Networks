"""Run CAPA over the external probe candidates and measure anti_debug yield.

This is the go/no-go measurement for the anti_debug collection.  It uses the
same CAPA build, rule commit, and parser as the frozen pipeline, so labels are
directly comparable.

For each candidate it records:

* whether CAPA produced output at all;
* how many functions carry each active label;
* the imphash cluster of the sample, flagged as *novel* when it does not
  already exist in the frozen v2 manifest.

The go/no-go bar is pre-registered in :mod:`src.collect.probe_gate` and is not
adjusted here.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import tomllib
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Iterable

from src.collect.common import EXTERNAL_ROOT
from src.collect.probe_gate import _existing_clusters
from src.data.build_manifest import QualityConfig, analyze_file, load_bodmas_ids, load_families
from src.label.parse_capa import parse_capa_file
from src.label.run_capa import Sample, run_one

ROOT = Path(__file__).resolve().parents[2]


def _quality_config() -> QualityConfig:
    return QualityConfig(
        exclude_dotnet=True,
        exclude_packed=True,
        exclude_non_bodmas=False,
        high_entropy_threshold=7.5,
        packed_entropy_threshold=7.8,
        packed_max_imports=20,
    )


def candidates(source: str) -> list[dict[str, Any]]:
    bodmas_ids = load_bodmas_ids(ROOT / "data" / "bodmas")
    families = load_families(ROOT / "data" / "bodmas")
    quality = _quality_config()
    root = EXTERNAL_ROOT / source
    if not root.exists():
        return []

    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name.startswith("."):
            continue
        rel = path.relative_to(root)
        family_hint = rel.parts[0] if len(rel.parts) > 1 else "unknown"
        row = analyze_file(path, root, bodmas_ids, families, quality)
        row["family"] = family_hint
        row["source"] = source
        if row["is_clean"]:
            rows.append(row)
    return rows


def _load_config() -> dict[str, Any]:
    return tomllib.loads((ROOT / "configs" / "phase0_v2.toml").read_text())


class _ProbeSample(Sample):
    """``Sample`` with a settable sample_id (hash is the identity here)."""


def run_capa(rows: list[dict[str, Any]], workers: int, timeout: int) -> dict[str, Any]:
    cfg = _load_config()
    tools = cfg["tools"]
    capa = Path(tools["capa"]).expanduser()
    rules = Path(tools["capa_rules"]).expanduser()
    out_dir = ROOT / "data" / "labels" / "capa_external_probe"
    scratch = ROOT / "data" / "scratch_external_probe"
    out_dir.mkdir(parents=True, exist_ok=True)
    scratch.mkdir(parents=True, exist_ok=True)

    samples = [
        Sample(
            sample_id=row["sample_id"],
            filepath=row["filepath"],
            source_bucket=row["source_bucket"],
            family=row["family"],
            cluster_key=row["cluster_key"],
            content_sha256=row["content_sha256"],
        )
        for row in rows
    ]

    results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(run_one, s, out_dir, scratch, capa, rules, timeout, False): s
            for s in samples
        }
        for future in as_completed(futures):
            sample = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:  # noqa: BLE001
                failures.append({"sample_id": sample.sample_id, "error": repr(exc)})

    return {
        "requested": len(samples),
        "completed": len(results),
        "failures": failures,
        "capa_dir": str(out_dir),
    }


def evaluate_labels(rows: list[dict[str, Any]]) -> dict[str, Any]:
    known = _existing_clusters()
    capa_dir = ROOT / "data" / "labels" / "capa_external_probe"

    per_label: dict[str, Any] = {}
    novel_families: Counter[str] = Counter()
    novel_clusters: dict[str, set[str]] = defaultdict(set)
    hit_binaries: dict[str, set[str]] = defaultdict(set)

    positives: dict[str, Counter[str]] = {label: Counter() for label in ("anti_debug", "injection")}
    total_functions = 0
    parsed = 0
    parse_failed: list[str] = []

    for row in rows:
        path = capa_dir / f"{row['sample_id']}.json"
        if not path.exists():
            continue
        try:
            result = parse_capa_file(path, sample_id=row["sample_id"])
        except Exception as exc:  # noqa: BLE001
            parse_failed.append(f"{row['sample_id']}: {exc}")
            continue
        parsed += 1
        total_functions += len(result.functions or [])
        for label in positives:
            count = int(result.label_counts.get(label, 0))
            if count <= 0:
                continue
            positives[label][row["family"]] += count
            hit_binaries[label].add(row["sample_id"])
            if row["cluster_key"] not in known:
                novel_clusters[label].add(row["cluster_key"])
                novel_families[label] += count

    for label in positives:
        total = sum(positives[label].values())
        per_label[label] = {
            "positive_functions": total,
            "positive_binaries": len(hit_binaries[label]),
            "families": len(positives[label]),
            "by_family": dict(positives[label].most_common()),
            "novel_clusters": len(novel_clusters[label]),
            "novel_cluster_keys": sorted(novel_clusters[label])[:40],
        }

    return {
        "parsed_samples": parsed,
        "parse_failed": parse_failed,
        "clean_functions_total": total_functions,
        "labels": per_label,
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source", default="malwarebazaar", choices=["malwarebazaar", "thezoo"]
    )
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--skip-capa", action="store_true")
    parser.add_argument(
        "--out", type=Path, default=ROOT / "results" / "collect" / "probe_labels.json"
    )
    args = parser.parse_args(argv)

    rows = candidates(args.source)
    run_stats = None
    if not args.skip_capa:
        run_stats = run_capa(rows, args.workers, args.timeout)

    payload = {
        "source": args.source,
        "clean_candidates": len(rows),
        "clean_clusters": len({r["cluster_key"] for r in rows}),
        "run": run_stats,
        **evaluate_labels(rows),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2) + "\n")
    print(json.dumps({k: v for k, v in payload.items() if k != "labels"}, indent=2))
    print(json.dumps(payload["labels"], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
