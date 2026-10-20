"""Cross-version sample coverage checks for the Stage 1 label set.

Answers two pre-training questions using metadata only (no model):

* Are the v2 removed samples actually suspect, and do they overlap the v2
  train/val used for Stage 1?
* For each active label, what are the pre-registered held-out (test) coverage
  numbers we can already measure without labels?

This is a data-quality / scoping report. It never looks at model performance.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


def _resolve(path: str | Path) -> Path:
    path = Path(path).expanduser()
    return path if path.is_absolute() else ROOT / path


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as fh:
        return list(csv.DictReader(fh))


def build_report(v2_manifest: Path, v2_main: Path, v2_lofo: Path) -> dict[str, Any]:
    rows = _rows(v2_manifest)
    clean = [row for row in rows if row.get("is_clean") == "1"]
    main = json.loads(v2_main.read_text())
    lofo = json.loads(v2_lofo.read_text())
    assign = main["assignments"]
    lofo_assign = lofo["assignments"]

    by_id = {row["sample_id"]: row for row in clean}

    def split_counts(assignments: dict[str, str]) -> dict[str, Any]:
        bins: dict[str, set[str]] = {s: set() for s in ("train", "val", "test")}
        clusters: dict[str, set[str]] = {s: set() for s in ("train", "val", "test")}
        families: dict[str, set[str]] = {s: set() for s in ("train", "val", "test")}
        for sample_id, split in assignments.items():
            row = by_id.get(sample_id)
            if not row:
                continue
            bins[split].add(sample_id)
            clusters[split].add(row["cluster_key"])
            families[split].add(row["family"] or "unknown")
        return {
            split: {
                "samples": len(bins[split]),
                "clusters": len(clusters[split]),
                "families": sorted(families[split]),
            }
            for split in bins
        }

    # The known v1->v2 removed set, reconstructed by re-applying the PE rule.
    def is_v2_removed(row: dict[str, str]) -> bool:
        return (
            float(row.get("text_entropy") or 0) >= 7.8
            and int(row.get("num_imports") or 0) <= 20
        )

    v1_path = ROOT / "data/versions/v1/manifest.csv"
    v1_rows = {row["sample_id"]: row for row in _rows(v1_path)}
    removed = [
        sample_id
        for sample_id, row in v1_rows.items()
        if row.get("is_clean") == "1" and is_v2_removed(row)
    ]
    removed_in_train_val = [
        sample_id
        for sample_id in removed
        if assign.get(sample_id) in {"train", "val"}
    ]

    return {
        "v2_clean_samples": len(clean),
        "main": split_counts(assign),
        "lofo": split_counts(lofo_assign),
        "main_lofo_held_out": lofo.get("held_out_families"),
        "v1_removed_total": len(removed),
        "v1_removed_in_v2_train_val": len(removed_in_train_val),
        "v1_removed_by_family": dict(
            Counter(
                (v1_rows[sample_id].get("family") or "unknown") for sample_id in removed
            ).most_common()
        ),
        "v1_removed_by_bucket": dict(
            Counter(
                v1_rows[sample_id].get("source_bucket") for sample_id in removed
            ).most_common()
        ),
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Stage 1 cross-version coverage",
        "",
        "Metadata-only scoping report. No model performance is consulted.",
        "",
        f"- v2 clean samples: **{report['v2_clean_samples']}**",
        f"- v1 samples removed by the v2 PE rule: **{report['v1_removed_total']}**",
        f"- ... of which fall in v2 main train/val: **{report['v1_removed_in_v2_train_val']}**",
        "",
        "## v2 main split coverage",
        "",
        "| Split | Samples | Clusters | Families |",
        "|---|---:|---:|---:|",
    ]
    for split in ("train", "val", "test"):
        item = report["main"][split]
        lines.append(
            f"| {split} | {item['samples']} | {item['clusters']} | {len(item['families'])} |"
        )
    lines += [
        "",
        "## v2 LOFO split coverage",
        "",
        "| Split | Samples | Clusters | Families |",
        "|---|---:|---:|---:|",
    ]
    for split in ("train", "val", "test"):
        item = report["lofo"][split]
        lines.append(
            f"| {split} | {item['samples']} | {item['clusters']} | {len(item['families'])} |"
        )
    lines += [
        "",
        "LOFO held-out families: "
        + ", ".join(
            f"`{b}={f}`" for b, f in (report["main_lofo_held_out"] or {}).items()
        ),
        "",
        "## Removed samples by family / bucket",
        "",
        "| Family | Removed |",
        "|---|---:|",
    ]
    for family, count in report["v1_removed_by_family"].items():
        lines.append(f"| `{family}` | {count} |")
    lines += [
        "",
        "| Bucket | Removed |",
        "|---|---:|",
    ]
    for bucket, count in report["v1_removed_by_bucket"].items():
        lines.append(f"| `{bucket}` | {count} |")
    lines += [
        "",
        "Held-out positive binary/cluster coverage can only be finalised after full",
        "v2 labels; the pre-registered minima are >=10 held-out positive binaries",
        "and >=5 held-out positive clusters per active label.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v2-manifest", type=Path, default=ROOT / "data/versions/v2/manifest.csv")
    parser.add_argument("--v2-main", type=Path, default=ROOT / "data/versions/v2/splits/main.json")
    parser.add_argument("--v2-lofo", type=Path, default=ROOT / "data/versions/v2/splits/lofo.json")
    parser.add_argument("--json-out", type=Path, default=ROOT / "results/phase0_v2/stage1_coverage.json")
    parser.add_argument("--md-out", type=Path, default=ROOT / "results/phase0_v2/stage1_coverage.md")
    args = parser.parse_args(argv)

    report = build_report(
        _resolve(args.v2_manifest), _resolve(args.v2_main), _resolve(args.v2_lofo)
    )
    json_out = _resolve(args.json_out)
    md_out = _resolve(args.md_out)
    json_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(report, indent=2) + "\n")
    md_out.write_text(render_markdown(report))
    print(render_markdown(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
