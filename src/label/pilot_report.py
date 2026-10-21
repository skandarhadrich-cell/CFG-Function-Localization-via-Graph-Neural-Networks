"""Pilot label census and gate report from CAPA JSON (and mapping output)."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from src.label.contract import (
    ACTIVE_LABELS,
    MAX_SINGLE_BINARY_SHARE,
    MAX_SINGLE_CLUSTER_SHARE,
    MIN_POSITIVE_BINARIES,
    MIN_POSITIVE_CLUSTERS,
    MIN_POSITIVE_FAMILIES,
)
from src.label.parse_capa import aggregate_summaries, parse_capa_file

ROOT = Path(__file__).resolve().parents[2]


def _resolve(path: str | Path) -> Path:
    path = Path(path).expanduser()
    return path if path.is_absolute() else ROOT / path


def _pilot_samples(path: Path) -> list[dict[str, str]]:
    return json.loads(path.read_text())["samples"]


def _manifest_rows(manifest: Path) -> dict[str, dict[str, str]]:
    with manifest.open(newline="") as fh:
        return {row["sample_id"]: row for row in csv.DictReader(fh)}


def _clean_counts(rows: dict[str, dict[str, str]]) -> dict[str, int]:
    counts: Counter[str] = Counter(
        row["source_bucket"] for row in rows.values() if row.get("is_clean") == "1"
    )
    return dict(counts)


def _share(counter: Counter[str], total: int) -> float:
    return max(counter.values(), default=0) / total if total else 0.0


def build_report(
    samples: list[dict[str, str]],
    capa_dir: Path,
    clean_counts: dict[str, int],
    mapping_summary: dict[str, Any] | None,
    *,
    manifest_rows: dict[str, dict[str, str]] | None = None,
    active_labels: tuple[str, ...] = ACTIVE_LABELS,
    min_coverage: float = 0.95,
    max_unresolved: float = 0.02,
    min_positive: int = 300,
    max_missing_rate: float = 0.005,
) -> dict[str, Any]:
    manifest_rows = manifest_rows or {}
    parsed = []
    missing: list[str] = []
    active_positive_total = 0
    selected_by_bucket: Counter[str] = Counter(
        sample["source_bucket"] for sample in samples
    )
    per_bucket: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "selected": 0,
            "samples": 0,
            "observed": 0,
            "positive_functions": 0,
            "weak_negative": 0,
            "label_counts": {label: 0 for label in active_labels},
        }
    )
    per_family: Counter[str] = Counter()
    label_stats: dict[str, dict[str, Any]] = {
        label: {
            "functions": 0,
            "binaries": set(),
            "clusters": set(),
            "families": set(),
            "per_binary": Counter(),
            "per_cluster": Counter(),
            "per_family": Counter(),
        }
        for label in active_labels
    }
    for sample in samples:
        sample_id = sample["sample_id"]
        path = capa_dir / f"{sample_id}.json"
        if not path.exists():
            missing.append(sample_id)
            continue
        result = parse_capa_file(path, sample_id=sample_id)
        parsed.append(result)
        meta = manifest_rows.get(sample_id, {})
        bucket = sample["source_bucket"]
        family = sample.get("family") or meta.get("family") or "unknown"
        cluster = meta.get("cluster_key") or sample_id
        row = per_bucket[bucket]
        row["selected"] = selected_by_bucket[bucket]
        row["samples"] += 1
        row["observed"] += len(result.functions)
        active_positive = sum(
            1
            for func in result.functions
            if any(func.labels.get(label, 0) for label in active_labels)
        )
        row["positive_functions"] += active_positive
        row["weak_negative"] += len(result.functions) - active_positive
        active_positive_total += active_positive
        for label in active_labels:
            count = result.label_counts.get(label, 0)
            row["label_counts"][label] += count
            if not count:
                continue
            stats = label_stats[label]
            stats["functions"] += count
            stats["binaries"].add(sample_id)
            stats["clusters"].add(cluster)
            stats["families"].add(family)
            stats["per_binary"][sample_id] += count
            stats["per_cluster"][cluster] += count
            stats["per_family"][family] += count
            per_family[f"{bucket}|{family}|{label}"] += 1

    project = {}
    for bucket, full_count in clean_counts.items():
        row = per_bucket.get(bucket)
        if not row or not row["samples"]:
            project[bucket] = {label: None for label in active_labels}
            continue
        denominator = selected_by_bucket.get(bucket, row["samples"])
        project[bucket] = {
            label: row["label_counts"][label] / denominator * full_count
            for label in active_labels
        }
    projected = {
        label: sum(
            item[label]
            for item in project.values()
            if item.get(label) is not None
        )
        for label in active_labels
    }

    diversity: dict[str, dict[str, Any]] = {}
    for label in active_labels:
        stats = label_stats[label]
        total = stats["functions"]
        top_binary_share = _share(stats["per_binary"], total)
        top_cluster_share = _share(stats["per_cluster"], total)
        top_family_share = _share(stats["per_family"], total)
        checks = {
            "positive_functions": total >= min_positive,
            "positive_binaries": len(stats["binaries"]) >= MIN_POSITIVE_BINARIES,
            "positive_clusters": len(stats["clusters"]) >= MIN_POSITIVE_CLUSTERS,
            "positive_families": len(stats["families"]) >= MIN_POSITIVE_FAMILIES,
            "top_binary_share": top_binary_share <= MAX_SINGLE_BINARY_SHARE,
            "top_cluster_share": top_cluster_share <= MAX_SINGLE_CLUSTER_SHARE,
        }
        diversity[label] = {
            "positive_functions": total,
            "positive_binaries": len(stats["binaries"]),
            "positive_clusters": len(stats["clusters"]),
            "positive_families": len(stats["families"]),
            "top_binary_share": top_binary_share,
            "top_cluster_share": top_cluster_share,
            "top_family_share": top_family_share,
            "checks": checks,
            "ready": all(checks.values()),
        }

    aggregate = aggregate_summaries(parsed)
    aggregate["active_positive_functions"] = active_positive_total
    aggregate["active_labels"] = list(active_labels)
    mapping = mapping_summary or {}
    capa_coverage = mapping.get("capa_mapping_coverage")
    target_coverage = mapping.get("target_match_coverage")
    unresolved = mapping.get("unresolved_target_matches", 0)
    target_matches = mapping.get("target_matches", 0)
    unresolved_rate = unresolved / target_matches if target_matches else 0.0
    mapping_requested = mapping.get("requested")
    mapping_completed = mapping.get("completed")
    mapping_failed = mapping.get("failed")
    mapping_samples = mapping.get("samples")
    # Coverage is measured against samples that actually produced CAPA output.
    # Samples with recorded CAPA failures cannot be mapped and must not be
    # counted as mapping gaps; they remain visible in missing_samples.
    expected_mappable = (
        mapping_requested
        if mapping_requested is not None
        else (len(parsed) if parsed else None)
    )
    mapping_scope = (
        None
        if mapping_samples is None
        else (
            "full"
            if (
                mapping_samples >= expected_mappable
                or (
                    mapping_failed is not None
                    and mapping_samples + mapping_failed >= expected_mappable
                )
            )
            else "subset"
        )
    )

    gates = {
        "mapping_available": mapping_summary is not None,
        "mapping_covers_all_samples": (
            mapping_samples is not None
            and (
                mapping_samples >= expected_mappable
                or (
                    mapping_failed is not None
                    and mapping_samples + mapping_failed >= expected_mappable
                )
            )
        ),
        "capa_observed_mapping": (
            None if capa_coverage is None else capa_coverage >= min_coverage
        ),
        "target_match_mapping": (
            None if target_coverage is None else target_coverage >= min_coverage
        ),
        "unresolved_target_rate": unresolved_rate < max_unresolved,
        "positive_projection": {
            label: projected[label] >= min_positive for label in active_labels
        },
        "all_samples_processed": (
            len(missing) <= int(max_missing_rate * len(samples) + 0.999)
        ),
        "diversity": {
            label: diversity[label]["ready"] for label in active_labels
        },
    }
    gate_pass = (
        gates["mapping_available"]
        and gates["mapping_covers_all_samples"]
        and gates["capa_observed_mapping"] is not False
        and gates["target_match_mapping"] is not False
        and gates["unresolved_target_rate"]
        and all(gates["positive_projection"].values())
        and gates["all_samples_processed"]
    )

    return {
        "samples_selected": len(samples),
        "samples_processed": len(parsed),
        "missing_samples": missing,
        "active_labels": list(active_labels),
        "capa": aggregate,
        "per_bucket": dict(per_bucket),
        "label_counts_by_bucket": {
            bucket: row["label_counts"] for bucket, row in per_bucket.items()
        },
        "per_family_positive_samples": dict(per_family),
        "clean_counts_full_set": clean_counts,
        "projected_positive_functions": projected,
        "projection_by_bucket": project,
        "diversity": diversity,
        "mapping": mapping,
        "mapping_samples": mapping_samples,
        "mapping_scope": mapping_scope,
        "mapping_unresolved_rate": unresolved_rate,
        "gates": gates,
        "gate_pass": gate_pass,
    }


def render_markdown(report: dict[str, Any]) -> str:
    capa = report["capa"]
    projected = report["projected_positive_functions"]
    gates = report["gates"]
    active_labels = report["active_labels"]
    lines = [
        "# Stage 1 Label Contract Report",
        "",
        f"- Scope: **{report.get('mapping_scope') or 'unknown'}**",
        f"- Samples selected: **{report['samples_selected']}**",
        f"- Samples processed: **{report['samples_processed']}**",
        f"- Missing CAPA JSON: **{len(report['missing_samples'])}**",
        f"- Active labels: **{', '.join(active_labels)}**",
        "",
        "## CAPA census",
        "",
        f"- CAPA-observed functions: **{capa['capa_observed']}**",
        f"- Stage 1 positive functions: **{capa['active_positive_functions']}**",
        f"- Function-scope target matches: **{capa['function_match_count']}**",
        f"- Basic-block target matches: **{capa['block_match_count']}**",
        f"- Unresolved CAPA-layout block matches: **{capa['unresolved_block_matches']}**",
        "",
        "| Label | Positive functions | Projected full-set | Gate >=300 |",
        "|---|---:|---:|---|",
    ]
    for label in active_labels:
        lines.append(
            f"| `{label}` | {capa['label_counts'].get(label, 0)} | "
            f"{projected[label]:.1f} | {'PASS' if gates['positive_projection'][label] else 'FAIL'} |"
        )
    lines += [
        "",
        "## Diversity diagnostics",
        "",
        "These are pre-registered claim diagnostics, not performance-tuned thresholds.",
        "",
        "| Label | Functions | Binaries | Clusters | Families | Top binary | Top cluster | Ready |",
        "|---|---:|---:|---:|---:|---:|---:|---|",
    ]
    for label in active_labels:
        item = report["diversity"][label]
        lines.append(
            f"| `{label}` | {item['positive_functions']} | {item['positive_binaries']} | "
            f"{item['positive_clusters']} | {item['positive_families']} | "
            f"{item['top_binary_share']:.1%} | {item['top_cluster_share']:.1%} | "
            f"{'YES' if item['ready'] else 'NO'} |"
        )
    lines += [
        "",
        "Diversity criteria: >=20 positive binaries, >=10 clusters, >=3 families, "
        "top binary <=50%, top cluster <=50%. Labels that fail remain eligible for "
        "training but cannot support a binary-level generalization claim.",
        "",
        "## Mapping",
        "",
        f"- Mapping samples: **{report.get('mapping_samples')}** "
        f"({report.get('mapping_scope') or 'not provided'})",
        f"- CAPA-observed -> angr coverage: **{report['mapping'].get('capa_mapping_coverage')}**",
        f"- Target-match -> angr coverage: **{report['mapping'].get('target_match_coverage')}**",
        f"- Unresolved target rate: **{report['mapping_unresolved_rate']:.3%}**",
        f"- Many-to-one collisions: **{report['mapping'].get('many_to_one_collisions', 0)}**",
        "",
        "## Per bucket",
        "",
        "| Bucket | Selected | Processed | Observed | Positive functions | Projected full-set positive functions |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for bucket, row in report["per_bucket"].items():
        proj = report["projection_by_bucket"].get(bucket, {})
        proj_total = sum(value for value in proj.values() if value is not None)
        lines.append(
            f"| `{bucket}` | {row.get('selected', row['samples'])} | {row['samples']} | "
            f"{row['observed']} | {row['positive_functions']} | {proj_total:.1f} |"
        )
    lines += [
        "",
        "## CAPA label counts by source bucket",
        "",
        "`source_bucket` is stratification metadata, not ground truth.",
        "",
        "| Bucket | " + " | ".join(active_labels) + " |",
        "|---|" + "|".join("---:" for _ in active_labels) + "|",
    ]
    for bucket, counts in report["label_counts_by_bucket"].items():
        values = " | ".join(str(counts.get(label, 0)) for label in active_labels)
        lines.append(f"| `{bucket}` | {values} |")
    lines += [
        "",
        "## Gate summary",
        "",
        f"- Mapping output available: **{gates['mapping_available']}**",
        f"- Mapping covers all labelable samples: **{gates['mapping_covers_all_samples']}**",
        f"- CAPA-observed mapping >=95%: **{gates['capa_observed_mapping']}**",
        f"- Target-match mapping >=95%: **{gates['target_match_mapping']}**",
        f"- Unresolved target rate <2%: **{gates['unresolved_target_rate']}**",
        f"- All selected samples processed: **{gates['all_samples_processed']}**",
        "- Diversity ready: " + ", ".join(
            f"`{label}`={gates['diversity'][label]}" for label in active_labels
        ),
        f"- Overall pipeline gate: **{'PASS' if report['gate_pass'] else 'STOP / REVISE'}**",
        "",
        "Weak negatives mean only that no selected CAPA rule matched in a function "
        "CAPA analyzed. They are not benign labels.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate pilot label census and gate report.")
    parser.add_argument("--samples", type=Path, default=ROOT / "results/pilot/samples.json")
    parser.add_argument("--capa-dir", type=Path, default=ROOT / "data/labels/capa_raw")
    parser.add_argument("--manifest", type=Path, default=ROOT / "data/versions/v2/manifest.csv")
    parser.add_argument("--mapping", type=Path, default=ROOT / "results/pilot/mapping_subset_summary.json")
    parser.add_argument("--json-out", type=Path, default=ROOT / "results/phase0_v2/stage1_label_census.json")
    parser.add_argument("--md-out", type=Path, default=ROOT / "results/phase0_v2/stage1_label_contract_report.md")
    parser.add_argument("--min-coverage", type=float, default=0.95)
    parser.add_argument("--max-unresolved", type=float, default=0.02)
    parser.add_argument("--min-positive", type=int, default=300)
    parser.add_argument(
        "--max-missing-rate",
        type=float,
        default=0.005,
        help="fraction of samples allowed to fail extraction/labeling records",
    )
    args = parser.parse_args(argv)

    samples = _pilot_samples(_resolve(args.samples))
    manifest_path = _resolve(args.manifest)
    manifest_rows = _manifest_rows(manifest_path)
    mapping_path = _resolve(args.mapping)
    mapping = json.loads(mapping_path.read_text()) if mapping_path.exists() else None
    report = build_report(
        samples,
        _resolve(args.capa_dir),
        _clean_counts(manifest_rows),
        mapping,
        manifest_rows=manifest_rows,
        active_labels=ACTIVE_LABELS,
        min_coverage=args.min_coverage,
        max_unresolved=args.max_unresolved,
        min_positive=args.min_positive,
        max_missing_rate=args.max_missing_rate,
    )
    json_out = _resolve(args.json_out)
    md_out = _resolve(args.md_out)
    json_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(report, indent=2) + "\n")
    md_out.write_text(render_markdown(report))
    print(render_markdown(report))
    return 0 if report["gate_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
