"""Pilot label census and gate report from CAPA JSON (and mapping output)."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from src.label.parse_capa import LABELS, aggregate_summaries, parse_capa_file

ROOT = Path(__file__).resolve().parents[2]


def _resolve(path: str | Path) -> Path:
    path = Path(path).expanduser()
    return path if path.is_absolute() else ROOT / path


def _pilot_samples(path: Path) -> list[dict[str, str]]:
    return json.loads(path.read_text())["samples"]


def _clean_counts(manifest: Path) -> dict[str, int]:
    counts: Counter[str] = Counter()
    with manifest.open(newline="") as fh:
        for row in csv.DictReader(fh):
            if row.get("is_clean") == "1":
                counts[row["source_bucket"]] += 1
    return dict(counts)


def build_report(
    samples: list[dict[str, str]],
    capa_dir: Path,
    clean_counts: dict[str, int],
    mapping_summary: dict[str, Any] | None,
    *,
    min_coverage: float = 0.95,
    max_unresolved: float = 0.02,
    min_positive: int = 300,
) -> dict[str, Any]:
    parsed = []
    missing: list[str] = []
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
            "label_counts": {label: 0 for label in LABELS},
        }
    )
    per_family: Counter[str] = Counter()
    for sample in samples:
        sample_id = sample["sample_id"]
        path = capa_dir / f"{sample_id}.json"
        if not path.exists():
            missing.append(sample_id)
            continue
        result = parse_capa_file(path, sample_id=sample_id)
        parsed.append(result)
        bucket = sample["source_bucket"]
        row = per_bucket[bucket]
        row["selected"] = selected_by_bucket[bucket]
        row["samples"] += 1
        row["observed"] += len(result.functions)
        row["positive_functions"] += result.positive_count
        row["weak_negative"] += result.weak_negative_count
        for label in LABELS:
            row["label_counts"][label] += result.label_counts[label]
            if result.label_counts[label]:
                per_family[f"{bucket}|{sample.get('family', 'unknown')}|{label}"] += 1

    project = {}
    for bucket, full_count in clean_counts.items():
        row = per_bucket.get(bucket)
        if not row or not row["samples"]:
            project[bucket] = {label: None for label in LABELS}
            continue
        denominator = selected_by_bucket.get(bucket, row["samples"])
        project[bucket] = {
            label: row["label_counts"][label] / denominator * full_count
            for label in LABELS
        }
    projected = {
        label: sum(
            item[label]
            for item in project.values()
            if item.get(label) is not None
        )
        for label in LABELS
    }

    aggregate = aggregate_summaries(parsed)
    mapping = mapping_summary or {}
    capa_coverage = mapping.get("capa_mapping_coverage")
    target_coverage = mapping.get("target_match_coverage")
    unresolved = mapping.get("unresolved_target_matches", 0)
    target_matches = mapping.get("target_matches", 0)
    unresolved_rate = unresolved / target_matches if target_matches else 0.0
    mapping_samples = mapping.get("samples")
    mapping_scope = (
        None
        if mapping_samples is None
        else ("pilot" if mapping_samples == len(samples) else "subset")
    )

    gates = {
        "mapping_available": mapping_summary is not None,
        "mapping_covers_all_samples": mapping_samples == len(samples),
        "capa_observed_mapping": (
            None if capa_coverage is None else capa_coverage >= min_coverage
        ),
        "target_match_mapping": (
            None if target_coverage is None else target_coverage >= min_coverage
        ),
        "unresolved_target_rate": unresolved_rate < max_unresolved,
        "positive_projection": {
            label: projected[label] >= min_positive for label in LABELS
        },
        "all_samples_processed": len(missing) == 0,
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
        "capa": aggregate,
        "per_bucket": dict(per_bucket),
        "label_counts_by_bucket": {
            bucket: row["label_counts"] for bucket, row in per_bucket.items()
        },
        "per_family_positive_samples": dict(per_family),
        "clean_counts_full_set": clean_counts,
        "projected_positive_functions": projected,
        "projection_by_bucket": project,
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
    lines = [
        "# Pilot Label Contract Report",
        "",
        f"- Samples selected: **{report['samples_selected']}**",
        f"- Samples processed: **{report['samples_processed']}**",
        f"- Missing CAPA JSON: **{len(report['missing_samples'])}**",
        "",
        "## CAPA census",
        "",
        f"- CAPA-observed functions: **{capa['capa_observed']}**",
        f"- Positive functions: **{capa['capa_matched']}**",
        f"- Weak-negative functions: **{capa['capa_weak_negative']}**",
        f"- Function-scope target matches: **{capa['function_match_count']}**",
        f"- Basic-block target matches: **{capa['block_match_count']}**",
        f"- Unresolved CAPA-layout block matches: **{capa['unresolved_block_matches']}**",
        "",
        "| Label | Positive functions | Projected full-set | Gate ≥300 |",
        "|---|---:|---:|---|",
    ]
    for label in LABELS:
        lines.append(
            f"| `{label}` | {capa['label_counts'].get(label, 0)} | "
            f"{projected[label]:.1f} | {'PASS' if gates['positive_projection'][label] else 'FAIL'} |"
        )
    lines += [
        "",
        "## Mapping",
        "",
        f"- Mapping samples: **{report.get('mapping_samples')}** "
        f"({report.get('mapping_scope') or 'not provided'})",
        f"- CAPA-observed → angr coverage: **{report['mapping'].get('capa_mapping_coverage')}**",
        f"- Target-match → angr coverage: **{report['mapping'].get('target_match_coverage')}**",
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
        "| Bucket | anti_debug | keylogger | injection |",
        "|---|---:|---:|---:|",
    ]
    for bucket, counts in report["label_counts_by_bucket"].items():
        lines.append(
            f"| `{bucket}` | {counts['anti_debug']} | {counts['keylogger']} | "
            f"{counts['injection']} |"
        )
    lines += [
        "",
        "## Gate summary",
        "",
        f"- Mapping output available: **{gates['mapping_available']}**",
        f"- Mapping covers all pilot samples: **{gates['mapping_covers_all_samples']}**",
        f"- CAPA-observed mapping ≥95%: **{gates['capa_observed_mapping']}**",
        f"- Target-match mapping ≥95%: **{gates['target_match_mapping']}**",
        f"- Unresolved target rate <2%: **{gates['unresolved_target_rate']}**",
        f"- All selected samples processed: **{gates['all_samples_processed']}**",
        f"- Overall: **{'PASS' if report['gate_pass'] else 'STOP / REVISE'}**",
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
    parser.add_argument("--manifest", type=Path, default=ROOT / "data/manifest.csv")
    parser.add_argument("--mapping", type=Path, default=ROOT / "results/pilot/mapping_summary.json")
    parser.add_argument("--json-out", type=Path, default=ROOT / "results/pilot/label_census.json")
    parser.add_argument("--md-out", type=Path, default=ROOT / "results/pilot/label_contract_report.md")
    parser.add_argument("--min-coverage", type=float, default=0.95)
    parser.add_argument("--max-unresolved", type=float, default=0.02)
    parser.add_argument("--min-positive", type=int, default=300)
    args = parser.parse_args(argv)

    samples = _pilot_samples(_resolve(args.samples))
    mapping_path = _resolve(args.mapping)
    mapping = json.loads(mapping_path.read_text()) if mapping_path.exists() else None
    report = build_report(
        samples,
        _resolve(args.capa_dir),
        _clean_counts(_resolve(args.manifest)),
        mapping,
        min_coverage=args.min_coverage,
        max_unresolved=args.max_unresolved,
        min_positive=args.min_positive,
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
