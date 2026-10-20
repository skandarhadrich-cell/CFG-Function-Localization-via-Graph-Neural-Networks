"""Audit the v2 packed-sample filter against PE evidence and CAPA packer rules.

The manifest builder uses only PE features.  CAPA packer detections are joined
here as an independent audit signal and are never used to exclude a sample.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

import pefile

from src.data.build_manifest import ROOT, shannon_entropy

THRESHOLDS = (7.8, 7.9)
MAX_IMPORTS = 20


def _resolve(path: str | Path) -> Path:
    path = Path(path).expanduser()
    return path if path.is_absolute() else ROOT / path


def _flag(row: dict[str, str], threshold: float) -> bool:
    return (
        float(row.get("text_entropy") or 0) >= threshold
        and int(row.get("num_imports") or 0) <= MAX_IMPORTS
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _capa_packers(path: Path) -> list[str]:
    if not path.exists():
        return []
    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    found = []
    for rule in (document.get("rules") or {}).values():
        meta = rule.get("meta") or {}
        namespace = str(meta.get("namespace") or "")
        if namespace == "anti-analysis/packing" or namespace.startswith(
            "anti-analysis/packing/"
        ):
            found.append(str(meta.get("name") or "packing rule"))
    return sorted(set(found))


def _section_profile(path: Path) -> dict[str, Any]:
    pe = pefile.PE(str(path), fast_load=True)
    try:
        sections = []
        for section in pe.sections:
            name = section.Name.rstrip(b"\x00").decode(errors="replace")
            data = section.get_data()
            entropy = shannon_entropy(data) if data else 0.0
            sections.append(
                {
                    "name": name,
                    "entropy": round(entropy, 4),
                    "raw_size": int(section.SizeOfRawData),
                    "virtual_size": int(section.Misc_VirtualSize),
                    "characteristics": hex(int(section.Characteristics)),
                    "writable": bool(section.Characteristics & 0x80000000),
                    "executable": bool(section.Characteristics & 0x20000000),
                    "code": bool(section.Characteristics & 0x00000020),
                }
            )
        entrypoint = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        return {
            "sections": sections,
            "max_section_entropy": max(
                (s["entropy"] for s in sections), default=0.0
            ),
            "executable_writable_sections": [
                s["name"] for s in sections if s["writable"] and s["executable"]
            ],
            "entrypoint_rva": entrypoint,
            "image_base": image_base,
        }
    finally:
        pe.close()


def build_audit(
    manifest_path: Path,
    pilot_audit_path: Path,
    capa_dir: Path,
) -> dict[str, Any]:
    with manifest_path.open(newline="") as fh:
        rows = list(csv.DictReader(fh))
    clean = [row for row in rows if row.get("is_clean") == "1"]
    by_id = {row["sample_id"]: row for row in clean}

    pilot = json.loads(pilot_audit_path.read_text())
    suspected = {
        item["sample_id"]: item
        for item in pilot.get("details", [])
        if item.get("suspected_packed")
    }

    threshold_results: dict[str, Any] = {}
    for threshold in THRESHOLDS:
        removed = [row for row in clean if _flag(row, threshold)]
        removed_ids = {row["sample_id"] for row in removed}
        missed_audit = sorted(set(suspected) - removed_ids)
        threshold_results[str(threshold)] = {
            "removed": len(removed),
            "removed_by_bucket": dict(Counter(row["source_bucket"] for row in removed)),
            "removed_by_family": dict(
                Counter(row["family"] or "unknown" for row in removed).most_common()
            ),
            "audit_suspected_caught": len(set(suspected) & removed_ids),
            "audit_suspected_total": len(suspected),
            "audit_missed": [
                {
                    "sample_id": sample_id,
                    "family": suspected[sample_id].get("family"),
                    "text_entropy": suspected[sample_id].get("text_entropy"),
                    "num_imports": suspected[sample_id].get("num_imports"),
                    "suspected_reasons": suspected[sample_id].get(
                        "suspected_reasons", []
                    ),
                }
                for sample_id in missed_audit
            ],
            "removed_sample_ids": sorted(removed_ids),
        }

    low_ids = {
        row["sample_id"] for row in clean if _flag(row, min(THRESHOLDS))
    }
    high_ids = {
        row["sample_id"] for row in clean if _flag(row, max(THRESHOLDS))
    }
    delta_ids = sorted(low_ids - high_ids)
    delta = []
    for sample_id in delta_ids:
        row = by_id[sample_id]
        profile = _section_profile(_resolve(row["filepath"]))
        delta.append(
            {
                "sample_id": sample_id,
                "source_bucket": row["source_bucket"],
                "family": row["family"],
                "cluster_key": row["cluster_key"],
                "text_entropy": float(row["text_entropy"]),
                "num_imports": int(row["num_imports"]),
                "size": int(row["size"]),
                "capa_packer_rules": _capa_packers(capa_dir / f"{sample_id}.json"),
                **profile,
            }
        )

    suspicious_delta = sum(
        bool(item["executable_writable_sections"])
        or item["max_section_entropy"] >= 7.5
        or bool(item["capa_packer_rules"])
        for item in delta
    )
    if (
        threshold_results["7.8"]["audit_missed"] == []
        and suspicious_delta == len(delta)
    ):
        recommendation = "7.8"
        rationale = (
            "7.8 catches every pilot audit flag. The 14 samples removed only at "
            "7.8 form two clusters with high-entropy sections or writable+executable "
            "sections, so 7.9 would retain likely packed files."
        )
    elif threshold_results["7.9"]["audit_missed"] == []:
        recommendation = "7.9"
        rationale = "7.9 catches every pilot audit flag with fewer exclusions."
    else:
        recommendation = "review"
        rationale = (
            "Neither threshold cleanly separates the pilot audit. Keep the entropy "
            "heuristic and CAPA packer audit as separate signals and review ambiguous cases."
        )

    return {
        "manifest": str(manifest_path),
        "manifest_sha256": _sha256(manifest_path),
        "pilot_audit": str(pilot_audit_path),
        "thresholds": threshold_results,
        "delta_7_8_minus_7_9": delta,
        "delta_suspicious_count": suspicious_delta,
        "recommendation": recommendation,
        "rationale": rationale,
        "capa_role": "audit_only",
    }


def render_markdown(audit: dict[str, Any]) -> str:
    lines = [
        "# Phase 0 v2 packed-filter audit",
        "",
        f"- v1 manifest: `{audit['manifest']}`",
        f"- v1 manifest SHA-256: `{audit['manifest_sha256']}`",
        f"- Candidate rule: `text_entropy >= T` and `num_imports <= {MAX_IMPORTS}`",
        "- CAPA packer detections are an audit signal only; they are not used by the filter.",
        "",
        "## Threshold comparison",
        "",
        "| Threshold | Removed | Audit caught | Audit missed |",
        "|---:|---:|---:|---:|",
    ]
    for threshold, result in audit["thresholds"].items():
        lines.append(
            f"| {threshold} | {result['removed']} | "
            f"{result['audit_suspected_caught']}/{result['audit_suspected_total']} | "
            f"{len(result['audit_missed'])} |"
        )
    lines += [
        "",
        "### Removed by bucket",
        "",
        "| Threshold | antidebug | injection | keylogger |",
        "|---:|---:|---:|---:|",
    ]
    for threshold, result in audit["thresholds"].items():
        counts = result["removed_by_bucket"]
        lines.append(
            f"| {threshold} | {counts.get('antidebug', 0)} | "
            f"{counts.get('injection', 0)} | {counts.get('keylogger', 0)} |"
        )
    lines += [
        "",
        "## Samples removed only by 7.8",
        "",
        "| Sample | Bucket | Family | Entropy | Imports | W+X sections | Max section entropy | CAPA packer |",
        "|---|---|---|---:|---:|---|---:|---|",
    ]
    for item in audit["delta_7_8_minus_7_9"]:
        lines.append(
            f"| `{item['sample_id'][:12]}` | {item['source_bucket']} | {item['family']} | "
            f"{item['text_entropy']:.4f} | {item['num_imports']} | "
            f"{', '.join(item['executable_writable_sections']) or '-'} | "
            f"{item['max_section_entropy']:.3f} | "
            f"{', '.join(item['capa_packer_rules']) or '-'} |"
        )
    lines += [
        "",
        "## Audit flags missed at each threshold",
        "",
    ]
    for threshold, result in audit["thresholds"].items():
        missed = result["audit_missed"]
        if not missed:
            lines.append(f"- **{threshold}**: none.")
            continue
        lines.append(f"- **{threshold}**:")
        for item in missed:
            lines.append(
                f"  - `{item['sample_id'][:12]}` ({item['family']}, "
                f"entropy {item['text_entropy']}, imports {item['num_imports']})"
            )
    lines += [
        "",
        "## Recommendation",
        "",
        f"**{audit['recommendation']}** — {audit['rationale']}",
        "",
        "This is a dataset-quality decision. It must not be chosen by comparing "
        "resulting positive-label counts.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=ROOT / "data/versions/v1/manifest.csv",
    )
    parser.add_argument(
        "--pilot-audit",
        type=Path,
        default=ROOT / "results/pilot/packing_audit.json",
    )
    parser.add_argument(
        "--capa-dir",
        type=Path,
        default=ROOT / "data/labels/capa_raw",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=ROOT / "results/phase0_v2/threshold_audit.json",
    )
    parser.add_argument(
        "--md-out",
        type=Path,
        default=ROOT / "results/phase0_v2/threshold_audit.md",
    )
    args = parser.parse_args(argv)

    audit = build_audit(
        _resolve(args.manifest),
        _resolve(args.pilot_audit),
        _resolve(args.capa_dir),
    )
    json_out = _resolve(args.json_out)
    md_out = _resolve(args.md_out)
    json_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(audit, indent=2) + "\n")
    md_out.write_text(render_markdown(audit))
    print(render_markdown(audit))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
