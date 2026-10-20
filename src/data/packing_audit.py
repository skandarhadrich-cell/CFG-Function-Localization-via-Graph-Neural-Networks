"""Audit the pilot sample set for packer evidence missed by Phase 0 flags."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


def _rows(path: Path) -> dict[str, dict[str, str]]:
    with path.open(newline="") as fh:
        return {row["sample_id"]: row for row in csv.DictReader(fh)}


def _capa_packers(path: Path) -> list[str]:
    if not path.exists():
        return []
    try:
        document = json.loads(path.read_text())
    except json.JSONDecodeError:
        return []
    names = []
    for rule in document.get("rules", {}).values():
        namespace = (rule.get("meta") or {}).get("namespace") or ""
        if namespace.startswith("anti-analysis/packer"):
            names.append((rule.get("meta") or {}).get("name") or namespace)
    return sorted(set(names))


def audit(
    sample_ids: list[str],
    manifest: dict[str, dict[str, str]],
    capa_dir: Path,
) -> dict[str, Any]:
    details = []
    counts: Counter[str] = Counter()
    for sample_id in sample_ids:
        row = manifest.get(sample_id)
        if row is None:
            continue
        entropy = float(row.get("text_entropy") or 0)
        imports = int(row.get("num_imports") or 0)
        capa_packers = _capa_packers(capa_dir / f"{sample_id}.json")
        reasons: list[str] = []
        if row.get("is_packed") == "1":
            reasons.append("phase0_is_packed")
        if capa_packers:
            reasons.append("capa_packer_rule")
        if entropy >= 7.5 and imports <= 3:
            reasons.append("high_entropy_low_imports")
        elif entropy >= 7.9:
            reasons.append("very_high_entropy")
        suspected = bool(reasons)
        if suspected:
            counts["suspected_packed"] += 1
            counts[f"bucket:{row['source_bucket']}"] += 1
            for reason in reasons:
                counts[f"reason:{reason}"] += 1
        details.append(
            {
                "sample_id": sample_id,
                "source_bucket": row["source_bucket"],
                "family": row["family"],
                "is_clean": row["is_clean"],
                "is_packed": row["is_packed"],
                "text_entropy": entropy,
                "num_imports": imports,
                "num_sections": int(row.get("num_sections") or 0),
                "size": int(row.get("size") or 0),
                "capa_packer_rules": capa_packers,
                "suspected_reasons": reasons,
                "suspected_packed": suspected,
            }
        )
    return {
        "samples": len(details),
        "counts": dict(counts),
        "details": sorted(details, key=lambda item: (item["source_bucket"], item["sample_id"])),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit pilot samples for packing evidence.")
    parser.add_argument("--samples", type=Path, default=ROOT / "results/pilot/samples.json")
    parser.add_argument("--manifest", type=Path, default=ROOT / "data/manifest.csv")
    parser.add_argument("--capa-dir", type=Path, default=ROOT / "data/labels/capa_raw")
    parser.add_argument("--out", type=Path, default=ROOT / "results/pilot/packing_audit.json")
    args = parser.parse_args(argv)

    payload = json.loads(args.samples.read_text())
    sample_ids = [item["sample_id"] for item in payload["samples"]]
    report = audit(sample_ids, _rows(args.manifest), args.capa_dir)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["counts"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
