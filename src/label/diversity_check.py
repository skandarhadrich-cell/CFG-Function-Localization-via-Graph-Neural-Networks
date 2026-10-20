"""Summarize a Stage 1 diversity report against the frozen criteria.

Reads ``results/full/stage1_label_census.json`` (produced by pilot_report) and
prints a compact per-label verdict.  Exit code 0 when every label meets the
pre-registered diversity criteria, 1 otherwise.

This is a review aid: it does not change labels or thresholds.  It exists so the
Phase 5 sign-off can be checked at a glance and re-run reproducibly.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

CRITERIA = (
    ("positive_functions", "functions >= 300"),
    ("positive_binaries", "binaries >= 20"),
    ("positive_clusters", "clusters >= 10"),
    ("positive_families", "families >= 3"),
    ("top_binary_share", "top binary share <= 0.50"),
    ("top_cluster_share", "top cluster share <= 0.50"),
)


def summarize(census: dict) -> dict:
    labels = census.get("active_labels", [])
    diversity = census.get("diversity", {})
    out: dict = {"active_labels": labels, "labels": {}}
    all_ready = True
    for label in labels:
        info = diversity.get(label, {})
        checks = info.get("checks", {})
        ready = bool(info.get("ready"))
        all_ready = all_ready and ready
        out["labels"][label] = {
            "ready": ready,
            "positive_functions": info.get("positive_functions"),
            "positive_binaries": info.get("positive_binaries"),
            "positive_clusters": info.get("positive_clusters"),
            "positive_families": info.get("positive_families"),
            "top_binary_share": info.get("top_binary_share"),
            "top_cluster_share": info.get("top_cluster_share"),
            "checks": {key: checks.get(key) for key, _ in CRITERIA},
        }
    out["all_ready"] = all_ready
    out["mapping_scope"] = census.get("mapping_scope")
    out["mapping_samples"] = census.get("mapping_samples")
    out["gate_pass"] = census.get("gate_pass")
    return out


def render(summary: dict) -> str:
    lines = []
    lines.append(f"active labels: {', '.join(summary['active_labels'])}")
    lines.append(
        f"mapping: scope={summary.get('mapping_scope')} "
        f"samples={summary.get('mapping_samples')} gate_pass={summary.get('gate_pass')}"
    )
    for label, info in summary["labels"].items():
        status = "PASS" if info["ready"] else "EXPLORATORY"
        lines.append(f"\n[{label}] {status}")
        lines.append(
            f"  functions={info['positive_functions']} "
            f"binaries={info['positive_binaries']} "
            f"clusters={info['positive_clusters']} "
            f"families={info['positive_families']}"
        )
        lines.append(
            f"  top_binary_share={info['top_binary_share']} "
            f"top_cluster_share={info['top_cluster_share']}"
        )
        for key, desc in CRITERIA:
            mark = "ok" if info["checks"].get(key) else "FAIL"
            lines.append(f"    - {desc}: {mark}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--census",
        type=Path,
        default=ROOT / "results/full/stage1_label_census.json",
    )
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args(argv)

    census = json.loads(args.census.read_text())
    summary = summarize(census)
    print(render(summary))
    if args.json_out:
        args.json_out.write_text(json.dumps(summary, indent=2) + "\n")
    return 0 if summary["all_ready"] else 1


if __name__ == "__main__":
    sys.exit(main())
