"""Select known-bad pilot rows that the quality filters must reject."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as fh:
        return list(csv.DictReader(fh))


def select(rows: list[dict[str, str]], per_kind: int = 10) -> list[dict[str, str]]:
    dotnet = [row for row in rows if row.get("is_dotnet") == "1" and row.get("in_bodmas") == "1"]
    packed = [row for row in rows if row.get("is_packed") == "1" and row.get("in_bodmas") == "1"]
    # Stable, bucket-diverse selection without random state.
    dotnet.sort(key=lambda row: (row["source_bucket"], row["sample_id"]))
    packed.sort(key=lambda row: (row["source_bucket"], row["sample_id"]))
    selected = dotnet[:per_kind] + packed[:per_kind]
    seen: set[str] = set()
    unique = []
    for row in selected:
        if row["sample_id"] in seen:
            continue
        seen.add(row["sample_id"])
        unique.append(row)
    return unique


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write the known-bad pilot filter check.")
    parser.add_argument("--manifest", type=Path, default=ROOT / "data/manifest.csv")
    parser.add_argument("--out", type=Path, default=ROOT / "results/pilot/known_bad.json")
    args = parser.parse_args(argv)

    rows = _rows(args.manifest)
    selected = select(rows)
    if any(row.get("is_clean") == "1" for row in selected):
        raise SystemExit("known-bad selection contains a clean row")
    payload = {
        "count": len(selected),
        "by_flag": {
            "dotnet": sum(row.get("is_dotnet") == "1" for row in selected),
            "packed": sum(row.get("is_packed") == "1" for row in selected),
        },
        "by_bucket": dict(Counter(row["source_bucket"] for row in selected)),
        "samples": [
            {
                "sample_id": row["sample_id"],
                "source_bucket": row["source_bucket"],
                "family": row["family"],
                "filepath": row["filepath"],
                "quality_flags": row["quality_flags"],
                "is_dotnet": row["is_dotnet"],
                "is_packed": row["is_packed"],
                "is_clean": row["is_clean"],
            }
            for row in selected
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2) + "\n")
    print(json.dumps({key: value for key, value in payload.items() if key != "samples"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
