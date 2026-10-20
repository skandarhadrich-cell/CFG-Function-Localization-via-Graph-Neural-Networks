"""Subprocess entry point for one CAPA-to-angr mapping task.

Running each sample in its own process lets the batch orchestrator enforce a
hard timeout and discard all angr memory when the task finishes.  The parent
reads the JSON payload from ``--out`` and appends it to the mapping JSONL.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from src.label.build_labels import map_one


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Map one sample's CAPA labels onto angr.")
    parser.add_argument("--sample-id", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--capa-json", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    payload = map_one(args.sample_id, args.binary, args.capa_json, args.scratch)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
