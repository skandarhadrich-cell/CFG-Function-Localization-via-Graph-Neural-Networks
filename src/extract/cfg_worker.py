"""Subprocess entry point for one CFG extraction task.

Isolating each sample in its own process bounds angr memory and lets the batch
orchestrator enforce a hard timeout.  The packed ``.npz`` is written atomically
by the parent-facing path in ``batch_extract``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from src.extract.angr_cfg import extract_cfg
from src.extract.cfg_store import save_cfg


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Extract one sample's per-function CFGs.")
    parser.add_argument("--sample-id", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--summary-out", type=Path, required=True)
    args = parser.parse_args(argv)

    cfg = extract_cfg(args.binary, args.sample_id, scratch_dir=args.scratch)
    save_cfg(cfg, args.out)
    args.summary_out.write_text(json.dumps(cfg.summary(), indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
