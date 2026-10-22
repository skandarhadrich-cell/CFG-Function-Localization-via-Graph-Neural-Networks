#!/usr/bin/env python3
"""Decode the top predicted blocks to sanity-check address mapping.

This is a static decoding check, not a manual label validation. It confirms that
predicted block addresses land on executable bytes and shows the API calls that
the Stage 2 API-seed objective is likely responding to.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

IAT_RE = re.compile(r"\[(0x[0-9a-fA-F]+)\]")


def imports_by_address(pe: pefile.PE) -> dict[int, str]:
    out: dict[int, str] = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode(errors="replace") if entry.dll else "?"
        for imp in entry.imports:
            name = imp.name.decode(errors="replace") if imp.name else f"ordinal:{imp.ordinal}"
            out[int(imp.address)] = f"{dll}!{name}"
    return out


def decode_block(pe: pefile.PE, md: Cs, raw: bytes, base: int,
                 block: dict[str, Any]) -> dict[str, Any]:
    va = int(block["block_va"])
    size = int(block["size"])
    offset = pe.get_offset_from_rva(va - base)
    data = raw[offset:offset + size]
    instructions = list(md.disasm(data, va))
    decoded = sum(ins.size for ins in instructions)
    iat = imports_by_address(pe)
    rendered = []
    api = None
    for ins in instructions:
        text = f"{ins.mnemonic} {ins.op_str}".strip()
        rendered.append({"address": f"0x{ins.address:x}", "text": text})
        match = IAT_RE.search(text)
        if match and ins.mnemonic in {"call", "jmp"}:
            api = iat.get(int(match.group(1), 16), api)
    return {
        "block_rva": block["block_rva"],
        "block_va": f"0x{va:x}",
        "size": size,
        "score": block["score"],
        "decoded_bytes": decoded,
        "complete": decoded == size,
        "instructions": rendered,
        "api": api,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--target", default="injection")
    parser.add_argument("--functions", type=int, default=5)
    parser.add_argument("--per-function", type=int, default=3)
    args = parser.parse_args(argv)

    report = json.loads(args.report.read_text())
    target = report["targets"][args.target]
    base = int(report["sample"]["base_address"])
    pe = pefile.PE(str(args.binary))
    raw = args.binary.read_bytes()
    md = Cs(CS_ARCH_X86, CS_MODE_32)

    blocks = []
    for fn in target["functions"][:args.functions]:
        for block in fn["blocks"][:args.per_function]:
            entry = decode_block(pe, md, raw, base, block)
            entry["function_rva"] = fn["func_rva"]
            entry["function_score"] = fn["score"]
            blocks.append(entry)

    out = {
        "kind": "static-capstone-decode",
        "not_manual_validation": True,
        "sample_sha256": report["sample"]["sha256"],
        "target": args.target,
        "blocks": blocks,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2) + "\n")
    print(f"wrote {args.out} ({len(blocks)} blocks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
