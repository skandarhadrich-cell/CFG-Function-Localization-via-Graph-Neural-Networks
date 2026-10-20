"""Deterministic repair of BODMAS "disarmed" PE headers.

BODMAS ships altered binaries with the COFF ``machine`` field and the optional
header ``subsystem`` field zeroed.  angr refuses to load them (``ArchNotFound``)
and CAPA exits with code 21.  This module restores only those two fields, using
the optional-header magic to decide x86 vs x64.  It never touches the raw corpus.

Usage::

    python -m src.data.repair_pe data/raw/keylogger/<id>.exe --out /tmp/<id>.exe
    python -m src.data.repair_pe data/raw/keylogger/<id>.exe --check
    python -m src.data.repair_pe data/raw/keylogger/<id>.exe --json
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

DOS_SIGNATURE = b"MZ"
PE_SIGNATURE = b"PE\0\0"

MACHINE_X86 = 0x014C
MACHINE_X64 = 0x8664

MAGIC_PE32 = 0x010B
MAGIC_PE32_PLUS = 0x020B

SUBSYSTEM_WINDOWS_GUI = 2
SUBSYSTEM_WINDOWS_CUI = 3

SUBSYSTEM_OFFSET = 68  # offset of Subsystem within the optional header

EXIT_OK = 0
EXIT_REPAIR_NEEDED = 1
EXIT_ERROR = 2


class PEError(ValueError):
    """Raised when a file is not a parseable PE image."""


@dataclass(frozen=True)
class PEHeader:
    """The header fields Phase 0 cares about."""

    e_lfanew: int
    machine: int
    subsystem: int
    optional_magic: int
    size_of_optional_header: int
    num_sections: int
    arch: str
    repaired_machine: int
    repaired_subsystem: int

    @property
    def needs_repair(self) -> bool:
        return (self.machine != self.repaired_machine) or (
            self.subsystem != self.repaired_subsystem
        )

    @property
    def repairs(self) -> list[str]:
        actions: list[str] = []
        if self.machine != self.repaired_machine:
            actions.append("machine")
        if self.subsystem != self.repaired_subsystem:
            actions.append("subsystem")
        return actions


def _arch_from_header(machine: int, optional_magic: int) -> str:
    if optional_magic == MAGIC_PE32:
        return "x86"
    if optional_magic == MAGIC_PE32_PLUS:
        return "x64"
    if machine == MACHINE_X86:
        return "x86"
    if machine == MACHINE_X64:
        return "x64"
    return "unknown"


def parse_header(data: bytes) -> PEHeader:
    """Parse the fields needed for repair.  Raises :class:`PEError` on failure."""

    if len(data) < 0x40:
        raise PEError("file is shorter than the DOS header")
    if data[:2] != DOS_SIGNATURE:
        raise PEError("missing MZ signature")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    # Most images put the PE header after a 64-byte DOS stub, but a compact
    # header at 0x10 is legal (seen in 16 BODMAS injector samples).  Only
    # reject offsets that cannot hold the COFF header inside the file.
    if e_lfanew < 4 or e_lfanew + 24 > len(data):
        raise PEError(f"invalid e_lfanew 0x{e_lfanew:x}")
    if data[e_lfanew : e_lfanew + 4] != PE_SIGNATURE:
        raise PEError("missing PE signature")

    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    size_of_optional_header = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    optional_magic = struct.unpack_from("<H", data, e_lfanew + 24)[0]

    subsystem = 0
    subsystem_pos = e_lfanew + 24 + SUBSYSTEM_OFFSET
    subsystem_valid = (
        size_of_optional_header >= SUBSYSTEM_OFFSET + 2
        and subsystem_pos + 2 <= len(data)
    )
    if subsystem_valid:
        subsystem = struct.unpack_from("<H", data, subsystem_pos)[0]

    arch = _arch_from_header(machine, optional_magic)

    if arch == "x86":
        repaired_machine = MACHINE_X86
    elif arch == "x64":
        repaired_machine = MACHINE_X64
    else:
        repaired_machine = machine

    repaired_subsystem = (
        SUBSYSTEM_WINDOWS_CUI
        if subsystem_valid and subsystem == 0
        else subsystem
    )

    return PEHeader(
        e_lfanew=e_lfanew,
        machine=machine,
        subsystem=subsystem,
        optional_magic=optional_magic,
        size_of_optional_header=size_of_optional_header,
        num_sections=num_sections,
        arch=arch,
        repaired_machine=repaired_machine,
        repaired_subsystem=repaired_subsystem,
    )


def repair_bytes(data: bytes) -> tuple[bytes, PEHeader]:
    """Return a repaired copy of *data* and the original header description."""

    header = parse_header(data)
    mutable = bytearray(data)

    if header.machine != header.repaired_machine:
        struct.pack_into("<H", mutable, header.e_lfanew + 4, header.repaired_machine)

    if header.subsystem != header.repaired_subsystem:
        struct.pack_into(
            "<H",
            mutable,
            header.e_lfanew + 24 + SUBSYSTEM_OFFSET,
            header.repaired_subsystem,
        )

    return bytes(mutable), header


def repair_file(src: Path | str, dst: Path | str) -> tuple[PEHeader, bool]:
    """Repair *src* into *dst* atomically.  Returns (header, changed)."""

    src = Path(src)
    dst = Path(dst)
    data = src.read_bytes()
    repaired, header = repair_bytes(data)

    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_name(dst.name + ".tmp")
    tmp.write_bytes(repaired)
    try:
        os.chmod(tmp, src.stat().st_mode & 0o777)
    except OSError:
        pass
    os.replace(tmp, dst)

    return header, header.needs_repair


def _iter_inputs(path: Path) -> list[Path]:
    if path.is_dir():
        return sorted(p for p in path.rglob("*.exe") if p.is_file())
    return [path]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Repair BODMAS disarmed PE headers (machine/subsystem only)."
    )
    parser.add_argument("input", type=Path, help="PE file or directory of .exe files")
    parser.add_argument("--out", type=Path, help="output file (single input)")
    parser.add_argument("--out-dir", type=Path, help="output directory (multiple inputs)")
    parser.add_argument(
        "--check",
        action="store_true",
        help="report whether repair is needed; do not write anything",
    )
    parser.add_argument(
        "--json", action="store_true", help="print header details as JSON"
    )
    args = parser.parse_args(argv)

    inputs = _iter_inputs(args.input)
    if not inputs:
        print(f"no .exe inputs found under {args.input}", file=sys.stderr)
        return EXIT_ERROR
    if len(inputs) > 1 and args.out:
        print("--out only accepts a single input; use --out-dir", file=sys.stderr)
        return EXIT_ERROR
    if len(inputs) > 1 and not args.out_dir and not args.check:
        print("multiple inputs require --out-dir (or --check)", file=sys.stderr)
        return EXIT_ERROR

    any_repair_needed = False
    for src in inputs:
        try:
            data = src.read_bytes()
            header = parse_header(data)
        except (OSError, PEError) as exc:
            print(f"{src}: {exc}", file=sys.stderr)
            return EXIT_ERROR

        any_repair_needed = any_repair_needed or header.needs_repair

        if args.json:
            payload = asdict(header)
            payload["path"] = str(src)
            payload["needs_repair"] = header.needs_repair
            payload["repairs"] = header.repairs
            print(json.dumps(payload, indent=2))
        elif args.check:
            status = "repair" if header.needs_repair else "ok"
            print(f"{status:6} {src} ({header.arch}, machine=0x{header.machine:04x}, subsystem={header.subsystem})")
        else:
            dst = args.out if args.out else (args.out_dir / src.name if args.out_dir else None)
            assert dst is not None
            _, changed = repair_file(src, dst)
            print(f"{'repaired' if changed else 'copied':8} {src} -> {dst}")

    if args.check:
        return EXIT_REPAIR_NEEDED if any_repair_needed else EXIT_OK
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
