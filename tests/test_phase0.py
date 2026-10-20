"""Phase 0 unit tests.  Run with: python -m unittest discover -s tests -v"""

from __future__ import annotations

import struct
import unittest

from src.data.build_manifest import (
    assign_lofo,
    assign_main,
    check_integrity,
    split_summary,
)
from src.data.repair_pe import PEError, parse_header, repair_bytes


def make_pe(
    *, magic: int, machine: int, subsystem: int, e_lfanew: int = 0x80
) -> bytes:
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, e_lfanew)
    data[e_lfanew : e_lfanew + 4] = b"PE\0\0"
    struct.pack_into("<H", data, e_lfanew + 4, machine)
    struct.pack_into("<H", data, e_lfanew + 6, 1)
    struct.pack_into("<H", data, e_lfanew + 20, 224)
    struct.pack_into("<H", data, e_lfanew + 24, magic)
    struct.pack_into("<H", data, e_lfanew + 24 + 68, subsystem)
    return bytes(data)


class RepairTests(unittest.TestCase):
    def test_x86_header_is_repaired(self) -> None:
        data = make_pe(magic=0x10B, machine=0, subsystem=0)
        header = parse_header(data)
        self.assertEqual(header.arch, "x86")
        self.assertEqual(header.repaired_machine, 0x014C)
        self.assertEqual(header.repaired_subsystem, 3)
        self.assertTrue(header.needs_repair)

        repaired, _ = repair_bytes(data)
        new_header = parse_header(repaired)
        self.assertEqual(new_header.machine, 0x014C)
        self.assertEqual(new_header.subsystem, 3)
        self.assertFalse(new_header.needs_repair)

    def test_x64_header_is_repaired(self) -> None:
        data = make_pe(magic=0x20B, machine=0, subsystem=0)
        repaired, header = repair_bytes(data)
        self.assertEqual(header.arch, "x64")
        self.assertEqual(parse_header(repaired).machine, 0x8664)

    def test_repair_is_idempotent(self) -> None:
        data = make_pe(magic=0x10B, machine=0, subsystem=0)
        once, _ = repair_bytes(data)
        twice, header = repair_bytes(once)
        self.assertEqual(once, twice)
        self.assertFalse(header.needs_repair)

    def test_compact_dos_header_is_accepted(self) -> None:
        data = make_pe(magic=0x10B, machine=0, subsystem=0, e_lfanew=0x10)
        header = parse_header(data)
        self.assertEqual(header.e_lfanew, 0x10)
        self.assertEqual(header.arch, "x86")
        repaired, _ = repair_bytes(data)
        self.assertEqual(parse_header(repaired).machine, 0x014C)
        self.assertEqual(parse_header(repaired).subsystem, 3)

    def test_non_pe_is_rejected(self) -> None:
        with self.assertRaises(PEError):
            parse_header(b"not a pe file")


def _rows() -> list[dict]:
    rows = []
    for bucket in ("keylogger", "injection", "antidebug"):
        for index in range(20):
            rows.append(
                {
                    "sample_id": f"{bucket}-{index:02d}",
                    "source_bucket": bucket,
                    "family": f"{bucket}-fam-{index % 4}",
                    "cluster_key": f"imphash:{bucket}-{index % 7}",
                }
            )
    return rows


class SplitTests(unittest.TestCase):
    def test_main_split_keeps_clusters_whole(self) -> None:
        rows = _rows()
        assignments = assign_main(rows, {"train": 0.7, "val": 0.15, "test": 0.15}, 42)
        check_integrity(rows, assignments)
        summary = split_summary(rows, assignments)
        self.assertEqual(sum(summary["counts"].values()), len(rows))
        self.assertEqual(set(summary["counts"]), {"train", "val", "test"})

    def test_lofo_holds_out_family(self) -> None:
        rows = _rows()
        assignments = assign_lofo(
            rows, {"keylogger": "keylogger-fam-0", "injection": "injection-fam-0"},
            0.15,
            42,
        )
        check_integrity(
            rows, assignments, {"keylogger-fam-0", "injection-fam-0"}
        )
        for row in rows:
            if row["family"] in {"keylogger-fam-0", "injection-fam-0"}:
                self.assertEqual(assignments[row["sample_id"]], "test")


if __name__ == "__main__":
    unittest.main()
