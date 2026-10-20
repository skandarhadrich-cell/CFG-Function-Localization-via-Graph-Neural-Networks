"""Tests for the packed CFG store and the intraprocedural edge invariant."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import numpy as np

from src.extract.angr_cfg import ExtractedCFG
from src.extract.cfg_store import load_cfg_summary, save_cfg


def _tiny_cfg() -> ExtractedCFG:
    return ExtractedCFG(
        sample_id="deadbeef",
        base_address=0x400000,
        arch="X86",
        node_block_addr=[0x401000, 0x401010, 0x402000],
        node_block_size=[16, 8, 12],
        node_func_id=[0, 0, 1],
        node_instruction_addrs=[[0x401000, 0x401002], [0x401010], [0x402000]],
        node_mnemonics=[["push", "mov"], ["ret"], ["xor"]],
        node_call_targets=[[], [0x402000], []],
        edge_src=[0, 1],
        edge_dst=[1, 0],
        dropped_cross_edges=7,
        dropped_call_edges=3,
        func_va=[0x401000, 0x402000],
        func_size=[16, 12],
        function_count=2,
        block_count=3,
        instruction_count=4,
        elapsed_seconds=0.5,
        maxrss_mb=100.0,
    )


class CfgStoreTest(unittest.TestCase):
    def test_round_trip_summary(self) -> None:
        cfg = _tiny_cfg()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.npz"
            save_cfg(cfg, path)
            self.assertTrue(path.exists())
            summary = load_cfg_summary(path)
        self.assertEqual(summary["sample_id"], "deadbeef")
        self.assertEqual(summary["function_count"], 2)
        self.assertEqual(summary["node_count"], 3)
        self.assertEqual(summary["edge_count"], 2)
        self.assertEqual(summary["dropped_cross_edges"], 7)
        self.assertEqual(summary["dropped_call_edges"], 3)

    def test_variable_length_lists_preserved(self) -> None:
        cfg = _tiny_cfg()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.npz"
            save_cfg(cfg, path)
            with np.load(path, allow_pickle=True) as data:
                offsets = data["mnemonic_offsets"]
                mnemonics = data["mnemonics"]
                calls = data["call_targets"]
                call_offsets = data["call_offsets"]
        self.assertEqual(list(offsets), [0, 2, 3, 4])
        self.assertEqual(list(mnemonics), ["push", "mov", "ret", "xor"])
        self.assertEqual(list(call_offsets), [0, 0, 1, 1])
        self.assertEqual(list(calls), [0x402000])

    def test_summary_has_no_cross_fields(self) -> None:
        summary = _tiny_cfg().summary()
        self.assertEqual(summary["dropped_cross_edges"], 7)
        self.assertEqual(summary["dropped_call_edges"], 3)
        self.assertEqual(summary["call_target_count"], 1)


if __name__ == "__main__":
    unittest.main()
