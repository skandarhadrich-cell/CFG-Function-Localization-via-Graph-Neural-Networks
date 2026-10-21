"""Tests for the v3 builder invariants.

The v3 dataset extends the frozen v2 corpus with external samples. The
properties that matter are all about *not* corrupting the evaluation:

* the v2 test set is byte-identical in v3;
* no external sample enters test;
* a cluster that exists in the v2 test set never has an external member placed
  in train/val (that would leak a near-duplicate of a test sample);
* no cluster crosses splits at all;
* external rows carry the neutral ``external`` bucket, never a presumed label.

These run against synthetic rows, so they exercise the logic without needing
the real corpus.
"""

from __future__ import annotations

import unittest
from typing import Any

from src.data.build_v3 import (
    assign_external_splits,
    verify_no_leak,
    verify_v2_test_frozen,
)


def row(sample_id: str, cluster: str, family: str = "fam", bucket: str = "external") -> dict[str, Any]:
    return {
        "sample_id": sample_id,
        "cluster_key": cluster,
        "family": family,
        "source_bucket": bucket,
        "is_clean": 1,
    }


class V3AssignmentTest(unittest.TestCase):
    def setUp(self) -> None:
        # v2: cluster A in train, cluster B in val, cluster C in test.
        self.v2_rows = [
            row("v2_a", "A", bucket="antidebug"),
            row("v2_b", "B", bucket="injection"),
            row("v2_c", "C", bucket="keylogger"),
        ]
        self.v2_main = {"v2_a": "train", "v2_b": "val", "v2_c": "test"}

    def test_external_never_enters_test(self) -> None:
        external = [row(f"e{i}", f"new{i}") for i in range(20)]
        assignments, _ = assign_external_splits(external, self.v2_rows, self.v2_main)

        self.assertTrue(assignments)
        self.assertNotIn("test", set(assignments.values()))

    def test_cluster_conflicting_with_test_is_dropped(self) -> None:
        """An external sample in a cluster that v2 holds out must be dropped."""

        external = [row("leak", "C"), row("ok1", "newA"), row("ok2", "newB")]
        assignments, summary = assign_external_splits(external, self.v2_rows, self.v2_main)

        self.assertNotIn("leak", assignments)
        self.assertEqual(summary["external_dropped_cluster_conflict_with_test"], 1)
        self.assertIn("leak", summary["dropped_sample_ids"])

    def test_external_joining_existing_cluster_follows_it(self) -> None:
        external = [row("join_val", "B"), row("join_train", "A")]
        assignments, summary = assign_external_splits(external, self.v2_rows, self.v2_main)

        self.assertEqual(assignments["join_val"], "val")
        self.assertEqual(assignments["join_train"], "train")
        self.assertEqual(summary["new_clusters_assigned"], 0)

    def test_combined_assignments_do_not_leak(self) -> None:
        external = [row(f"e{i}", f"new{i}") for i in range(20)]
        ext_assign, _ = assign_external_splits(external, self.v2_rows, self.v2_main)
        combined = dict(self.v2_main)
        combined.update(ext_assign)

        # Should not raise.
        verify_no_leak(self.v2_rows + external, combined)


class V3TestFrozenTest(unittest.TestCase):
    def test_identical_test_sets_pass(self) -> None:
        v2_rows = [row("a", "A"), row("b", "B"), row("c", "C")]
        v2_main = {"a": "train", "b": "val", "c": "test"}
        v3 = dict(v2_main)
        v3["d"] = "train"

        result = verify_v2_test_frozen(v2_rows, v2_main, v3)
        self.assertTrue(result["identical"])
        self.assertEqual(result["v2_test_size"], 1)

    def test_changed_test_set_raises(self) -> None:
        v2_rows = [row("a", "A"), row("b", "B"), row("c", "C")]
        v2_main = {"a": "train", "b": "val", "c": "test"}
        v3 = {"a": "train", "b": "val", "c": "train"}  # test emptied

        with self.assertRaises(ValueError):
            verify_v2_test_frozen(v2_rows, v2_main, v3)

    def test_extra_test_sample_raises(self) -> None:
        v2_rows = [row("a", "A"), row("b", "B"), row("c", "C")]
        v2_main = {"a": "train", "b": "val", "c": "test"}
        v3 = dict(v2_main)
        v3["d"] = "test"  # external leaked into test

        with self.assertRaises(ValueError):
            verify_v2_test_frozen(v2_rows, v2_main, v3)


if __name__ == "__main__":
    unittest.main()
