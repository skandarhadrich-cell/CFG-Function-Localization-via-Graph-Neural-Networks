"""Tests for the label contract after the 2026-10-22 label audit.

These lock in the decisions that the audits produced, so they cannot silently
regress:

* keylogger is never an active label (audit-only, permanently);
* the active labels carry honest display names that are not the capability they
  were originally named after;
* the census gate numbers match the recorded census;
* the evaluation protocol version and fold counts are fixed before any model
  run, and the retired single test split is not referenced.
"""

from __future__ import annotations

import unittest

from src.label import contract as c


class KeyloggerExclusionTest(unittest.TestCase):
    def test_keylogger_not_active(self) -> None:
        self.assertNotIn("keylogger", c.ACTIVE_LABELS)

    def test_only_two_active_labels(self) -> None:
        self.assertEqual(len(c.ACTIVE_LABELS), 2)
        self.assertEqual(set(c.ACTIVE_LABELS), {"anti_debug", "injection"})

    def test_keylogger_description_marks_audit_only(self) -> None:
        self.assertIn("AUDIT-ONLY", c.LABEL_DESCRIPTIONS["keylogger"])


class LabelRescopeTest(unittest.TestCase):
    def test_display_names_are_honest(self) -> None:
        self.assertEqual(c.LABEL_DISPLAY_NAMES["anti_debug"], "anti_debug_timing")
        self.assertEqual(c.LABEL_DISPLAY_NAMES["injection"], "rwx_alloc")

    def test_display_names_differ_from_internal_ids(self) -> None:
        """The rename is the point: internal id must not be the claim."""
        for label in c.ACTIVE_LABELS:
            self.assertNotEqual(c.LABEL_DISPLAY_NAMES[label], label)

    def test_descriptions_deny_the_capability_claim(self) -> None:
        self.assertIn("NOT debugger detection", c.LABEL_DESCRIPTIONS["anti_debug"])
        self.assertIn("NOT process injection", c.LABEL_DESCRIPTIONS["injection"])


class CensusGateTest(unittest.TestCase):
    def test_gate_matches_recorded_census(self) -> None:
        self.assertEqual(c.CENSUS_RULES_LOADED, 1031)
        self.assertEqual(c.CENSUS_RULES_FIRING, 12)
        self.assertEqual(c.CENSUS_RULES_PASSING, 1)

    def test_gate_thresholds(self) -> None:
        self.assertEqual(c.MIN_CENSUS_FUNCTIONS, 100)
        self.assertEqual(c.MIN_CENSUS_CLUSTERS, 10)
        self.assertEqual(c.MIN_CENSUS_FAMILIES, 3)
        self.assertEqual(c.MAX_CENSUS_TOP_CLUSTER_SHARE, 0.50)

    def test_secondary_tier_below_primary(self) -> None:
        self.assertLess(c.SECONDARY_CENSUS_FUNCTIONS, c.MIN_CENSUS_FUNCTIONS)


class EvaluationProtocolTest(unittest.TestCase):
    def test_protocol_version_is_grouped_kfold(self) -> None:
        self.assertEqual(c.EVAL_PROTOCOL_VERSION, "grouped-kfold-v3")
        self.assertEqual(c.N_FOLDS, 5)
        self.assertEqual(c.N_LOFO_REPEATS, 10)

    def test_contract_version_bumped_for_rescope(self) -> None:
        self.assertEqual(c.LABEL_CONTRACT_VERSION, "stage1-v3")
        self.assertEqual(c.LABEL_CONTRACT_NAME, "stage1-two-label-rescoped")


if __name__ == "__main__":
    unittest.main()
