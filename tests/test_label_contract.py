"""Tests for the three-target label contract.

The reset restores the original three targets.  These tests pin that decision
so a later experiment cannot silently drop keylogger again.
"""

from __future__ import annotations

import unittest

from src.label import contract as c


class ActiveLabelsTest(unittest.TestCase):
    def test_three_active_labels(self) -> None:
        self.assertEqual(c.ACTIVE_LABELS, ("anti_debug", "keylogger", "injection"))
        self.assertEqual(c.ALL_LABELS, c.ACTIVE_LABELS)

    def test_outputs_match_labels(self) -> None:
        self.assertEqual(c.N_OUTPUTS, 3)

    def test_display_names_are_the_targets(self) -> None:
        for label in c.ACTIVE_LABELS:
            self.assertEqual(c.LABEL_DISPLAY_NAMES[label], label)

    def test_descriptions_are_present(self) -> None:
        for label in c.ACTIVE_LABELS:
            self.assertTrue(c.LABEL_DESCRIPTIONS[label])


class ContractTest(unittest.TestCase):
    def test_version(self) -> None:
        self.assertEqual(c.LABEL_CONTRACT_VERSION, "stage1-three-target-v1")
        self.assertEqual(c.LABEL_CONTRACT_NAME, "three-target-function-localization")

    def test_zero_rule_policy(self) -> None:
        self.assertEqual(c.ZERO_RULE_POLICY, "exclude_from_loss_not_negative")

    def test_diversity_thresholds_are_preregistered(self) -> None:
        self.assertEqual(c.MIN_POSITIVE_BINARIES, 20)
        self.assertEqual(c.MIN_POSITIVE_CLUSTERS, 10)
        self.assertEqual(c.MIN_POSITIVE_FAMILIES, 3)
        self.assertEqual(c.MAX_SINGLE_BINARY_SHARE, 0.50)
        self.assertEqual(c.MAX_SINGLE_CLUSTER_SHARE, 0.50)


if __name__ == "__main__":
    unittest.main()
