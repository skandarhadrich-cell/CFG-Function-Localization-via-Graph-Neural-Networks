"""Tests for pilot sample selection."""

from __future__ import annotations

import unittest
from collections import Counter

from src.label.run_capa import Sample, select_pilot, select_stage1_pilot


def samples() -> list[Sample]:
    rows: list[Sample] = []
    for bucket in ("keylogger", "injection", "antidebug"):
        for index in range(40):
            rows.append(
                Sample(
                    sample_id=f"{bucket}-{index:02d}",
                    filepath=f"data/raw/{bucket}/{index}.exe",
                    source_bucket=bucket,
                    family=f"{bucket}-fam",
                )
            )
    return rows


def assignments(rows: list[Sample]) -> dict[str, str]:
    return {
        row.sample_id: ("test" if int(row.sample_id[-2:]) % 5 == 0 else "train")
        for row in rows
    }


class PilotSamplingTests(unittest.TestCase):
    def test_keylogger_train_val_are_all_selected(self) -> None:
        rows = samples()
        split = assignments(rows)
        selected = select_pilot(rows, split, target=50, seed=42)
        self.assertEqual(len(selected), 50)

        selected_keyloggers = [
            row.sample_id for row in selected if row.source_bucket == "keylogger"
        ]
        expected_keyloggers = [
            row.sample_id
            for row in rows
            if row.source_bucket == "keylogger" and split[row.sample_id] != "test"
        ]
        self.assertEqual(sorted(selected_keyloggers), sorted(expected_keyloggers))

    def test_no_test_samples_are_selected(self) -> None:
        rows = samples()
        split = assignments(rows)
        selected = select_pilot(rows, split, target=100, seed=42)
        self.assertTrue(all(split[row.sample_id] != "test" for row in selected))

    def test_selection_is_deterministic(self) -> None:
        rows = samples()
        split = assignments(rows)
        first = select_pilot(rows, split, target=75, seed=42)
        second = select_pilot(rows, split, target=75, seed=42)
        self.assertEqual(
            [row.sample_id for row in first],
            [row.sample_id for row in second],
        )


class Stage1SamplingTests(unittest.TestCase):
    def _rows(self) -> tuple[list[Sample], dict[str, str]]:
        rows: list[Sample] = []
        splits: dict[str, str] = {}
        for cluster in range(30):
            for member in range(6):
                sample_id = f"c{cluster:02d}-{member}"
                rows.append(
                    Sample(
                        sample_id=sample_id,
                        filepath=f"data/raw/x/{sample_id}.exe",
                        source_bucket="antidebug" if cluster % 2 else "injection",
                        family=f"fam-{cluster % 5}",
                        cluster_key=f"imphash:{cluster:02d}",
                    )
                )
                splits[sample_id] = "test" if member == 5 else "train"
        return rows, splits

    def test_stage1_never_selects_test(self) -> None:
        rows, splits = self._rows()
        selected = select_stage1_pilot(rows, splits, target=100, seed=42)
        self.assertEqual(len(selected), 100)
        self.assertTrue(all(splits[row.sample_id] != "test" for row in selected))

    def test_stage1_respects_per_cluster_cap(self) -> None:
        rows, splits = self._rows()
        selected = select_stage1_pilot(rows, splits, target=200, seed=42, max_per_cluster=4)
        counts = Counter(
            row.cluster_key or row.sample_id for row in selected
        )
        self.assertTrue(counts)
        self.assertLessEqual(max(counts.values()), 4)

    def test_stage1_deterministic(self) -> None:
        rows, splits = self._rows()
        first = select_stage1_pilot(rows, splits, target=120, seed=42)
        second = select_stage1_pilot(rows, splits, target=120, seed=42)
        self.assertEqual(
            [row.sample_id for row in first],
            [row.sample_id for row in second],
        )


if __name__ == "__main__":
    unittest.main()
