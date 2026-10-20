"""Tests for CAPA-to-angr address mapping."""

from __future__ import annotations

import unittest

from src.label.mapping import AngrBlock, AngrFunction, map_capa_to_angr
from src.label.parse_capa import parse_capa_document

BASE = 0x400000


def addr(value: int) -> dict:
    return {"type": "absolute", "value": BASE + value}


def rule(name: str, namespace: str, scope: str, addresses: list[int]) -> dict:
    return {
        "meta": {"name": name, "namespace": namespace, "scopes": {"static": scope}},
        "matches": [[addr(address), {}] for address in addresses],
    }


def doc() -> dict:
    return {
        "meta": {
            "version": "capa 9.1.0",
            "analysis": {
                "base_address": {"type": "absolute", "value": BASE},
                "feature_counts": {
                    "functions": [
                        {"address": addr(offset), "count": 1}
                        for offset in (0x1000, 0x2000, 0x3000, 0x4008, 0x5000, 0x8000, 0x7000, 0x7008)
                    ]
                },
                "layout": {
                    "functions": [
                        {
                            "address": addr(0x1000),
                            "matched_basic_blocks": [
                                {"address": addr(0x1000)},
                                {"address": addr(0x1010)},
                            ],
                        }
                    ]
                },
            },
        },
        "rules": {
            "inject block": rule(
                "inject block",
                "host-interaction/process/inject",
                "basic block",
                [0x1010],
            ),
            "anti function": rule(
                "anti function",
                "anti-analysis/anti-debugging",
                "function",
                [0x2000],
            ),
            "keylog function": rule(
                "keylog function",
                "collection/keylog",
                "function",
                [0x3000],
            ),
            "unmapped anti": rule(
                "unmapped anti",
                "anti-analysis/anti-debugging",
                "function",
                [0x9000],
            ),
        },
    }


def functions() -> list[AngrFunction]:
    return [
        AngrFunction(
            0x401000,
            (
                AngrBlock(0x401000, 0x10),
                AngrBlock(0x401010, 0x10),
            ),
        ),
        AngrFunction(0x402000, (AngrBlock(0x402000, 0x20),)),
        AngrFunction(0x403000, (AngrBlock(0x403000, 0x20),)),
        AngrFunction(0x404000, (AngrBlock(0x404000, 0x20),)),
        AngrFunction(0x405000, (AngrBlock(0x405000, 0x20),)),
        AngrFunction(0x406000, (AngrBlock(0x406000, 0x20),)),
        AngrFunction(0x407000, (AngrBlock(0x407000, 0x20),)),
    ]


class MappingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.result = parse_capa_document(doc(), sample_id="sample")
        self.mapping = map_capa_to_angr(
            self.result,
            functions(),
            angr_base=BASE,
            sample_id="sample",
        )
        self.rows = {row["func_va"]: row for row in self.mapping.rows}

    def test_positive_exact_and_block_mapping(self) -> None:
        self.assertEqual(self.rows[0x401000]["label_status"], "positive")
        self.assertEqual(self.rows[0x401000]["label_injection"], 1)
        self.assertEqual(self.rows[0x401000]["mapping_method"], "exact")
        self.assertEqual(self.rows[0x401000]["matched_block_vas"], [0x401010])

        self.assertEqual(self.rows[0x402000]["label_anti_debug"], 1)
        self.assertEqual(self.rows[0x403000]["label_keylogger"], 1)

    def test_weak_negative_and_containment(self) -> None:
        self.assertEqual(self.rows[0x404000]["label_status"], "weak_negative")
        self.assertEqual(self.rows[0x404000]["label_mask"], 1)
        self.assertEqual(self.rows[0x404000]["mapping_method"], "containment")
        self.assertEqual(self.rows[0x405000]["label_status"], "weak_negative")

    def test_unlabeled_function_is_masked_out(self) -> None:
        self.assertEqual(self.rows[0x406000]["label_status"], "unlabeled")
        self.assertEqual(self.rows[0x406000]["label_mask"], 0)
        self.assertEqual(self.rows[0x406000]["capa_func_va"], None)

    def test_many_to_one_collision_unions_labels(self) -> None:
        row = self.rows[0x407000]
        self.assertEqual(row["label_status"], "weak_negative")
        self.assertTrue(row["mapping_collision"])
        self.assertEqual(row["capa_func_vas"], [0x7000, 0x7008])

    def test_unresolved_target_is_logged(self) -> None:
        unresolved = self.mapping.unresolved_target_matches
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(unresolved[0]["capa_func_va"], 0x9000)
        self.assertEqual(unresolved[0]["match_count"], 1)
        self.assertEqual(self.mapping.summary["target_matches"], 4)
        self.assertEqual(self.mapping.summary["mapped_target_matches"], 3)
        self.assertAlmostEqual(self.mapping.summary["target_match_coverage"], 0.75)

    def test_unresolved_capa_function_is_logged(self) -> None:
        self.assertEqual(len(self.mapping.unresolved_capa_functions), 2)
        self.assertEqual(
            sorted(item["capa_func_va"] for item in self.mapping.unresolved_capa_functions),
            [0x8000, 0x9000],
        )
        self.assertAlmostEqual(self.mapping.summary["capa_mapping_coverage"], 7 / 9)

    def test_label_census(self) -> None:
        self.assertEqual(self.mapping.summary["label_counts"]["injection"], 1)
        self.assertEqual(self.mapping.summary["label_counts"]["anti_debug"], 1)
        self.assertEqual(self.mapping.summary["label_counts"]["keylogger"], 1)
        self.assertEqual(
            self.mapping.summary["status_counts"],
            {"positive": 3, "weak_negative": 3, "unlabeled": 1},
        )


if __name__ == "__main__":
    unittest.main()
