"""Tests for the frozen CAPA three-state label parser."""

from __future__ import annotations

import unittest

from src.label.parse_capa import aggregate_summaries, parse_capa_document

BASE = 0x400000


def addr(value: int) -> dict:
    return {"type": "absolute", "value": value}


def rel(value: int) -> dict:
    return {"type": "relative", "value": value}


def rule(
    name: str,
    namespace: str,
    scope: str,
    matches: list[tuple[dict, dict]],
) -> dict:
    return {
        "meta": {"name": name, "namespace": namespace, "scopes": {"static": scope}},
        "matches": [[address, match] for address, match in matches],
    }


def document(*, relative: bool = False) -> dict:
    def make_addr(value: int) -> dict:
        return rel(value) if relative else addr(BASE + value)
    return {
        "meta": {
            "version": "capa 9.1.0",
            "analysis": {
                "base_address": addr(BASE),
                "feature_counts": {
                    "functions": [
                        {"address": make_addr(0x1000), "count": 2},
                        {"address": make_addr(0x2000), "count": 3},
                        {"address": make_addr(0x3000), "count": 4},
                        {"address": make_addr(0x4000), "count": 5},
                    ]
                },
                "layout": {
                    "functions": [
                        {
                            "address": make_addr(0x1000),
                            "matched_basic_blocks": [
                                {"address": make_addr(0x1000)},
                                {"address": make_addr(0x1010)},
                            ],
                        }
                    ]
                },
            },
        },
        "rules": {
            "anti-debug function": rule(
                "anti-debug function",
                "anti-analysis/anti-debugging/debugger-detection",
                "function",
                [(make_addr(0x2000), {})],
            ),
            "inject block": rule(
                "inject block",
                "host-interaction/process/inject",
                "basic block",
                [(make_addr(0x1010), {})],
            ),
            "keylog function": rule(
                "keylog function",
                "collection/keylog",
                "function",
                [(make_addr(0x3000), {})],
            ),
            "unrelated function": rule(
                "unrelated function",
                "host-interaction/file-system",
                "function",
                [(make_addr(0x4000), {})],
            ),
            "file target ignored": rule(
                "file target ignored",
                "load-code/pe/inject-shellcode",
                "file",
                [(make_addr(0x5000), {})],
            ),
            "orphan block": rule(
                "orphan block",
                "collection/keylog",
                "basic block",
                [(make_addr(0x9000), {})],
            ),
        },
    }


class ParseCapaTests(unittest.TestCase):
    def test_function_and_block_matches_become_positive(self) -> None:
        result = parse_capa_document(document(), sample_id="sample")
        by_addr = {func.capa_func_va: func for func in result.functions}

        self.assertEqual(set(by_addr), {0x1000, 0x2000, 0x3000, 0x4000})
        self.assertEqual(by_addr[0x1000].labels["injection"], 1)
        self.assertEqual(by_addr[0x1000].block_labels["injection"], 1)
        self.assertEqual(by_addr[0x1000].function_labels["injection"], 0)
        self.assertEqual(by_addr[0x1000].matched_block_vas, [0x1010])
        self.assertEqual(by_addr[0x2000].labels["anti_debug"], 1)
        self.assertEqual(by_addr[0x2000].function_labels["anti_debug"], 1)
        self.assertEqual(by_addr[0x3000].labels["keylogger"], 1)
        self.assertEqual(by_addr[0x4000].status, "weak_negative")
        self.assertTrue(all(value == 0 for value in by_addr[0x4000].labels.values()))
        self.assertEqual(result.positive_count, 3)
        self.assertEqual(result.weak_negative_count, 1)
        self.assertEqual(result.label_counts, {"anti_debug": 1, "keylogger": 1, "injection": 1})

    def test_unresolved_block_is_logged_not_dropped(self) -> None:
        result = parse_capa_document(document(), sample_id="sample")
        self.assertEqual(len(result.unresolved_block_matches), 1)
        unresolved = result.unresolved_block_matches[0]
        self.assertEqual(unresolved["rule"], "orphan block")
        self.assertEqual(unresolved["address"], 0x9000)
        self.assertEqual(unresolved["reason"], "block not present in layout.functions")

    def test_file_scope_target_is_ignored(self) -> None:
        result = parse_capa_document(document(), sample_id="sample")
        self.assertEqual(result.ignored_scope_counts, {"file": 1})

    def test_relative_addresses_are_not_rebased_twice(self) -> None:
        result = parse_capa_document(document(relative=True), sample_id="sample")
        self.assertEqual(result.normalization, "capa_absolute_minus_base")
        self.assertEqual(
            [func.capa_func_va for func in result.functions],
            [0x1000, 0x2000, 0x3000, 0x4000],
        )
        self.assertEqual(result.functions[0].matched_block_vas, [0x1010])

    def test_fallback_to_meta_scope(self) -> None:
        doc = document()
        for item in doc["rules"].values():
            item["meta"]["scopes"] = {}
            item["meta"]["scope"] = "function"
        result = parse_capa_document(doc, sample_id="sample")
        # The original block rule now has function scope, so its address is a
        # function match rather than an orphaned block.
        self.assertEqual(result.unresolved_block_matches, [])
        self.assertEqual(result.positive_count, 5)

    def test_multiple_capa_functions_can_share_labels(self) -> None:
        doc = document()
        doc["rules"]["second keylog"] = rule(
            "second keylog",
            "collection/keylog",
            "function",
            [(addr(BASE + 0x3000), {})],
        )
        result = parse_capa_document(doc, sample_id="sample")
        keylog = next(func for func in result.functions if func.capa_func_va == 0x3000)
        self.assertEqual(sorted(keylog.matched_rules), ["keylog function", "second keylog"])

    def test_aggregate_summaries(self) -> None:
        result = parse_capa_document(document(), sample_id="sample")
        aggregate = aggregate_summaries([result, result])
        self.assertEqual(aggregate["samples"], 2)
        self.assertEqual(aggregate["capa_observed"], 8)
        self.assertEqual(aggregate["capa_matched"], 6)
        self.assertEqual(aggregate["capa_weak_negative"], 2)
        self.assertEqual(aggregate["unresolved_block_matches"], 2)


if __name__ == "__main__":
    unittest.main()


class EvidenceLocationTests(unittest.TestCase):
    def test_function_scope_evidence_is_localised(self) -> None:
        doc = document()
        doc["rules"]["anti-debug function"]["matches"] = [
            [
                addr(BASE + 0x2000),
                {
                    "success": True,
                    "children": [
                        {"locations": [addr(BASE + 0x3008)]},
                    ],
                },
            ]
        ]
        result = parse_capa_document(doc, sample_id="sample")
        anti = next(func for func in result.functions if func.capa_func_va == 0x2000)
        self.assertEqual(anti.function_match_count, 1)
        self.assertEqual(anti.matched_block_vas, [0x3008])
        self.assertEqual(anti.block_labels["anti_debug"], 1)
        self.assertEqual(anti.function_labels["anti_debug"], 1)
