"""Map CAPA-side RVA labels onto angr functions.

This module is deliberately pure: it takes the parser result and a list of
angr function/block ranges.  The angr extractor lives in
``src/extract/angr_cfg.py`` so mapping can be unit-tested without loading a
binary.

Mapping rules (frozen label contract v1):

* exact function-start match first, otherwise the containing function;
* exact block-start match first, otherwise the containing block;
* CAPA functions and blocks are RVAs; add the angr mapped base before lookup;
* a CAPA target match that does not map is logged, never converted to a
  negative;
* multiple CAPA functions mapping to one angr function union labels and set
  ``mapping_collision``.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable

from src.label.parse_capa import LABELS, CapaFunctionLabel, CapaParseResult


@dataclass(frozen=True)
class AngrBlock:
    va: int
    size: int

    @property
    def end(self) -> int:
        return self.va + max(self.size, 1)


@dataclass(frozen=True)
class AngrFunction:
    func_va: int
    blocks: tuple[AngrBlock, ...] = ()

    @property
    def start(self) -> int:
        return min((block.va for block in self.blocks), default=self.func_va)

    @property
    def end(self) -> int:
        return max((block.end for block in self.blocks), default=self.func_va + 1)

    @property
    def span(self) -> int:
        return max(self.end - self.start, 1)


@dataclass(frozen=True)
class _AddressMatch:
    function: AngrFunction | None
    block: AngrBlock | None
    method: str
    candidates: int


@dataclass
class MappingResult:
    sample_id: str
    rows: list[dict[str, Any]]
    summary: dict[str, Any]
    unresolved_capa_functions: list[dict[str, Any]] = field(default_factory=list)
    unresolved_target_matches: list[dict[str, Any]] = field(default_factory=list)
    collisions: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "rows": self.rows,
            "unresolved_capa_functions": self.unresolved_capa_functions,
            "unresolved_target_matches": self.unresolved_target_matches,
            "collisions": self.collisions,
        }


class _AddressIndex:
    def __init__(self, functions: Iterable[AngrFunction]) -> None:
        self.functions = sorted(functions, key=lambda item: item.func_va)
        self.by_start = {function.func_va: function for function in self.functions}
        self.block_exact: dict[int, tuple[AngrFunction, AngrBlock]] = {}
        self.block_ranges: list[tuple[int, int, AngrFunction, AngrBlock]] = []
        for function in self.functions:
            for block in function.blocks:
                self.block_exact.setdefault(block.va, (function, block))
                self.block_ranges.append((block.va, block.end, function, block))
        self.block_ranges.sort(key=lambda item: (item[1] - item[0], item[0]))

    def find_function(self, va: int) -> _AddressMatch:
        exact = self.by_start.get(va)
        if exact is not None:
            return _AddressMatch(exact, None, "exact", 1)
        candidates = [
            function
            for function in self.functions
            if function.start <= va < function.end
        ]
        if not candidates:
            return _AddressMatch(None, None, "unmapped", 0)
        candidates.sort(key=lambda function: (function.span, function.func_va))
        return _AddressMatch(candidates[0], None, "containment", len(candidates))

    def find_block(self, va: int) -> _AddressMatch:
        exact = self.block_exact.get(va)
        if exact is not None:
            return _AddressMatch(exact[0], exact[1], "exact", 1)
        candidates = [
            (function, block)
            for start, end, function, block in self.block_ranges
            if start <= va < end
        ]
        if not candidates:
            return _AddressMatch(None, None, "unmapped", 0)
        function, block = candidates[0]
        return _AddressMatch(function, block, "containment", len(candidates))


def _row(sample_id: str, function: AngrFunction) -> dict[str, Any]:
    return {
        "sample_id": sample_id,
        "func_va": function.func_va,
        "capa_func_va": None,
        "capa_func_vas": [],
        **{f"label_{label}": 0 for label in LABELS},
        "label_status": "unlabeled",
        "label_mask": 0,
        "matched_rules": [],
        "matched_block_vas": [],
        "mapping_method": "unmapped",
        "mapping_collision": False,
        "_methods": set(),
        "_rules": set(),
        "_blocks": set(),
    }


def _merge(
    row: dict[str, Any],
    capa_func: CapaFunctionLabel,
    *,
    labels: dict[str, int],
    rules: Iterable[str],
    block_vas: Iterable[int],
    method: str,
    collision: bool,
) -> None:
    if row["capa_func_va"] is None:
        row["capa_func_va"] = capa_func.capa_func_va
    if capa_func.capa_func_va not in row["capa_func_vas"]:
        row["capa_func_vas"].append(capa_func.capa_func_va)
    if row["capa_func_va"] != capa_func.capa_func_va:
        row["mapping_collision"] = True
    if collision:
        row["mapping_collision"] = True

    for label in LABELS:
        row[f"label_{label}"] = max(row[f"label_{label}"], int(labels.get(label, 0)))
    row["_rules"].update(rules)
    row["_blocks"].update(block_vas)
    row["_methods"].add(method)

    if any(row[f"label_{label}"] for label in LABELS):
        row["label_status"] = "positive"
        row["label_mask"] = 1
    elif row["label_status"] == "unlabeled":
        row["label_status"] = "weak_negative"
        row["label_mask"] = 1


def _finalize_row(row: dict[str, Any]) -> dict[str, Any]:
    methods = row.pop("_methods")
    row["matched_rules"] = sorted(row.pop("_rules"))
    row["matched_block_vas"] = sorted(row.pop("_blocks"))
    if "exact" in methods:
        row["mapping_method"] = "exact"
    elif "containment" in methods:
        row["mapping_method"] = "containment"
    else:
        row["mapping_method"] = "unmapped"
    row["capa_func_vas"] = sorted(row["capa_func_vas"])
    return row


def map_capa_to_angr(
    result: CapaParseResult,
    functions: Iterable[AngrFunction],
    *,
    angr_base: int,
    sample_id: str | None = None,
) -> MappingResult:
    """Map one sample's CAPA labels onto angr function ranges."""

    sample = sample_id or result.sample_id
    index = _AddressIndex(functions)
    rows = {function.func_va: _row(sample, function) for function in index.functions}
    mapped_capa: set[int] = set()
    unresolved_capa: list[dict[str, Any]] = []
    collisions: list[dict[str, Any]] = []
    unresolved_targets: list[dict[str, Any]] = []
    exact_functions = 0
    containment_functions = 0
    exact_blocks = 0
    containment_blocks = 0

    # The parser already found block matches that are absent from CAPA layout.
    for item in result.unresolved_block_matches:
        unresolved_targets.append({**item, "stage": "capa_layout", "match_count": 1})

    for capa_func in result.functions:
        function_match = index.find_function(angr_base + capa_func.capa_func_va)
        block_matches: dict[int, _AddressMatch] = {}
        for block_rva in capa_func.matched_block_vas:
            match = index.find_block(angr_base + block_rva)
            if match.function is None:
                # Function-scope evidence can point at an instruction whose
                # block was not recovered, or at a function start.  Fall back
                # to the containing function rather than dropping the match.
                function_match_fallback = index.find_function(angr_base + block_rva)
                if function_match_fallback.function is not None:
                    match = _AddressMatch(
                        function_match_fallback.function,
                        None,
                        function_match_fallback.method,
                        function_match_fallback.candidates,
                    )
            block_matches[block_rva] = match

        mapped_function = function_match.function
        if function_match.method == "exact":
            exact_functions += 1
        elif function_match.method == "containment":
            containment_functions += 1

        if capa_func.function_match_count:
            if mapped_function is not None:
                mapped_capa.add(capa_func.capa_func_va)
            else:
                unresolved_targets.append(
                    {
                        "capa_func_va": capa_func.capa_func_va,
                        "scope": "function",
                        "reason": "function not mapped to angr",
                        "match_count": capa_func.function_match_count,
                        "stage": "angr_mapping",
                    }
                )

        mapped_block_parents: list[AngrFunction] = []
        for block_rva, block_match in block_matches.items():
            count = capa_func.block_match_counts.get(block_rva, 1)
            if block_match.function is not None:
                mapped_block_parents.append(block_match.function)
                mapped_capa.add(capa_func.capa_func_va)
                if block_match.method == "exact":
                    exact_blocks += count
                else:
                    containment_blocks += count
            else:
                unresolved_targets.append(
                    {
                        "capa_func_va": capa_func.capa_func_va,
                        "address": block_rva,
                        "scope": "basic block",
                        "reason": "block not mapped to angr",
                        "match_count": count,
                        "stage": "angr_mapping",
                    }
                )

        # Function-scope matches label the mapped function only when CAPA did
        # not report evidence locations.  When it did, the evidence blocks are
        # the localisable part: label their angr parents, and keep the CAPA
        # function-start function as a weak negative if it is a different
        # angr function.  This avoids turning one large CAPA function into
        # dozens of unrelated positives when angr split it.
        labeled_targets: list[tuple[AngrFunction, str, dict[str, int]]] = []
        has_block_targets = bool(capa_func.matched_block_vas)
        has_function_evidence = capa_func.function_evidence_count > 0
        if (
            mapped_function is not None
            and not has_function_evidence
            and capa_func.function_match_count
        ):
            labeled_targets.append(
                (mapped_function, function_match.method, capa_func.function_labels)
            )
        for parent in mapped_block_parents:
            method = "exact" if any(
                match.function is not None and match.function.func_va == parent.func_va
                and match.method == "exact"
                for match in block_matches.values()
            ) else "containment"
            labeled_targets.append((parent, method, capa_func.block_labels))
        if mapped_function is not None and has_block_targets and not any(
            target.func_va == mapped_function.func_va
            for target, _method, _labels in labeled_targets
        ):
            labeled_targets.append(
                (mapped_function, function_match.method,
                 {label: 0 for label in LABELS})
            )

        if not labeled_targets and mapped_function is not None:
            # Weak negatives are attached to the CAPA function's own mapped
            # angr function, even when it has no target match.
            labeled_targets.append(
                (mapped_function, function_match.method, {label: 0 for label in LABELS})
            )

        if not labeled_targets:
            if capa_func.capa_func_va not in mapped_capa:
                unresolved_capa.append(
                    {
                        "capa_func_va": capa_func.capa_func_va,
                        "status": capa_func.status,
                        "reason": "CAPA function/block did not map to angr",
                    }
                )
            continue

        mapped_capa.add(capa_func.capa_func_va)
        for target, method, target_labels in labeled_targets:
            row = rows.get(target.func_va)
            if row is None:
                continue
            if (
                capa_func.block_match_count
                and mapped_function is not None
                and target.func_va != mapped_function.func_va
            ):
                collisions.append(
                    {
                        "type": "block_parent_mismatch",
                        "capa_func_va": capa_func.capa_func_va,
                        "function_va": mapped_function.func_va if mapped_function else None,
                        "block_parent_va": target.func_va,
                    }
                )
            block_vas = [
                match.block.va
                for match in block_matches.values()
                if match.block is not None and match.function is not None
                and match.function.func_va == target.func_va
            ]
            is_positive = any(target_labels.values())
            _merge(
                row,
                capa_func,
                labels=target_labels,
                rules=capa_func.matched_rules if is_positive else [],
                block_vas=block_vas if is_positive else [],
                method=method,
                collision=False,
            )

    # Any row that received more than one CAPA function is a many-to-one
    # collision, even if both source functions were individually mapped.
    for row in rows.values():
        if len(row["capa_func_vas"]) > 1:
            row["mapping_collision"] = True
            collisions.append(
                {
                    "type": "many_to_one",
                    "func_va": row["func_va"],
                    "capa_func_vas": sorted(row["capa_func_vas"]),
                }
            )

    output_rows = [_finalize_row(row) for row in rows.values()]
    output_rows.sort(key=lambda row: row["func_va"])

    target_matches = result.raw_target_match_count
    unresolved_match_count = sum(
        item.get("match_count", 1) for item in unresolved_targets
    )
    mapped_target_matches = max(target_matches - unresolved_match_count, 0)
    status_counts = Counter(row["label_status"] for row in output_rows)
    label_counts = {
        label: sum(int(row[f"label_{label}"]) for row in output_rows)
        for label in LABELS
    }
    summary = {
        "sample_id": sample,
        "capa_base_address": result.base_address,
        "capa_normalization": result.normalization,
        "angr_base": angr_base,
        "angr_functions": len(output_rows),
        "capa_observed": len(result.functions),
        "mapped_capa_functions": len(mapped_capa),
        "unresolved_capa_functions": len(unresolved_capa),
        "capa_mapping_coverage": (
            len(mapped_capa) / len(result.functions) if result.functions else 0.0
        ),
        "target_matches": target_matches,
        "mapped_target_matches": mapped_target_matches,
        "unresolved_target_matches": unresolved_match_count,
        "target_match_coverage": (
            mapped_target_matches / target_matches if target_matches else 0.0
        ),
        "exact_function_mappings": exact_functions,
        "containment_function_mappings": containment_functions,
        "exact_block_mappings": exact_blocks,
        "containment_block_mappings": containment_blocks,
        "many_to_one_collisions": sum(
            1 for item in collisions if item.get("type") == "many_to_one"
        ),
        "block_parent_mismatches": sum(
            1 for item in collisions if item.get("type") == "block_parent_mismatch"
        ),
        "status_counts": dict(status_counts),
        "label_counts": label_counts,
        "labeled_functions": status_counts.get("positive", 0) + status_counts.get("weak_negative", 0),
    }
    return MappingResult(
        sample_id=sample,
        rows=output_rows,
        summary=summary,
        unresolved_capa_functions=unresolved_capa,
        unresolved_target_matches=unresolved_targets,
        collisions=collisions,
    )


def aggregate_mapping_summaries(results: Iterable[MappingResult]) -> dict[str, Any]:
    results = list(results)
    totals: Counter[str] = Counter()
    label_totals: Counter[str] = Counter()
    status_totals: Counter[str] = Counter()
    for result in results:
        summary = result.summary
        for key in (
            "angr_functions",
            "capa_observed",
            "mapped_capa_functions",
            "unresolved_capa_functions",
            "target_matches",
            "mapped_target_matches",
            "unresolved_target_matches",
            "exact_function_mappings",
            "containment_function_mappings",
            "exact_block_mappings",
            "containment_block_mappings",
            "many_to_one_collisions",
            "block_parent_mismatches",
            "labeled_functions",
        ):
            totals[key] += int(summary.get(key, 0))
        for label, count in summary.get("label_counts", {}).items():
            label_totals[label] += count
        for status, count in summary.get("status_counts", {}).items():
            status_totals[status] += count

    observed = totals["capa_observed"]
    targets = totals["target_matches"]
    return {
        "samples": len(results),
        **{key: value for key, value in totals.items()},
        "label_counts": dict(label_totals),
        "status_counts": dict(status_totals),
        "capa_mapping_coverage": (
            totals["mapped_capa_functions"] / observed if observed else 0.0
        ),
        "target_match_coverage": (
            totals["mapped_target_matches"] / targets if targets else 0.0
        ),
    }
