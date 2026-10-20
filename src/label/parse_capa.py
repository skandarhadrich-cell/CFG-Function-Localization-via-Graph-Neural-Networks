"""Parse CAPA 9.1 JSON into the frozen three-state function label contract.

The parser is deliberately independent of angr.  It produces CAPA-side
function labels in RVA space; :mod:`src.label.mapping` maps those to angr
functions later.

Key rules from ``docs/labeling_contract.md``:

* ``meta.analysis.feature_counts.functions`` is the observed inventory.
* ``meta.analysis.layout.functions`` is only a block-to-parent map.
* Rule scopes come from ``meta.scopes.static``.
* Only static function and basic-block target matches are labels.
* An observed function with no target match is a weak negative, not benign.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

LABELS = ("anti_debug", "keylogger", "injection")

# Prefixes are intentional: CAPA namespaces are hierarchical.  The
# load-code prefix includes its trailing hyphen so it cannot accidentally
# swallow unrelated load-code namespaces.
DEFAULT_NAMESPACES: dict[str, tuple[str, ...]] = {
    "anti_debug": ("anti-analysis/anti-debugging",),
    "keylogger": ("collection/keylog",),
    "injection": (
        "host-interaction/process/inject",
        "load-code/pe/inject-",
    ),
}


@dataclass
class CapaFunctionLabel:
    capa_func_va: int
    labels: dict[str, int]
    function_labels: dict[str, int] = field(default_factory=dict)
    block_labels: dict[str, int] = field(default_factory=dict)
    matched_rules: list[str] = field(default_factory=list)
    matched_block_vas: list[int] = field(default_factory=list)
    block_match_counts: dict[int, int] = field(default_factory=dict)
    function_match_count: int = 0
    block_match_count: int = 0

    @property
    def status(self) -> str:
        return "positive" if any(self.labels.values()) else "weak_negative"

    def as_dict(self) -> dict[str, Any]:
        return {
            "capa_func_va": self.capa_func_va,
            **{f"label_{label}": self.labels.get(label, 0) for label in LABELS},
            "function_labels": self.function_labels,
            "block_labels": self.block_labels,
            "label_status": self.status,
            "matched_rules": self.matched_rules,
            "matched_block_vas": self.matched_block_vas,
            "block_match_counts": self.block_match_counts,
            "function_match_count": self.function_match_count,
            "block_match_count": self.block_match_count,
        }


@dataclass
class CapaParseResult:
    sample_id: str
    base_address: int
    normalization: str
    capa_version: str | None
    functions: list[CapaFunctionLabel]
    unresolved_block_matches: list[dict[str, Any]]
    ignored_scope_counts: dict[str, int]
    rule_match_counts: dict[str, int]
    raw_observed_count: int
    raw_target_match_count: int

    @property
    def positive_count(self) -> int:
        return sum(func.status == "positive" for func in self.functions)

    @property
    def weak_negative_count(self) -> int:
        return sum(func.status == "weak_negative" for func in self.functions)

    @property
    def function_match_count(self) -> int:
        return sum(func.function_match_count for func in self.functions)

    @property
    def block_match_count(self) -> int:
        return sum(func.block_match_count for func in self.functions)

    @property
    def label_counts(self) -> dict[str, int]:
        counts = {label: 0 for label in LABELS}
        for func in self.functions:
            for label in LABELS:
                counts[label] += int(func.labels.get(label, 0))
        return counts

    def summary(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "base_address": self.base_address,
            "normalization": self.normalization,
            "capa_version": self.capa_version,
            "raw_observed_count": self.raw_observed_count,
            "capa_observed": len(self.functions),
            "capa_matched": self.positive_count,
            "capa_weak_negative": self.weak_negative_count,
            "label_counts": self.label_counts,
            "function_match_count": self.function_match_count,
            "block_match_count": self.block_match_count,
            "target_rule_matches": self.raw_target_match_count,
            "unresolved_block_matches": len(self.unresolved_block_matches),
            "ignored_scope_counts": self.ignored_scope_counts,
            "rule_match_counts": self.rule_match_counts,
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            **self.summary(),
            "functions": [func.as_dict() for func in self.functions],
            "unresolved_block_matches": self.unresolved_block_matches,
        }


def _address_raw(obj: Any) -> int | None:
    """Return the numeric portion of a CAPA address without rebasing it."""

    if obj is None:
        return None
    if isinstance(obj, bool):
        raise ValueError(f"invalid address: {obj!r}")
    if isinstance(obj, int):
        return obj
    if isinstance(obj, str):
        return int(obj, 0)
    if isinstance(obj, dict):
        kind = obj.get("type")
        if kind == "no address":
            return None
        value = obj.get("value")
        if value is None:
            return None
        return int(value, 0) if isinstance(value, str) else int(value)
    raise ValueError(f"unsupported address: {obj!r}")


def _to_rva(obj: Any, base: int) -> int | None:
    """Normalize a CAPA address to an RVA.

    CAPA 9.1 normally emits absolute addresses.  ``relative`` addresses are
    already RVA-like and are not rebased again.
    """

    raw = _address_raw(obj)
    if raw is None:
        return None
    if isinstance(obj, dict) and obj.get("type") == "relative":
        return raw
    return raw - base


def _iter_items(value: Any) -> Iterable[Any]:
    if isinstance(value, dict):
        return value.values()
    return value or []


def _match_pairs(matches: Any) -> Iterable[tuple[Any, Any]]:
    for item in matches or []:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            yield item[0], item[1]
        elif isinstance(item, dict) and "address" in item:
            yield item["address"], item
        else:
            raise ValueError(f"unsupported CAPA match entry: {item!r}")


def _scope(rule_meta: dict[str, Any]) -> str | None:
    scopes = rule_meta.get("scopes") or {}
    if isinstance(scopes, dict) and scopes.get("static"):
        return scopes["static"]
    # Some older/third-party rule sets use meta.scope.  It is only a fallback:
    # CAPA 9.1 commonly leaves it null while meta.scopes.static is populated.
    return rule_meta.get("scope")


def _matches_label(namespace: str, prefixes: dict[str, tuple[str, ...]]) -> list[str]:
    return [
        label
        for label, label_prefixes in prefixes.items()
        if any(namespace == prefix or namespace.startswith(prefix) for prefix in label_prefixes)
    ]


def parse_capa_document(
    document: dict[str, Any],
    *,
    sample_id: str = "",
    namespaces: dict[str, tuple[str, ...]] | None = None,
) -> CapaParseResult:
    """Parse one CAPA JSON document.

    Addresses in the result are RVAs.  ``raw_observed_count`` is the number of
    distinct CAPA-side observed addresses before duplicate protection.
    """

    prefixes = namespaces or DEFAULT_NAMESPACES
    meta = document.get("meta") or {}
    analysis = meta.get("analysis") or {}
    base = _address_raw(analysis.get("base_address")) or 0
    normalization = "capa_absolute_minus_base" if base else "capa_absolute"

    feature_functions = {
        rva
        for rva in (
            _to_rva(item.get("address"), base)
            for item in _iter_items((analysis.get("feature_counts") or {}).get("functions"))
        )
        if rva is not None
    }

    block_to_parent: dict[int, int] = {}
    layout_functions: set[int] = set()
    for layout in _iter_items((analysis.get("layout") or {}).get("functions")):
        func_rva = _to_rva(layout.get("address"), base)
        if func_rva is None:
            continue
        layout_functions.add(func_rva)
        for block in layout.get("matched_basic_blocks") or []:
            block_rva = _to_rva(block.get("address"), base)
            if block_rva is not None:
                block_to_parent.setdefault(block_rva, func_rva)

    matched: dict[int, CapaFunctionLabel] = {}

    def get_function(func_rva: int) -> CapaFunctionLabel:
        return matched.setdefault(
            func_rva,
            CapaFunctionLabel(
                capa_func_va=func_rva,
                labels={label: 0 for label in LABELS},
                function_labels={label: 0 for label in LABELS},
                block_labels={label: 0 for label in LABELS},
            ),
        )

    unresolved: list[dict[str, Any]] = []
    ignored_scopes: Counter[str] = Counter()
    rule_match_counts: Counter[str] = Counter()
    target_match_count = 0

    for rule in _iter_items(document.get("rules")):
        rule_meta = rule.get("meta") or {}
        namespace = rule_meta.get("namespace") or ""
        label_names = _matches_label(namespace, prefixes)
        if not label_names:
            continue

        scope = _scope(rule_meta)
        if scope not in {"function", "basic block"}:
            ignored_scopes[scope or "missing"] += 1
            continue

        rule_name = rule_meta.get("name") or "<unnamed>"
        for address_obj, _match in _match_pairs(rule.get("matches")):
            target_match_count += 1
            rule_match_counts[rule_name] += 1
            target_rva = _to_rva(address_obj, base)
            if target_rva is None:
                unresolved.append(
                    {
                        "rule": rule_name,
                        "namespace": namespace,
                        "scope": scope,
                        "address": None,
                        "reason": "no address",
                    }
                )
                continue

            if scope == "function":
                func_rva = target_rva
                block_rva = None
            else:
                func_rva = block_to_parent.get(target_rva)
                block_rva = target_rva
                if func_rva is None:
                    unresolved.append(
                        {
                            "rule": rule_name,
                            "namespace": namespace,
                            "scope": scope,
                            "address": target_rva,
                            "reason": "block not present in layout.functions",
                        }
                    )
                    continue

            entry = get_function(func_rva)
            if scope == "function":
                entry.function_match_count += 1
            else:
                entry.block_match_count += 1
            if rule_name not in entry.matched_rules:
                entry.matched_rules.append(rule_name)
            if block_rva is not None:
                entry.block_match_counts[block_rva] = entry.block_match_counts.get(block_rva, 0) + 1
                if block_rva not in entry.matched_block_vas:
                    entry.matched_block_vas.append(block_rva)
            for label in label_names:
                entry.labels[label] = 1
                if scope == "function":
                    entry.function_labels[label] = 1
                else:
                    entry.block_labels[label] = 1
        rule_match_counts[f"namespace:{namespace}"] += len(rule.get("matches") or [])

    # Observed inventory: feature counts plus defensive layout entries plus
    # function-scope/block-scope target matches.  Layout is expected to be a
    # subset of feature counts, but the contract asks us to keep it defensively.
    observed = feature_functions | layout_functions | set(matched)
    for func_rva in sorted(observed):
        get_function(func_rva)

    functions = sorted(matched.values(), key=lambda item: item.capa_func_va)
    for func in functions:
        func.matched_rules.sort()
        func.matched_block_vas.sort()

    return CapaParseResult(
        sample_id=sample_id,
        base_address=base,
        normalization=normalization,
        capa_version=meta.get("version"),
        functions=functions,
        unresolved_block_matches=unresolved,
        ignored_scope_counts=dict(sorted(ignored_scopes.items())),
        rule_match_counts=dict(sorted(rule_match_counts.items())),
        raw_observed_count=len(feature_functions | layout_functions),
        raw_target_match_count=target_match_count,
    )


def parse_capa_file(
    path: Path,
    *,
    sample_id: str | None = None,
    namespaces: dict[str, tuple[str, ...]] | None = None,
) -> CapaParseResult:
    with path.open() as fh:
        document = json.load(fh)
    return parse_capa_document(
        document,
        sample_id=sample_id or path.stem,
        namespaces=namespaces,
    )


def aggregate_summaries(results: Iterable[CapaParseResult]) -> dict[str, Any]:
    results = list(results)
    totals: Counter[str] = Counter()
    label_totals: Counter[str] = Counter()
    ignored: Counter[str] = Counter()
    unresolved = 0
    for result in results:
        summary = result.summary()
        totals["samples"] += 1
        totals["capa_observed"] += summary["capa_observed"]
        totals["capa_matched"] += summary["capa_matched"]
        totals["capa_weak_negative"] += summary["capa_weak_negative"]
        totals["function_match_count"] += summary["function_match_count"]
        totals["block_match_count"] += summary["block_match_count"]
        totals["target_rule_matches"] += summary["target_rule_matches"]
        totals["unresolved_block_matches"] += summary["unresolved_block_matches"]
        unresolved += summary["unresolved_block_matches"]
        for label, count in summary["label_counts"].items():
            label_totals[label] += count
        for scope, count in summary["ignored_scope_counts"].items():
            ignored[scope] += count

    return {
        "samples": totals["samples"],
        "capa_observed": totals["capa_observed"],
        "capa_matched": totals["capa_matched"],
        "capa_weak_negative": totals["capa_weak_negative"],
        "function_match_count": totals["function_match_count"],
        "block_match_count": totals["block_match_count"],
        "target_rule_matches": totals["target_rule_matches"],
        "unresolved_block_matches": unresolved,
        "label_counts": dict(label_totals),
        "ignored_scope_counts": dict(sorted(ignored.items())),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Parse CAPA JSON into three-state labels.")
    parser.add_argument("input", type=Path, help="CAPA JSON file or directory")
    parser.add_argument("--out", type=Path, help="write sample-level JSONL here")
    parser.add_argument("--summary-out", type=Path, help="write aggregate JSON here")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    if args.input.is_dir():
        paths = sorted(
            path
            for path in args.input.glob("*.json")
            if not path.name.startswith("_") and not path.name.endswith(".meta.json")
        )
    else:
        paths = [args.input]
    if not paths:
        raise SystemExit(f"no CAPA JSON found under {args.input}")

    results = [parse_capa_file(path) for path in paths]
    aggregate = aggregate_summaries(results)
    aggregate["input"] = str(args.input)
    aggregate["files"] = len(paths)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("w") as fh:
            for result in results:
                fh.write(json.dumps(result.as_dict(), sort_keys=True) + "\n")
    if args.summary_out:
        args.summary_out.parent.mkdir(parents=True, exist_ok=True)
        args.summary_out.write_text(json.dumps(aggregate, indent=2) + "\n")

    if not args.quiet:
        print(json.dumps(aggregate, indent=2))
        if len(results) <= 5:
            for result in results:
                print(json.dumps(result.summary(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
