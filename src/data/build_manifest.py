"""Build the Phase 0 manifest and frozen train/val/test splits.

The manifest is the single source of truth for sample identity, quality flags,
family metadata, and grouping keys.  Splits are generated from the clean subset
only and bind to the manifest by SHA-256.

Usage::

    python -m src.data.build_manifest --config configs/phase0.toml
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import random
import statistics
import sys
import tomllib
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import numpy as np
import pefile
from tqdm import tqdm

from src.data.repair_pe import PEError, parse_header

ROOT = Path(__file__).resolve().parents[2]

EXCLUDE_FLAGS = {
    "no_pe",
    "parse_error",
    "dotnet",
    "packed",
    "non_bodmas",
    "unknown_arch",
}

MANIFEST_FIELDS = [
    "sample_id",
    "filepath",
    "source_bucket",
    "family",
    "in_bodmas",
    "content_sha256",
    "imphash",
    "cluster_key",
    "arch",
    "original_machine",
    "original_subsystem",
    "optional_magic",
    "repair_needed",
    "is_dotnet",
    "is_packed",
    "packer_reason",
    "text_entropy",
    "num_sections",
    "num_imports",
    "size",
    "quality_flags",
    "is_clean",
]

BUCKET_ORDER = ["keylogger", "injection", "antidebug", "unknown"]


@dataclass
class QualityConfig:
    exclude_dotnet: bool = True
    exclude_packed: bool = True
    exclude_non_bodmas: bool = True
    high_entropy_threshold: float = 7.5
    packed_entropy_threshold: float | None = None
    packed_max_imports: int = 20
    entropy_sample_bytes: int = 2_000_000
    packer_strings: tuple[str, ...] = (
        "UPX!",
        "MPRESS",
        "Themida",
        "VMProtect",
        "ASPack",
        "PECompact",
        "Armadillo",
        "Enigma",
        "Obsidium",
    )


@dataclass
class SplitConfig:
    seed: int = 42
    train: float = 0.70
    val: float = 0.15
    test: float = 0.15
    lofo_families: dict[str, str] | None = None

    @property
    def ratios(self) -> dict[str, float]:
        return {"train": self.train, "val": self.val, "test": self.test}


def _resolve(path: str | Path, base: Path = ROOT) -> Path:
    path = Path(path).expanduser()
    return path if path.is_absolute() else base / path


def load_config(path: Path) -> dict[str, Any]:
    with path.open("rb") as fh:
        return tomllib.load(fh)


def _bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def load_bodmas_ids(bodmas_dir: Path) -> dict[str, set[str]]:
    ids: dict[str, set[str]] = {}
    for bucket in ("keylogger", "injection", "antidebug"):
        path = bodmas_dir / f"{bucket}_paths.txt"
        values: set[str] = set()
        if path.exists():
            with path.open() as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        values.add(Path(line).stem)
        ids[bucket] = values
    return ids


def load_families(bodmas_dir: Path) -> dict[str, str]:
    path = bodmas_dir / "bodmas_metadata.csv"
    families: dict[str, str] = {}
    if not path.exists():
        return families
    with path.open(newline="") as fh:
        for row in csv.DictReader(fh):
            sha = (row.get("sha") or "").strip()
            if sha:
                families[sha] = (row.get("family") or "").strip()
    return families


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs = counts[counts > 0].astype(np.float64) / len(data)
    return float(-(probs * np.log2(probs)).sum())


def _section_name(section: Any) -> str:
    return section.Name.rstrip(b"\0").decode("latin1", errors="replace")


def analyze_file(
    path: Path,
    raw_root: Path,
    bodmas_ids: dict[str, set[str]],
    families: dict[str, str],
    quality: QualityConfig,
) -> dict[str, Any]:
    raw = path.read_bytes()
    sample_id = path.stem
    rel = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
    raw_rel = path.relative_to(raw_root) if path.is_relative_to(raw_root) else path
    bucket = raw_rel.parts[0] if len(raw_rel.parts) > 1 else "unknown"

    row: dict[str, Any] = {
        "sample_id": sample_id,
        "filepath": str(rel),
        "source_bucket": bucket,
        "family": families.get(sample_id, ""),
        "in_bodmas": int(sample_id in bodmas_ids.get(bucket, set())),
        "content_sha256": hashlib.sha256(raw).hexdigest(),
        "imphash": "",
        "cluster_key": "",
        "arch": "unknown",
        "original_machine": 0,
        "original_subsystem": 0,
        "optional_magic": 0,
        "repair_needed": 0,
        "is_dotnet": 0,
        "is_packed": 0,
        "packer_reason": "",
        "text_entropy": 0.0,
        "num_sections": 0,
        "num_imports": 0,
        "size": len(raw),
        "quality_flags": "",
        "is_clean": 0,
    }

    flags: list[str] = []
    packer_reasons: list[str] = []

    try:
        header = parse_header(raw)
    except PEError:
        flags.append("no_pe")
        row["quality_flags"] = ";".join(flags)
        row["cluster_key"] = f"sha:{row['content_sha256']}"
        return row

    arch = header.arch
    row.update(
        {
            "arch": arch,
            "original_machine": header.machine,
            "original_subsystem": header.subsystem,
            "optional_magic": header.optional_magic,
            "repair_needed": int(header.needs_repair),
        }
    )
    if arch == "unknown":
        flags.append("unknown_arch")

    try:
        pe = pefile.PE(data=raw, fast_load=True)
        try:
            pe.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"],
                ]
            )
        except Exception:
            # Import/COM parsing is best-effort; header and sections remain usable.
            pass

        sections = list(pe.sections)
        row["num_sections"] = len(sections)
        names = [_section_name(s) for s in sections]
        upx_names = [n for n in names if n.upper().startswith("UPX")]
        if upx_names:
            packer_reasons.append("upx_section:" + ",".join(upx_names))

        imports = getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
        num_imports = sum(len(entry.imports) for entry in imports)
        dlls = [entry.dll.decode(errors="replace").lower() for entry in imports]
        row["num_imports"] = num_imports
        if num_imports == 0:
            flags.append("no_imports")

        com_dir = None
        try:
            directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
            if len(directories) > 14:
                com_dir = directories[14]
        except Exception:
            pass
        is_dotnet = bool(
            (com_dir is not None and (com_dir.VirtualAddress or com_dir.Size))
            or any("mscoree" in dll or "mscorlib" in dll for dll in dlls)
        )
        row["is_dotnet"] = int(is_dotnet)
        if is_dotnet:
            flags.append("dotnet")

        imphash = pe.get_imphash() if num_imports else ""
        row["imphash"] = imphash or ""

        text = next((s for s in sections if _section_name(s) == ".text"), None)
        if text is None and sections:
            text = max(sections, key=lambda s: s.SizeOfRawData)
        if text is not None:
            section_data = text.get_data()
            if len(section_data) > quality.entropy_sample_bytes:
                section_data = section_data[: quality.entropy_sample_bytes]
            row["text_entropy"] = round(shannon_entropy(section_data), 4)

        hits = [p for p in quality.packer_strings if p.encode() in raw]
        if hits:
            packer_reasons.append("string:" + ",".join(hits))

        high_entropy_no_imports = (
            num_imports == 0
            and row["text_entropy"] >= quality.high_entropy_threshold
        )
        if high_entropy_no_imports:
            packer_reasons.append("high_entropy_no_imports")

        high_entropy_low_imports = (
            quality.packed_entropy_threshold is not None
            and num_imports <= quality.packed_max_imports
            and row["text_entropy"] >= quality.packed_entropy_threshold
        )
        if high_entropy_low_imports:
            packer_reasons.append("high_entropy_low_imports")

        is_packed = bool(
            upx_names or hits or high_entropy_no_imports or high_entropy_low_imports
        )
        row["is_packed"] = int(is_packed)
        if is_packed:
            flags.append("packed")

        pe.close()
    except Exception:
        flags.append("parse_error")

    if not row["in_bodmas"]:
        flags.append("non_bodmas")

    row["packer_reason"] = ";".join(packer_reasons)
    row["cluster_key"] = (
        f"imphash:{row['imphash']}"
        if row["imphash"]
        else f"sha:{row['content_sha256']}"
    )

    # Exclusion flags are only applied when the matching config switch is on.
    excluded: set[str] = {"no_pe", "parse_error", "unknown_arch"}
    if quality.exclude_dotnet:
        excluded.add("dotnet")
    if quality.exclude_packed:
        excluded.add("packed")
    if quality.exclude_non_bodmas:
        excluded.add("non_bodmas")

    row["quality_flags"] = ";".join(dict.fromkeys(flags))
    row["is_clean"] = int(not (set(flags) & excluded))
    return row


def write_manifest(rows: list[dict[str, Any]], path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=MANIFEST_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in MANIFEST_FIELDS})
    os.replace(tmp, path)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _cluster_rows(rows: Iterable[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    clusters: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        clusters[row["cluster_key"]].append(row)
    return dict(clusters)


def _assign_bucket_clusters(
    rows: list[dict[str, Any]],
    bucket: str,
    ratios: dict[str, float],
    assignments: dict[str, str],
) -> None:
    """Assign one bucket's clusters, keeping the bucket's own target ratios.

    Clusters already assigned (e.g. a cross-bucket cluster) are counted as fixed
    and are not reassigned.  The largest remaining cluster always goes to train.
    """

    members = [row for row in rows if row["source_bucket"] == bucket]
    pending = [
        row for row in members if row["sample_id"] not in assignments
    ]
    if not pending:
        return

    total = len(members)
    current = {
        split: sum(
            1
            for row in members
            if assignments.get(row["sample_id"]) == split
        )
        for split in ratios
    }
    clusters = _cluster_rows(pending)
    ordered = sorted(clusters.items(), key=lambda kv: (-len(kv[1]), kv[0]))

    for index, (_, cluster) in enumerate(ordered):
        if index == 0:
            split = "train"
        else:
            split = max(
                ratios, key=lambda name: ratios[name] * total - current[name]
            )
        for row in cluster:
            assignments[row["sample_id"]] = split
        current[split] += len(cluster)


def assign_main(
    rows: list[dict[str, Any]],
    ratios: dict[str, float],
    seed: int,
) -> dict[str, str]:
    """Per-bucket greedy cluster assignment.

    A handful of imphash clusters span two buckets; those are assigned as a unit
    (to train) so they can never leak across splits.  Everything else is
    balanced within its source bucket, which prevents a large bucket from
    starving keylogger of training samples.
    """

    del seed  # deterministic; kept in the signature for API stability
    assignments: dict[str, str] = {}
    clusters = _cluster_rows(rows)

    for _, cluster in sorted(clusters.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        buckets = {row["source_bucket"] for row in cluster}
        if len(buckets) > 1:
            for row in cluster:
                assignments[row["sample_id"]] = "train"

    for bucket in sorted({row["source_bucket"] for row in rows}):
        _assign_bucket_clusters(rows, bucket, ratios, assignments)

    # Never return an empty split; move the smallest cluster if necessary.
    names = list(ratios)
    for empty in [name for name in names if not any(
        split == name for split in assignments.values()
    )]:
        donor = max(names, key=lambda name: sum(
            1 for split in assignments.values() if split == name
        ))
        candidates = sorted(
            (
                (key, cluster)
                for key, cluster in clusters.items()
                if assignments[cluster[0]["sample_id"]] == donor
            ),
            key=lambda kv: (len(kv[1]), kv[0]),
        )
        if not candidates:
            break
        _, cluster = candidates[0]
        for row in cluster:
            assignments[row["sample_id"]] = empty

    return assignments


def _choose_lofo_families(
    rows: list[dict[str, Any]],
    requested: dict[str, str],
    min_count: int = 5,
) -> dict[str, str]:
    by_bucket_family: dict[str, Counter[str]] = defaultdict(Counter)
    bucket_totals: Counter[str] = Counter()
    for row in rows:
        bucket = row["source_bucket"]
        family = row["family"] or "unknown"
        by_bucket_family[bucket][family] += 1
        bucket_totals[bucket] += 1

    selected: dict[str, str] = {}
    for bucket in ("keylogger", "injection", "antidebug"):
        counts = by_bucket_family.get(bucket, Counter())
        if not counts:
            continue
        wanted = requested.get(bucket, "")
        if wanted and counts.get(wanted, 0) >= min_count:
            selected[bucket] = wanted
            continue

        target = max(min_count, int(0.10 * bucket_totals[bucket]))
        candidates = [
            (abs(count - target), -count, family)
            for family, count in counts.items()
            if family != "unknown" and count >= min_count
        ]
        if candidates:
            selected[bucket] = min(candidates)[2]
        else:
            selected[bucket] = max(counts.items(), key=lambda kv: kv[1])[0]
    return selected


def assign_lofo(
    rows: list[dict[str, Any]],
    held_out: dict[str, str],
    val_ratio: float,
    seed: int,
) -> dict[str, str]:
    """Hold out one family per bucket and split the rest by bucket.

    The held-out family (and any cluster it touches) goes to test.  Remaining
    clusters are divided train/val independently per bucket, so a large bucket
    cannot consume the keylogger validation budget.
    """

    del seed  # deterministic; kept in the signature for API stability
    held = set(held_out.values())
    assignments: dict[str, str] = {}
    clusters = _cluster_rows(rows)

    # Clusters containing a held-out family stay together in test.
    for _, cluster in sorted(clusters.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        if any((row["family"] or "unknown") in held for row in cluster):
            for row in cluster:
                assignments[row["sample_id"]] = "test"
        elif len({row["source_bucket"] for row in cluster}) > 1:
            # Cross-bucket clusters are tiny; keep them in train as a unit.
            for row in cluster:
                assignments[row["sample_id"]] = "train"

    ratios = {"train": 1.0 - val_ratio, "val": val_ratio}
    for bucket in sorted({row["source_bucket"] for row in rows}):
        members = [row for row in rows if row["source_bucket"] == bucket]
        pending = [
            row for row in members if row["sample_id"] not in assignments
        ]
        if not pending:
            continue
        total = len(pending)
        current = {"train": 0, "val": 0}
        pending_clusters = _cluster_rows(pending)
        ordered = sorted(
            pending_clusters.items(), key=lambda kv: (-len(kv[1]), kv[0])
        )
        for index, (_, cluster) in enumerate(ordered):
            if index == 0:
                split = "train"
            else:
                split = max(
                    ratios, key=lambda name: ratios[name] * total - current[name]
                )
            for row in cluster:
                assignments[row["sample_id"]] = split
            current[split] += len(cluster)

        if current["val"] == 0 and current["train"] > 1 and len(ordered) > 1:
            _, cluster = sorted(ordered, key=lambda kv: (len(kv[1]), kv[0]))[0]
            for row in cluster:
                assignments[row["sample_id"]] = "val"

    return assignments


def check_integrity(
    rows: list[dict[str, Any]],
    assignments: dict[str, str],
    held_out_families: set[str] | None = None,
) -> None:
    ids = {row["sample_id"] for row in rows}
    if set(assignments) != ids:
        missing = ids - set(assignments)
        extra = set(assignments) - ids
        raise ValueError(
            f"assignment mismatch: missing={len(missing)} extra={len(extra)}"
        )

    by_cluster: dict[str, set[str]] = defaultdict(set)
    by_sample = {row["sample_id"]: row for row in rows}
    for sample_id, split in assignments.items():
        by_cluster[by_sample[sample_id]["cluster_key"]].add(split)
    leaking = {key: splits for key, splits in by_cluster.items() if len(splits) > 1}
    if leaking:
        raise ValueError(
            f"{len(leaking)} clusters cross splits, e.g. {next(iter(leaking.items()))}"
        )

    if held_out_families:
        for sample_id, split in assignments.items():
            family = by_sample[sample_id]["family"] or "unknown"
            if family in held_out_families and split != "test":
                raise ValueError(
                    f"held-out family sample {sample_id} assigned to {split}"
                )


def split_summary(
    rows: list[dict[str, Any]], assignments: dict[str, str]
) -> dict[str, Any]:
    by_sample = {row["sample_id"]: row for row in rows}
    counts = Counter(assignments.values())
    clusters: dict[str, set[str]] = defaultdict(set)
    bucket_counts: dict[str, Counter[str]] = defaultdict(Counter)
    family_counts: dict[str, Counter[str]] = defaultdict(Counter)
    for sample_id, split in assignments.items():
        row = by_sample[sample_id]
        clusters[split].add(row["cluster_key"])
        bucket_counts[row["source_bucket"]][split] += 1
        family_counts[row["family"] or "unknown"][split] += 1
    return {
        "counts": dict(sorted(counts.items())),
        "cluster_counts": {split: len(values) for split, values in sorted(clusters.items())},
        "bucket_counts": {
            bucket: dict(sorted(counter.items()))
            for bucket, counter in sorted(bucket_counts.items())
        },
        "family_counts": {
            family: dict(sorted(counter.items()))
            for family, counter in sorted(family_counts.items())
        },
    }


def write_splits(
    rows: list[dict[str, Any]],
    manifest_sha256: str,
    splits_dir: Path,
    split_config: SplitConfig,
) -> dict[str, Any]:
    splits_dir.mkdir(parents=True, exist_ok=True)
    created = datetime.now(timezone.utc).isoformat(timespec="seconds")

    main_assignments = assign_main(rows, split_config.ratios, split_config.seed)
    check_integrity(rows, main_assignments)
    main = {
        "protocol": "main",
        "version": 1,
        "created_utc": created,
        "manifest_sha256": manifest_sha256,
        "seed": split_config.seed,
        "ratios": split_config.ratios,
        **split_summary(rows, main_assignments),
        "assignments": dict(sorted(main_assignments.items())),
    }

    held_out = _choose_lofo_families(rows, split_config.lofo_families or {})
    lofo_assignments = assign_lofo(
        rows, held_out, split_config.val, split_config.seed
    )
    check_integrity(rows, lofo_assignments, set(held_out.values()))
    lofo = {
        "protocol": "lofo",
        "version": 1,
        "created_utc": created,
        "manifest_sha256": manifest_sha256,
        "seed": split_config.seed,
        "val_ratio": split_config.val,
        "held_out_families": held_out,
        **split_summary(rows, lofo_assignments),
        "assignments": dict(sorted(lofo_assignments.items())),
    }

    for name, payload in (("main", main), ("lofo", lofo)):
        path = splits_dir / f"{name}.json"
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n")
        os.replace(tmp, path)

    return {"main": main, "lofo": lofo}


def build_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    clean = [row for row in rows if row["is_clean"]]
    flag_counts: Counter[str] = Counter()
    for row in rows:
        for flag in str(row["quality_flags"]).split(";"):
            if flag:
                flag_counts[flag] += 1

    buckets: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "clean": 0})
    families: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "clean": 0})
    for row in rows:
        bucket = row["source_bucket"]
        family = row["family"] or "unknown"
        buckets[bucket]["total"] += 1
        families[family]["total"] += 1
        if row["is_clean"]:
            buckets[bucket]["clean"] += 1
            families[family]["clean"] += 1

    clean_clusters = Counter(row["cluster_key"] for row in clean)
    top_clusters = clean_clusters.most_common(10)

    return {
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total_files": len(rows),
        "clean_files": len(clean),
        "excluded_files": len(rows) - len(clean),
        "arch": dict(Counter(row["arch"] for row in rows)),
        "clean_arch": dict(Counter(row["arch"] for row in clean)),
        "repair_needed": sum(int(row["repair_needed"]) for row in rows),
        "flags": dict(flag_counts.most_common()),
        "buckets": dict(sorted(buckets.items())),
        "families": dict(sorted(families.items(), key=lambda kv: (-kv[1]["clean"], kv[0]))),
        "clean_clusters": len(clean_clusters),
        "clean_singleton_clusters": sum(1 for count in clean_clusters.values() if count == 1),
        "largest_clean_clusters": top_clusters,
        "content_sha_duplicates": sum(
            count - 1 for count in Counter(row["content_sha256"] for row in rows).values() if count > 1
        ),
        "text_entropy_median": round(
            statistics.median(row["text_entropy"] for row in rows), 4
        )
        if rows
        else 0.0,
    }


def write_report(
    summary: dict[str, Any],
    splits: dict[str, Any] | None,
    path: Path,
) -> None:
    validation: dict[str, Any] | None = None
    validation_path = path.parent / "phase0_validation_summary.json"
    if validation_path.exists():
        try:
            validation = json.loads(validation_path.read_text())
        except json.JSONDecodeError:
            validation = None

    lines: list[str] = []
    lines.append("# Phase 0 report\n")
    lines.append(f"Generated: `{summary['generated_utc']}`\n")
    lines.append("## Corpus\n")
    lines.append(f"- Files discovered: **{summary['total_files']}**")
    lines.append(f"- Clean files: **{summary['clean_files']}**")
    lines.append(f"- Excluded: **{summary['excluded_files']}**")
    lines.append(f"- Header repair needed: **{summary['repair_needed']}**")
    lines.append(f"- Architecture (all / clean): `{summary['arch']}` / `{summary['clean_arch']}`")
    lines.append(f"- Median `.text` entropy (sampled): `{summary['text_entropy_median']}`")
    lines.append(f"- Duplicate content hashes: **{summary['content_sha_duplicates']}**\n")

    lines.append("## Quality flags\n")
    lines.append("| Flag | Files |")
    lines.append("|---|---:|")
    for flag, count in summary["flags"].items():
        lines.append(f"| `{flag}` | {count} |")

    lines.append("\n## Buckets\n")
    lines.append("| Bucket | Total | Clean |")
    lines.append("|---|---:|---:|")
    for bucket, counts in summary["buckets"].items():
        lines.append(f"| `{bucket}` | {counts['total']} | {counts['clean']} |")

    lines.append("\n## Families\n")
    lines.append("| Family | Total | Clean |")
    lines.append("|---|---:|---:|")
    for family, counts in summary["families"].items():
        lines.append(f"| `{family}` | {counts['total']} | {counts['clean']} |")

    lines.append("\n## Clusters\n")
    lines.append(f"- Clean imphash/sha clusters: **{summary['clean_clusters']}**")
    lines.append(f"- Singleton clusters: **{summary['clean_singleton_clusters']}**")
    lines.append("- Largest clusters:")
    lines.append("")
    lines.append("| Cluster | Files |")
    lines.append("|---|---:|")
    for key, count in summary["largest_clean_clusters"]:
        lines.append(f"| `{key}` | {count} |")

    if splits:
        for protocol in ("main", "lofo"):
            payload = splits[protocol]
            lines.append(f"\n## Split: `{protocol}`\n")
            lines.append(f"- Seed: `{payload['seed']}`")
            lines.append(f"- Manifest SHA-256: `{payload['manifest_sha256']}`")
            if protocol == "lofo":
                lines.append(f"- Held-out families: `{payload['held_out_families']}`")
            lines.append(f"- Counts: `{payload['counts']}`")
            lines.append(f"- Clusters per split: `{payload['cluster_counts']}`")
            lines.append("\n| Bucket | Train | Val | Test |")
            lines.append("|---|---:|---:|---:|")
            for bucket, counts in payload["bucket_counts"].items():
                lines.append(
                    f"| `{bucket}` | {counts.get('train', 0)} | "
                    f"{counts.get('val', 0)} | {counts.get('test', 0)} |"
                )

    lines.append("\n## Validation\n")
    angr_ok = False
    capa_ok = False
    if validation:
        angr = validation.get("angr", {})
        if angr:
            angr_ok = angr.get("failed", 1) == 0 and angr.get("total", 0) > 0
            lines.append(
                f"- angr load: **{angr.get('ok', 0)}/{angr.get('total', 0)}** ok, "
                f"**{angr.get('failed', 0)}** failed"
            )
        capa = validation.get("capa", {})
        if capa and capa.get("ran", 0) > 0:
            capa_ok = capa.get("ok", 0) == capa.get("ran", 0)
            lines.append(
                f"- CAPA smoke: **{capa.get('ok', 0)}/{capa.get('ran', 0)}** exit 0"
            )
    if not validation:
        lines.append("- Not run yet.")

    lines.append("\n## Gate status\n")
    lines.append("- [x] Manifest generated")
    lines.append("- [x] Quality filters applied; no compute caps")
    lines.append("- [x] Splits frozen and cluster-integrity checked")
    lines.append(
        f"- [{'x' if angr_ok else ' '}] angr load validation "
        f"(see `results/phase0_validation.csv`)"
    )
    lines.append(
        f"- [{'x' if capa_ok else ' '}] CAPA smoke test "
        f"(see `results/phase0_capa_smoke.csv`)"
    )
    lines.append(
        "- [ ] Full-set CAPA exit-code pass (belongs to Phase 1, not Phase 0)\n"
    )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the Phase 0 manifest and splits.")
    parser.add_argument("--config", type=Path, default=ROOT / "configs/phase0.toml")
    parser.add_argument("--raw", type=Path, help="override raw data root")
    parser.add_argument("--bodmas", type=Path, help="override BODMAS metadata root")
    parser.add_argument("--manifest", type=Path, help="override manifest output path")
    parser.add_argument("--splits", type=Path, help="override splits output directory")
    parser.add_argument("--results", type=Path, help="override results directory")
    parser.add_argument("--skip-splits", action="store_true")
    parser.add_argument(
        "--min-clean",
        type=int,
        default=100,
        help="refuse to freeze splits below this clean count (smoke tests: 1)",
    )
    args = parser.parse_args(argv)

    config = load_config(args.config)
    paths = config.get("paths", {})
    raw_root = _resolve(args.raw or paths.get("raw", "data/raw"))
    bodmas_dir = _resolve(args.bodmas or paths.get("bodmas", "data/bodmas"))
    manifest_path = _resolve(args.manifest or paths.get("manifest", "data/manifest.csv"))
    splits_dir = _resolve(args.splits or paths.get("splits", "data/splits"))
    results_dir = _resolve(args.results or paths.get("results", "results"))

    quality_cfg = config.get("quality", {})
    quality = QualityConfig(
        exclude_dotnet=_bool(quality_cfg.get("exclude_dotnet"), True),
        exclude_packed=_bool(quality_cfg.get("exclude_packed"), True),
        exclude_non_bodmas=_bool(quality_cfg.get("exclude_non_bodmas"), True),
        high_entropy_threshold=float(quality_cfg.get("high_entropy_threshold", 7.5)),
        packed_entropy_threshold=(
            float(quality_cfg["packed_entropy_threshold"])
            if quality_cfg.get("packed_entropy_threshold") is not None
            else None
        ),
        packed_max_imports=int(quality_cfg.get("packed_max_imports", 20)),
        entropy_sample_bytes=int(quality_cfg.get("entropy_sample_bytes", 2_000_000)),
        packer_strings=tuple(quality_cfg.get("packer_strings", QualityConfig.packer_strings)),
    )
    split_cfg_raw = config.get("splits", {})
    split_config = SplitConfig(
        seed=int(split_cfg_raw.get("seed", 42)),
        train=float(split_cfg_raw.get("train", 0.70)),
        val=float(split_cfg_raw.get("val", 0.15)),
        test=float(split_cfg_raw.get("test", 0.15)),
        lofo_families=dict(split_cfg_raw.get("lofo_families", {})),
    )
    if abs(sum(split_config.ratios.values()) - 1.0) > 1e-6:
        raise SystemExit("split ratios must sum to 1.0")

    bodmas_ids = load_bodmas_ids(bodmas_dir)
    families = load_families(bodmas_dir)

    files = sorted(path for path in raw_root.rglob("*.exe") if path.is_file())
    if not files:
        raise SystemExit(f"no .exe files under {raw_root}")

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    duplicates: list[str] = []
    for path in tqdm(files, desc="manifest", unit="file"):
        row = analyze_file(path, raw_root, bodmas_ids, families, quality)
        if row["sample_id"] in seen:
            duplicates.append(row["sample_id"])
        seen.add(row["sample_id"])
        rows.append(row)

    if duplicates:
        raise SystemExit(
            f"duplicate sample_id values ({len(duplicates)}): {duplicates[:10]}"
        )

    rows.sort(key=lambda row: (BUCKET_ORDER.index(row["source_bucket"])
                               if row["source_bucket"] in BUCKET_ORDER else len(BUCKET_ORDER),
                               row["sample_id"]))
    manifest_sha256 = write_manifest(rows, manifest_path)
    summary = build_summary(rows)
    summary["manifest_sha256"] = manifest_sha256
    summary["manifest_path"] = str(manifest_path.relative_to(ROOT))

    clean_rows = [row for row in rows if row["is_clean"]]
    if len(clean_rows) < args.min_clean:
        raise SystemExit(
            f"only {len(clean_rows)} clean samples; refusing to freeze splits "
            f"(min-clean={args.min_clean})"
        )

    splits = None
    if not args.skip_splits:
        splits = write_splits(clean_rows, manifest_sha256, splits_dir, split_config)

    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "phase0_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n"
    )
    write_report(summary, splits, results_dir / "phase0_report.md")

    print(json.dumps(
        {
            "total_files": summary["total_files"],
            "clean_files": summary["clean_files"],
            "excluded_files": summary["excluded_files"],
            "clusters": summary["clean_clusters"],
            "manifest": str(manifest_path),
            "manifest_sha256": manifest_sha256,
            "splits": {
                protocol: {
                    "counts": payload["counts"],
                    "cluster_counts": payload["cluster_counts"],
                    "held_out_families": payload.get("held_out_families"),
                }
                for protocol, payload in (splits or {}).items()
            },
        },
        indent=2,
    ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
