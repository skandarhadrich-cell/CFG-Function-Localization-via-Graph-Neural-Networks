"""Validate the Phase 0 manifest: angr loads and a small CAPA smoke test.

This is the Phase 0 gate that does not require a full CFG or a full CAPA run.
It repairs each clean sample into a temporary file, loads it with angr, and
optionally runs CAPA on a small stratified sample.

Usage::

    python -m src.data.validate_manifest --limit 200
    python -m src.data.validate_manifest --workers 4
    python -m src.data.validate_manifest --capa-smoke 5
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.data.repair_pe import PEError, repair_file

ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Sample:
    sample_id: str
    filepath: str
    source_bucket: str


def _resolve(path: str | Path) -> Path:
    path = Path(path).expanduser()
    return path if path.is_absolute() else ROOT / path


def load_config(path: Path) -> dict[str, Any]:
    with path.open("rb") as fh:
        return tomllib.load(fh)


def read_samples(manifest: Path) -> list[Sample]:
    samples: list[Sample] = []
    with manifest.open(newline="") as fh:
        for row in csv.DictReader(fh):
            if str(row.get("is_clean", "0")) != "1":
                continue
            samples.append(
                Sample(
                    sample_id=row["sample_id"],
                    filepath=row["filepath"],
                    source_bucket=row["source_bucket"],
                )
            )
    return samples


def _angr_load(sample: Sample, scratch: Path) -> dict[str, Any]:
    # Import inside the worker so the parent process stays light.
    import angr  # type: ignore

    logging.getLogger("angr").setLevel(logging.CRITICAL)
    logging.getLogger("cle").setLevel(logging.CRITICAL)
    logging.getLogger("pyvex").setLevel(logging.CRITICAL)

    src = ROOT / sample.filepath
    dst = scratch / f"{sample.sample_id}.exe"
    started = time.time()
    try:
        repair_file(src, dst)
        project = angr.Project(str(dst), auto_load_libs=False)
        elapsed = time.time() - started
        return {
            "sample_id": sample.sample_id,
            "source_bucket": sample.source_bucket,
            "ok": 1,
            "arch": project.arch.name,
            "entry": hex(project.loader.main_object.entry),
            "seconds": round(elapsed, 3),
            "error": "",
        }
    except Exception as exc:  # noqa: BLE001 - report the failure, don't crash the pool
        return {
            "sample_id": sample.sample_id,
            "source_bucket": sample.source_bucket,
            "ok": 0,
            "arch": "",
            "entry": "",
            "seconds": round(time.time() - started, 3),
            "error": f"{type(exc).__name__}: {exc}",
        }
    finally:
        try:
            dst.unlink()
        except OSError:
            pass


def _sample_stratified(samples: list[Sample], limit: int, seed: int) -> list[Sample]:
    """Proportional sample, with at least one sample per non-empty bucket.

    The keylogger bucket is only ~1% of the clean corpus, so a naive
    proportional draw of 10-20 samples would never exercise it.
    """

    if limit <= 0 or limit >= len(samples):
        return list(samples)
    rng = random.Random(seed)
    by_bucket: dict[str, list[Sample]] = {}
    for sample in samples:
        by_bucket.setdefault(sample.source_bucket, []).append(sample)
    buckets = sorted(by_bucket)
    min_take = 1 if limit >= len(buckets) else 0
    selected: list[Sample] = []
    remaining = limit

    for index, bucket in enumerate(buckets):
        values = by_bucket[bucket]
        if index == len(buckets) - 1:
            take = remaining
        else:
            reserve = (len(buckets) - index - 1) * min_take
            proportional = round(limit * len(values) / len(samples))
            take = max(min_take, proportional)
            take = min(take, len(values), max(0, remaining - reserve))
        selected.extend(rng.sample(values, take))
        remaining -= take
    return selected


def validate_angr(
    samples: list[Sample], workers: int, output: Path
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    scratch = Path(tempfile.mkdtemp(prefix="cfg-gnn-phase0-"))
    try:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_angr_load, sample, scratch): sample for sample in samples}
            for future in as_completed(futures):
                sample = futures[future]
                try:
                    rows.append(future.result())
                except Exception as exc:  # noqa: BLE001
                    rows.append(
                        {
                            "sample_id": sample.sample_id,
                            "source_bucket": sample.source_bucket,
                            "ok": 0,
                            "arch": "",
                            "entry": "",
                            "seconds": 0.0,
                            "error": f"{type(exc).__name__}: {exc}",
                        }
                    )
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    rows.sort(key=lambda row: row["sample_id"])
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "sample_id",
                "source_bucket",
                "ok",
                "arch",
                "entry",
                "seconds",
                "error",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    ok = sum(int(row["ok"]) for row in rows)
    return {
        "total": len(rows),
        "ok": ok,
        "failed": len(rows) - ok,
        "per_bucket": dict(Counter(row["source_bucket"] for row in rows)),
        "failures": [row for row in rows if not int(row["ok"])][:20],
        "output": str(output.relative_to(ROOT)),
    }


def capa_smoke(
    samples: list[Sample],
    capa: Path,
    rules: Path,
    limit: int,
    seed: int,
    output: Path,
) -> dict[str, Any]:
    if limit <= 0:
        return {"ran": 0}
    if not capa.exists():
        return {"ran": 0, "error": f"capa not found: {capa}"}
    if not rules.exists():
        return {"ran": 0, "error": f"capa rules not found: {rules}"}

    rng = random.Random(seed)
    chosen = _sample_stratified(samples, min(limit, len(samples)), seed)
    rows: list[dict[str, Any]] = []
    scratch = Path(tempfile.mkdtemp(prefix="cfg-gnn-capa-"))
    try:
        for sample in chosen:
            src = ROOT / sample.filepath
            dst = scratch / f"{sample.sample_id}.exe"
            started = time.time()
            try:
                repair_file(src, dst)
                proc = subprocess.run(
                    [str(capa), "--rules", str(rules), "-j", str(dst)],
                    capture_output=True,
                    timeout=240,
                )
                elapsed = time.time() - started
                rows.append(
                    {
                        "sample_id": sample.sample_id,
                        "source_bucket": sample.source_bucket,
                        "returncode": proc.returncode,
                        "json_bytes": len(proc.stdout),
                        "seconds": round(elapsed, 2),
                        "error": proc.stderr.decode(errors="replace")[-300:].replace("\n", " ")
                        if proc.returncode
                        else "",
                    }
                )
            except subprocess.TimeoutExpired:
                rows.append(
                    {
                        "sample_id": sample.sample_id,
                        "source_bucket": sample.source_bucket,
                        "returncode": "timeout",
                        "json_bytes": 0,
                        "seconds": 240.0,
                        "error": "timeout",
                    }
                )
            except Exception as exc:  # noqa: BLE001
                rows.append(
                    {
                        "sample_id": sample.sample_id,
                        "source_bucket": sample.source_bucket,
                        "returncode": "error",
                        "json_bytes": 0,
                        "seconds": round(time.time() - started, 2),
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
            finally:
                try:
                    dst.unlink()
                except OSError:
                    pass
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "sample_id",
                "source_bucket",
                "returncode",
                "json_bytes",
                "seconds",
                "error",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    return {
        "ran": len(rows),
        "ok": sum(1 for row in rows if row["returncode"] == 0),
        "failures": [row for row in rows if row["returncode"] != 0][:10],
        "output": str(output.relative_to(ROOT)),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate the Phase 0 manifest.")
    parser.add_argument("--config", type=Path, default=ROOT / "configs/phase0.toml")
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--results", type=Path)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--limit", type=int, default=0, help="0 = all clean samples")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--capa-smoke",
        type=int,
        default=0,
        help="run CAPA on N stratified clean samples (0 = skip)",
    )
    parser.add_argument("--skip-angr", action="store_true")
    args = parser.parse_args(argv)

    config = load_config(args.config)
    paths = config.get("paths", {})
    tools = config.get("tools", {})
    manifest = _resolve(args.manifest or paths.get("manifest", "data/manifest.csv"))
    results = _resolve(args.results or paths.get("results", "results"))
    capa = _resolve(tools.get("capa", "~/tools/capa/capa"))
    rules = _resolve(tools.get("capa_rules", "~/tools/capa-rules"))

    if not manifest.exists():
        raise SystemExit(f"manifest not found: {manifest}")

    samples = read_samples(manifest)
    chosen = _sample_stratified(samples, args.limit, args.seed)
    summary_path = results / "phase0_validation_summary.json"
    summary: dict[str, Any] = {}
    if args.skip_angr and summary_path.exists():
        try:
            summary = json.loads(summary_path.read_text())
        except json.JSONDecodeError:
            summary = {}
    summary.update({"clean_samples": len(samples), "selected": len(chosen)})

    if not args.skip_angr:
        summary["angr"] = validate_angr(
            chosen, args.workers, results / "phase0_validation.csv"
        )

    if args.capa_smoke:
        summary["capa"] = capa_smoke(
            samples,
            capa,
            rules,
            args.capa_smoke,
            args.seed,
            results / "phase0_capa_smoke.csv",
        )

    summary_path.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0 if not summary.get("angr", {}).get("failed") else 1


if __name__ == "__main__":
    sys.exit(main())
