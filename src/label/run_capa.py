"""Run CAPA over a pilot or full sample list, with repair and resume support.

The raw JSON is written to ``data/labels/capa_raw/`` (git-ignored).  A small
summary is written under ``results/pilot/`` for review.  CAPA is always run on
a repaired temporary copy; ``data/raw/`` is never modified.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
import time
import tomllib
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.data.repair_pe import repair_file

ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Sample:
    sample_id: str
    filepath: str
    source_bucket: str
    family: str


def _resolve(path: str | Path) -> Path:
    path = Path(path).expanduser()
    return path if path.is_absolute() else ROOT / path


def load_config(path: Path) -> dict[str, Any]:
    with path.open("rb") as fh:
        return tomllib.load(fh)


def read_manifest(manifest: Path) -> list[Sample]:
    rows: list[Sample] = []
    with manifest.open(newline="") as fh:
        for row in csv.DictReader(fh):
            rows.append(
                Sample(
                    sample_id=row["sample_id"],
                    filepath=row["filepath"],
                    source_bucket=row["source_bucket"],
                    family=row["family"] or "unknown",
                )
            )
    return rows


def select_pilot(
    rows: list[Sample],
    main_assignments: dict[str, str],
    target: int,
    seed: int,
) -> list[Sample]:
    clean = [row for row in rows if main_assignments.get(row.sample_id) in {"train", "val"}]
    if not clean:
        clean = list(rows)
    keyloggers = [row for row in clean if row.source_bucket == "keylogger"]
    rng = random.Random(seed)

    selected = list(keyloggers)
    remaining = max(0, target - len(selected))
    injection = sorted(
        (row for row in clean if row.source_bucket == "injection"),
        key=lambda row: row.sample_id,
    )
    antidebug = sorted(
        (row for row in clean if row.source_bucket == "antidebug"),
        key=lambda row: row.sample_id,
    )
    take_injection = min(len(injection), (remaining + 1) // 2)
    take_antidebug = min(len(antidebug), remaining - take_injection)
    selected.extend(rng.sample(injection, take_injection))
    selected.extend(rng.sample(antidebug, take_antidebug))

    used = {row.sample_id for row in selected}
    leftovers = [row for row in clean if row.sample_id not in used]
    fill = max(0, target - len(selected))
    if fill:
        selected.extend(rng.sample(leftovers, min(fill, len(leftovers))))

    return sorted(selected, key=lambda row: (row.source_bucket, row.sample_id))


def _tool_identity(capa: Path, rules: Path) -> dict[str, Any]:
    identity: dict[str, Any] = {
        "capa_path": str(capa),
        "rules_path": str(rules),
        "capa_version": None,
        "rules_commit": None,
        "rules_dirty": None,
    }
    try:
        identity["capa_version"] = subprocess.check_output(
            [str(capa), "--version"], text=True, stderr=subprocess.STDOUT
        ).strip()
    except Exception as exc:  # noqa: BLE001
        identity["capa_version_error"] = f"{type(exc).__name__}: {exc}"
    try:
        identity["rules_commit"] = subprocess.check_output(
            ["git", "-C", str(rules), "rev-parse", "HEAD"], text=True, stderr=subprocess.STDOUT
        ).strip()
        dirty = subprocess.check_output(
            ["git", "-C", str(rules), "status", "--porcelain"], text=True, stderr=subprocess.STDOUT
        )
        identity["rules_dirty"] = bool(dirty.strip())
    except Exception as exc:  # noqa: BLE001
        identity["rules_git_error"] = f"{type(exc).__name__}: {exc}"
    return identity


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_one(
    sample: Sample,
    out_dir: Path,
    scratch_dir: Path,
    capa: Path,
    rules: Path,
    timeout: int,
    force: bool,
) -> dict[str, Any]:
    """Run CAPA for one sample.  Top-level so ProcessPoolExecutor can pickle it."""

    out_path = out_dir / f"{sample.sample_id}.json"
    meta_path = out_dir / f"{sample.sample_id}.meta.json"
    sample_sha256 = _sha256_file(ROOT / sample.filepath)
    if out_path.exists() and not force:
        try:
            json.loads(out_path.read_text())
            return {
                "sample_id": sample.sample_id,
                "sample_sha256": sample_sha256,
                "source_bucket": sample.source_bucket,
                "family": sample.family,
                "status": "skipped",
                "returncode": 0,
                "seconds": 0.0,
                "json_bytes": out_path.stat().st_size,
                "error": "",
            }
        except (OSError, json.JSONDecodeError):
            pass

    out_dir.mkdir(parents=True, exist_ok=True)
    scratch_dir.mkdir(parents=True, exist_ok=True)
    started = time.time()
    tmp_out = out_dir / f".{sample.sample_id}.json.tmp"

    try:
        with tempfile.TemporaryDirectory(
            dir=scratch_dir, prefix=f"{sample.sample_id[:12]}-"
        ) as temp_dir:
            repaired = Path(temp_dir) / f"{sample.sample_id}.exe"
            repair_file(ROOT / sample.filepath, repaired)
            with tmp_out.open("wb") as stdout:
                proc = subprocess.run(
                    [str(capa), "--rules", str(rules), "-j", str(repaired)],
                    stdout=stdout,
                    stderr=subprocess.PIPE,
                    timeout=timeout,
                )
        if proc.returncode != 0:
            tmp_out.unlink(missing_ok=True)
            error = proc.stderr.decode(errors="replace")[-500:].replace("\n", " ")
            raise RuntimeError(f"CAPA exit {proc.returncode}: {error}")

        json.loads(tmp_out.read_text())
        os.replace(tmp_out, out_path)
        elapsed = time.time() - started
        result = {
            "sample_id": sample.sample_id,
            "sample_sha256": sample_sha256,
            "source_bucket": sample.source_bucket,
            "family": sample.family,
            "status": "ok",
            "returncode": 0,
            "seconds": round(elapsed, 3),
            "json_bytes": out_path.stat().st_size,
            "error": "",
        }
    except subprocess.TimeoutExpired:
        tmp_out.unlink(missing_ok=True)
        result = {
            "sample_id": sample.sample_id,
            "sample_sha256": sample_sha256,
            "source_bucket": sample.source_bucket,
            "family": sample.family,
            "status": "timeout",
            "returncode": "timeout",
            "seconds": round(time.time() - started, 3),
            "json_bytes": 0,
            "error": f"timeout after {timeout}s",
        }
    except Exception as exc:  # noqa: BLE001
        tmp_out.unlink(missing_ok=True)
        result = {
            "sample_id": sample.sample_id,
            "sample_sha256": sample_sha256,
            "source_bucket": sample.source_bucket,
            "family": sample.family,
            "status": "failed",
            "returncode": "error",
            "seconds": round(time.time() - started, 3),
            "json_bytes": 0,
            "error": f"{type(exc).__name__}: {exc}",
        }

    result["sample_sha256"] = sample_sha256
    meta_path.write_text(json.dumps(result, indent=2) + "\n")
    return result


def write_samples(path: Path, samples: list[Sample]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "count": len(samples),
        "by_bucket": dict(Counter(sample.source_bucket for sample in samples)),
        "samples": [
            {
                "sample_id": sample.sample_id,
                "source_bucket": sample.source_bucket,
                "family": sample.family,
            }
            for sample in samples
        ],
    }
    path.write_text(json.dumps(payload, indent=2) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run CAPA on pilot or selected samples.")
    parser.add_argument("--config", type=Path, default=ROOT / "configs/pilot.toml")
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--splits", type=Path)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--results", type=Path)
    parser.add_argument("--workers", type=int)
    parser.add_argument("--timeout", type=int)
    parser.add_argument("--target", type=int)
    parser.add_argument("--sample-id", action="append", default=[])
    parser.add_argument("--all-clean", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)

    config = load_config(args.config)
    paths = config.get("paths", {})
    tools = config.get("tools", {})
    sampling = config.get("pilot", {}).get("sampling", {})
    compute = config.get("pilot", {}).get("compute", {})

    manifest = _resolve(args.manifest or paths.get("manifest", "data/manifest.csv"))
    splits = _resolve(args.splits or paths.get("splits", "data/splits"))
    out_dir = _resolve(args.out_dir or paths.get("labels_raw", "data/labels/capa_raw"))
    results = _resolve(args.results or paths.get("results", "results"))
    capa = _resolve(tools.get("capa", "~/tools/capa/capa"))
    rules = _resolve(tools.get("capa_rules", "~/tools/capa_rules"))
    workers = args.workers or int(compute.get("workers", 4))
    timeout = args.timeout or int(compute.get("capa_timeout_seconds", 240))
    target = args.target or int(sampling.get("clean_target", 200))

    if not capa.exists():
        raise SystemExit(f"CAPA not found: {capa}")
    if not rules.exists():
        raise SystemExit(f"CAPA rules not found: {rules}")

    all_rows = read_manifest(manifest)
    manifest_clean = {row.sample_id for row in all_rows}
    if args.sample_id:
        wanted = set(args.sample_id)
        missing = wanted - manifest_clean
        if missing:
            raise SystemExit(f"sample IDs not in manifest: {sorted(missing)[:5]}")
        samples = [row for row in all_rows if row.sample_id in wanted]
    elif args.all_clean:
        samples = all_rows
    else:
        main_path = splits / "main.json"
        main_assignments = {}
        if main_path.exists():
            main_assignments = json.loads(main_path.read_text()).get("assignments", {})
        samples = select_pilot(all_rows, main_assignments, target, 42)

    if not samples:
        raise SystemExit("no samples selected")

    run_meta = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "manifest": str(manifest),
        "splits": str(splits),
        "out_dir": str(out_dir),
        "workers": workers,
        "timeout_seconds": timeout,
        "selected": len(samples),
        "by_bucket": dict(Counter(sample.source_bucket for sample in samples)),
        "argv": sys.argv,
        "capa_argv_template": [
            str(capa),
            "--rules",
            str(rules),
            "-j",
            "<repaired-temporary-copy>",
        ],
        **_tool_identity(capa, rules),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    results.mkdir(parents=True, exist_ok=True)
    if not args.sample_id and not args.all_clean:
        write_samples(results / "pilot" / "samples.json", samples)
    (out_dir / "_run_metadata.json").write_text(json.dumps(run_meta, indent=2) + "\n")

    print(json.dumps(run_meta, indent=2))
    started = time.time()
    results_rows: list[dict[str, Any]] = []
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(
                run_one,
                sample,
                out_dir,
                out_dir / "_scratch",
                capa,
                rules,
                timeout,
                args.force,
            ): sample
            for sample in samples
        }
        for index, future in enumerate(as_completed(futures), start=1):
            sample = futures[future]
            try:
                rows = future.result()
            except Exception as exc:  # noqa: BLE001
                rows = {
                    "sample_id": sample.sample_id,
                    "sample_sha256": _sha256_file(ROOT / sample.filepath),
                    "source_bucket": sample.source_bucket,
                    "family": sample.family,
                    "status": "failed",
                    "returncode": "error",
                    "seconds": 0.0,
                    "json_bytes": 0,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            results_rows.append(rows)
            if index % 10 == 0 or index == len(futures):
                print(f"capa {index}/{len(futures)}", flush=True)

    results_rows.sort(key=lambda row: row["sample_id"])
    counts = Counter(row["status"] for row in results_rows)
    summary = {
        **run_meta,
        "elapsed_seconds": round(time.time() - started, 2),
        "status_counts": dict(counts),
        "ok": counts.get("ok", 0),
        "skipped": counts.get("skipped", 0),
        "failed": counts.get("failed", 0),
        "timeouts": counts.get("timeout", 0),
        "failures": [row for row in results_rows if row["status"] not in {"ok", "skipped"}][:20],
        "runs": results_rows,
    }
    (results / "pilot").mkdir(parents=True, exist_ok=True)
    summary_path = results / "pilot" / "capa_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(
        {
            "selected": len(samples),
            "status_counts": dict(counts),
            "elapsed_seconds": summary["elapsed_seconds"],
            "summary": str(summary_path),
        },
        indent=2,
    ))
    return 0 if summary["failed"] == 0 and summary["timeouts"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
