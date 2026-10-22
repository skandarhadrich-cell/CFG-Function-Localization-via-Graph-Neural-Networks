"""Build CAPA-to-angr function labels for selected pilot samples.

This is intentionally a thin orchestration layer around the parser, the angr
function-range extractor, and the pure mapping module.  The full Phase 2
extractor will replace the range-only pass with packed CFG data, but the label
table schema stays the same.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import signal
import subprocess
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from src.extract.angr_cfg import extract_function_ranges
from src.extract.cfg_store import functions_from_stored_cfg, load_cfg_summary
from src.label.mapping import MappingResult, aggregate_mapping_summaries, map_capa_to_angr
from src.label.parse_capa import parse_capa_file

ROOT = Path(__file__).resolve().parents[2]


def _resolve(path: str | Path) -> Path:
    path = Path(path).expanduser()
    return path if path.is_absolute() else ROOT / path


def _manifest_paths(manifest: Path) -> dict[str, Path]:
    with manifest.open(newline="") as fh:
        return {
            row["sample_id"]: _resolve(row["filepath"])
            for row in csv.DictReader(fh)
        }


def _manifest_clean_ids(manifest: Path) -> set[str]:
    """Sample IDs the run is allowed to label (clean v2 rows only)."""
    with manifest.open(newline="") as fh:
        return {
            row["sample_id"]
            for row in csv.DictReader(fh)
            if row.get("is_clean", "1") == "1"
        }


def map_one(
    sample_id: str,
    binary: Path,
    capa_json: Path,
    scratch_dir: Path,
    cfg_path: Path | None = None,
) -> dict[str, Any]:
    capa = parse_capa_file(capa_json, sample_id=sample_id)
    if cfg_path is not None and cfg_path.exists():
        # Phase 3: reuse the stored CFG.  No second angr pass, and the mapping
        # is guaranteed to agree with the graph training will consume.
        functions = functions_from_stored_cfg(cfg_path)
        summary = load_cfg_summary(cfg_path)
        base = summary["base_address"]
        inventory_summary = {
            "base_address": base,
            "arch": summary["arch"],
            "function_count": summary["function_count"],
            "block_count": summary["block_count"],
            "source": "stored_cfg",
        }
    else:
        inventory = extract_function_ranges(binary, scratch_dir=scratch_dir)
        functions = inventory.functions
        base = inventory.base_address
        inventory_summary = inventory.summary()
        inventory_summary = {**inventory_summary, "source": "angr"}
    mapping = map_capa_to_angr(
        capa,
        functions,
        angr_base=base,
        sample_id=sample_id,
    )
    return {
        "sample_id": sample_id,
        "inventory": inventory_summary,
        "mapping": mapping.as_dict(),
    }


def run_worker(
    sample_id: str,
    binary: Path,
    capa_json: Path,
    scratch_dir: Path,
    timeout: float,
    cfg_path: Path | None = None,
) -> dict[str, Any]:
    """Run one mapping task in an isolated process with a hard timeout."""

    out_path = scratch_dir / f".map-{sample_id}-{uuid.uuid4().hex}.json"
    command = [
        sys.executable,
        "-m",
        "src.label.map_worker",
        "--sample-id",
        sample_id,
        "--binary",
        str(binary),
        "--capa-json",
        str(capa_json),
        "--scratch",
        str(scratch_dir),
        "--out",
        str(out_path),
    ]
    if cfg_path is not None:
        command += ["--cfg-path", str(cfg_path)]
    started = time.time()
    proc = subprocess.Popen(
        command,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        _stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        _stdout, stderr = proc.communicate()
        out_path.unlink(missing_ok=True)
        return {
            "ok": False,
            "status": "timeout",
            "sample_id": sample_id,
            "error": f"timeout after {timeout:g}s",
            "stderr": stderr[-2000:],
            "elapsed_seconds": round(time.time() - started, 3),
        }

    elapsed = time.time() - started
    if proc.returncode != 0 or not out_path.exists():
        out_path.unlink(missing_ok=True)
        return {
            "ok": False,
            "status": "failed",
            "sample_id": sample_id,
            "returncode": proc.returncode,
            "error": "worker failed",
            "stderr": stderr[-2000:],
            "elapsed_seconds": round(elapsed, 3),
        }

    try:
        payload = json.loads(out_path.read_text())
    finally:
        out_path.unlink(missing_ok=True)
    return {
        "ok": True,
        "status": "ok",
        "sample_id": sample_id,
        "payload": payload,
        "stderr": stderr[-1000:],
        "elapsed_seconds": round(elapsed, 3),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Map CAPA labels onto angr functions.")
    parser.add_argument("--manifest", type=Path, default=ROOT / "data/manifest.csv")
    parser.add_argument("--capa-dir", type=Path, default=ROOT / "data/labels/capa_raw")
    parser.add_argument("--out", type=Path, default=ROOT / "results/full/mapping_three_target.jsonl")
    parser.add_argument("--summary", type=Path, default=ROOT / "results/pilot/mapping_summary.json")
    parser.add_argument("--scratch", type=Path, default=ROOT / "data/processed/angr_scratch")
    parser.add_argument(
        "--cfg-dir",
        type=Path,
        help="directory of stored .npz CFGs; when set, mapping reuses them (no angr)",
    )
    parser.add_argument("--sample-id", action="append", default=[])
    parser.add_argument("--samples-file", type=Path, help="pilot samples.json; restrict to its sample IDs")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--sample-timeout", type=float, default=300.0)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args(argv)

    manifest = _manifest_paths(_resolve(args.manifest))
    clean_ids = _manifest_clean_ids(_resolve(args.manifest))
    capa_dir = _resolve(args.capa_dir)
    out_path = _resolve(args.out)
    summary_path = _resolve(args.summary)
    scratch = _resolve(args.scratch)
    scratch.mkdir(parents=True, exist_ok=True)
    cfg_dir = _resolve(args.cfg_dir) if args.cfg_dir else None

    if args.sample_id:
        sample_ids = list(dict.fromkeys(args.sample_id))
    elif args.samples_file:
        payload = json.loads(_resolve(args.samples_file).read_text())
        sample_ids = [item["sample_id"] for item in payload["samples"]]
    else:
        sample_ids = sorted(
            path.stem
            for path in capa_dir.glob("*.json")
            if not path.name.startswith("_") and not path.name.endswith(".meta.json")
        )
    if args.limit is not None:
        sample_ids = sample_ids[: args.limit]
    # Never label a sample outside the frozen clean set.  When the caller gives
    # no explicit list we glob the CAPA directory, which can contain stale or
    # pilot-only JSON; drop those here rather than letting them into the table.
    excluded = [sid for sid in sample_ids if sid not in clean_ids]
    if excluded:
        print(
            f"excluding {len(excluded)} sample(s) outside the clean set "
            f"(e.g. {excluded[:3]})"
        )
    sample_ids = [sid for sid in sample_ids if sid in clean_ids]
    missing = [sample_id for sample_id in sample_ids if sample_id not in manifest]
    if missing:
        raise SystemExit(f"sample IDs missing from manifest: {missing[:5]}")
    missing_capa = [
        sample_id
        for sample_id in sample_ids
        if not (capa_dir / f"{sample_id}.json").exists()
    ]
    sample_ids = [
        sample_id
        for sample_id in sample_ids
        if (capa_dir / f"{sample_id}.json").exists()
    ]

    done: set[str] = set()
    if args.resume and out_path.exists():
        for line in out_path.read_text().splitlines():
            if line.strip():
                try:
                    done.add(json.loads(line)["sample_id"])
                except (json.JSONDecodeError, KeyError):
                    continue
    # Deduplicate the requested IDs as well, so a repeated --sample-id or a
    # samples.json with duplicate rows cannot append the same sample twice.
    sample_ids = list(dict.fromkeys(sample_ids))
    sample_ids = [sample_id for sample_id in sample_ids if sample_id not in done]

    if not sample_ids:
        print("nothing to do")
        return 0

    out_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = out_path.with_suffix(out_path.suffix + ".lock")
    lock_fh = lock_path.open("w")
    try:
        import fcntl

        fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (ImportError, OSError):
        pass
    results: list[MappingResult] = []
    per_sample: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    mode = "a" if args.resume else "w"
    with out_path.open(mode) as out_fh, ThreadPoolExecutor(
        max_workers=args.workers
    ) as pool:
        futures = {
            pool.submit(
                run_worker,
                sample_id,
                manifest[sample_id],
                capa_dir / f"{sample_id}.json",
                scratch,
                args.sample_timeout,
                (
                    cfg_dir / f"{sample_id}.npz"
                    if cfg_dir is not None and (cfg_dir / f"{sample_id}.npz").exists()
                    else None
                ),
            ): sample_id
            for sample_id in sample_ids
        }
        for index, future in enumerate(as_completed(futures), start=1):
            sample_id = futures[future]
            try:
                result = future.result()
            except Exception as exc:  # noqa: BLE001
                failures.append(
                    {
                        "sample_id": sample_id,
                        "status": "failed",
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                continue
            if not result["ok"]:
                failures.append(result)
                continue
            payload = result["payload"]
            out_fh.write(json.dumps(payload, sort_keys=True) + "\n")
            out_fh.flush()
            per_sample.append(payload["mapping"]["summary"])
            # Reconstruct a lightweight result for aggregation.  The
            # summary is the only part needed for aggregate statistics.
            results.append(
                MappingResult(
                    sample_id=sample_id,
                    rows=[],
                    summary=payload["mapping"]["summary"],
                )
            )
            if index % 5 == 0 or index == len(futures):
                print(f"mapped {index}/{len(futures)}", flush=True)

    # Close and release the resume lock before compacting.
    try:
        lock_fh.close()
    except OSError:
        pass

    # Compact the JSONL: keep the last entry per sample_id so a partial write
    # or an overlapping run cannot leave duplicate rows.
    if args.resume and out_path.exists():
        unique: dict[str, str] = {}
        order: list[str] = []
        for line in out_path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                sid = json.loads(line)["sample_id"]
            except (json.JSONDecodeError, KeyError):
                continue
            if sid not in unique:
                order.append(sid)
            unique[sid] = line
        compacted = "\n".join(unique[sid] for sid in order)
        tmp = out_path.with_name(f".{out_path.name}.{os.getpid()}.tmp")
        tmp.write_text(compacted + ("\n" if compacted else ""))
        os.replace(tmp, out_path)

    aggregate = aggregate_mapping_summaries(results)
    aggregate["requested"] = len(sample_ids) + len(missing_capa)
    aggregate["completed"] = len(per_sample)
    aggregate["failed"] = len(failures)
    aggregate["timeouts"] = sum(item.get("status") == "timeout" for item in failures)
    aggregate["missing_capa_json"] = missing_capa
    aggregate["failures"] = failures[:20]
    summary_path.write_text(json.dumps(aggregate, indent=2) + "\n")
    print(json.dumps(aggregate, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
