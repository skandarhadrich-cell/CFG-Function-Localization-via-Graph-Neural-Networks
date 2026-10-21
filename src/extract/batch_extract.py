"""Batch per-function CFG extraction for the Stage 1 run.

Selects v2 clean samples (or an explicit sample list), runs each through
``cfg_worker`` in an isolated process with a hard timeout and RSS watchdog,
writes one packed ``.npz`` per sample, and records failures by category.
Resumable: existing valid ``.npz`` files are skipped.
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
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.extract.cfg_store import load_cfg_summary

ROOT = Path(__file__).resolve().parents[2]


def _resolve(path: str | Path) -> Path:
    path = Path(path).expanduser()
    return path if path.is_absolute() else ROOT / path


@dataclass(frozen=True)
class CfgSample:
    sample_id: str
    filepath: str
    source_bucket: str
    family: str
    cluster_key: str = ""


def read_manifest(manifest: Path, *, clean_only: bool = True) -> list[CfgSample]:
    rows: list[CfgSample] = []
    with manifest.open(newline="") as fh:
        for row in csv.DictReader(fh):
            if clean_only and row.get("is_clean") != "1":
                continue
            rows.append(
                CfgSample(
                    sample_id=row["sample_id"],
                    filepath=row["filepath"],
                    source_bucket=row["source_bucket"],
                    family=row["family"] or "unknown",
                    cluster_key=row.get("cluster_key") or "",
                )
            )
    return rows


def run_worker(
    sample: CfgSample,
    binary: Path,
    out_path: Path,
    scratch_dir: Path,
    timeout: float,
    rss_limit_gb: float,
) -> dict[str, Any]:
    summary_path = scratch_dir / f".cfg-summary-{sample.sample_id}.json"
    command = [
        sys.executable,
        "-m",
        "src.extract.cfg_worker",
        "--sample-id",
        sample.sample_id,
        "--binary",
        str(binary),
        "--scratch",
        str(scratch_dir),
        "--out",
        str(out_path),
        "--summary-out",
        str(summary_path),
    ]
    started = time.time()
    proc = subprocess.Popen(
        command,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    rss_limit_bytes = int(rss_limit_gb * 1024 * 1024 * 1024)
    watchdog = {"killed": False, "peak_mb": 0.0}

    def monitor() -> None:
        import psutil

        try:
            process = psutil.Process(proc.pid)
        except Exception:  # noqa: BLE001
            return
        while proc.poll() is None:
            try:
                total = process.memory_info().rss
                for child in process.children(recursive=True):
                    try:
                        total += child.memory_info().rss
                    except Exception:  # noqa: BLE001
                        pass
                peak = total / (1024 * 1024)
                watchdog["peak_mb"] = max(watchdog["peak_mb"], peak)
                if total > rss_limit_bytes:
                    watchdog["killed"] = True
                    os.killpg(proc.pid, signal.SIGKILL)
                    return
            except Exception:  # noqa: BLE001
                return
            time.sleep(0.5)

    import threading

    monitor_thread = threading.Thread(target=monitor, daemon=True)
    monitor_thread.start()

    timed_out = False
    try:
        _stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(proc.pid, signal.SIGKILL)
        _stdout, stderr = proc.communicate()
    elapsed = time.time() - started
    monitor_thread.join(timeout=2)

    if timed_out:
        return {
            "ok": False,
            "status": "timeout",
            "sample_id": sample.sample_id,
            "elapsed_seconds": round(elapsed, 3),
            "peak_mb": round(watchdog["peak_mb"], 1),
            "error": f"timeout after {timeout:g}s",
        }
    if watchdog["killed"]:
        return {
            "ok": False,
            "status": "memory",
            "sample_id": sample.sample_id,
            "elapsed_seconds": round(elapsed, 3),
            "peak_mb": round(watchdog["peak_mb"], 1),
            "error": f"RSS exceeded {rss_limit_gb} GB",
        }
    if proc.returncode != 0 or not out_path.exists():
        category = "loader" if "ArchNotFound" in (stderr or "") else "crash"
        return {
            "ok": False,
            "status": category,
            "sample_id": sample.sample_id,
            "returncode": proc.returncode,
            "elapsed_seconds": round(elapsed, 3),
            "peak_mb": round(watchdog["peak_mb"], 1),
            "error": (stderr or "")[-1500:],
        }

    try:
        summary = load_cfg_summary(out_path)
    except Exception as exc:  # noqa: BLE001
        out_path.unlink(missing_ok=True)
        return {
            "ok": False,
            "status": "corrupt",
            "sample_id": sample.sample_id,
            "error": f"{type(exc).__name__}: {exc}",
            "elapsed_seconds": round(elapsed, 3),
            "peak_mb": round(watchdog["peak_mb"], 1),
        }
    finally:
        summary_path.unlink(missing_ok=True)

    return {
        "ok": True,
        "status": "ok",
        "sample_id": sample.sample_id,
        "summary": summary,
        "elapsed_seconds": round(elapsed, 3),
        "peak_mb": round(watchdog["peak_mb"], 1),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "data/versions/v2/manifest.csv")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "data/graphs_v2/cfg")
    parser.add_argument("--scratch", type=Path, default=ROOT / "data/processed_v2/cfg_scratch")
    parser.add_argument("--results", type=Path, default=ROOT / "results/full")
    parser.add_argument("--samples-file", type=Path, help="optional stage1 samples.json to restrict to")
    parser.add_argument("--sample-id", action="append", default=[])
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=1800.0)
    parser.add_argument("--rss-limit-gb", type=float, default=3.0)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--resume", action="store_true", default=True)
    args = parser.parse_args(argv)

    manifest = _resolve(args.manifest)
    out_dir = _resolve(args.out_dir)
    scratch = _resolve(args.scratch)
    results = _resolve(args.results)
    out_dir.mkdir(parents=True, exist_ok=True)
    scratch.mkdir(parents=True, exist_ok=True)
    results.mkdir(parents=True, exist_ok=True)

    rows = read_manifest(manifest, clean_only=True)
    if args.samples_file:
        wanted = {
            item["sample_id"]
            for item in json.loads(_resolve(args.samples_file).read_text())["samples"]
        }
        rows = [row for row in rows if row.sample_id in wanted]
    if args.sample_id:
        wanted = set(args.sample_id)
        rows = [row for row in rows if row.sample_id in wanted]
    rows = list({row.sample_id: row for row in rows}.values())
    rows.sort(key=lambda row: row.sample_id)
    if args.limit is not None:
        rows = rows[: args.limit]

    todo: list[CfgSample] = []
    for row in rows:
        out_path = out_dir / f"{row.sample_id}.npz"
        if args.resume and out_path.exists():
            try:
                load_cfg_summary(out_path)
                continue
            except Exception:  # noqa: BLE001
                out_path.unlink(missing_ok=True)
        todo.append(row)

    if not todo:
        print("nothing to do")
        return 0

    print(f"extracting {len(todo)} of {len(rows)} samples with {args.workers} workers")
    started = time.time()
    results_rows: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(
                run_worker,
                row,
                ROOT / row.filepath,
                out_dir / f"{row.sample_id}.npz",
                scratch,
                args.timeout,
                args.rss_limit_gb,
            ): row
            for row in todo
        }
        for index, future in enumerate(as_completed(futures), start=1):
            try:
                result = future.result()
            except Exception as exc:  # noqa: BLE001
                row = futures[future]
                result = {
                    "ok": False,
                    "status": "crash",
                    "sample_id": row.sample_id,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            if result["ok"]:
                results_rows.append(result)
            else:
                failures.append(result)
            if index % 10 == 0 or index == len(futures):
                print(
                    f"cfg {index}/{len(futures)} ok={len(results_rows)} fail={len(failures)}",
                    flush=True,
                )

    by_status: dict[str, int] = {}
    for item in failures:
        by_status[item["status"]] = by_status.get(item["status"], 0) + 1
    summary = {
        "requested": len(todo),
        "completed": len(results_rows),
        "failed": len(failures),
        "failure_by_status": by_status,
        "elapsed_seconds": round(time.time() - started, 2),
        "total_nodes": sum(r["summary"]["node_count"] for r in results_rows),
        "total_edges": sum(r["summary"]["edge_count"] for r in results_rows),
        "dropped_cross_edges": sum(
            r["summary"].get("dropped_cross_edges", 0) for r in results_rows
        ),
        "dropped_call_edges": sum(
            r["summary"].get("dropped_call_edges", 0) for r in results_rows
        ),
        "peak_rss_mb": max((r.get("peak_mb", 0.0) for r in results_rows), default=0.0),
        "failures": failures[:50],
    }
    summary_path = results / "cfg_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
