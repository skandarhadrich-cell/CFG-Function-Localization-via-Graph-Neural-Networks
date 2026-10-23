#!/usr/bin/env python3
"""Run Stage 1 + Stage 2 on one x86 PE.

Examples
--------
    Arrodes sample.exe
    Arrodes sample.exe --graph graph.npz
    Arrodes sample.exe --no-stage2

    ./venv/bin/python -m src.infer.run sample.exe
    ./venv/bin/python -m src.infer.run --binary sample.exe

Outputs are always written to workspace/<sha256>/report.json and
workspace/<sha256>/report.pdf. The PDF is opened automatically.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

from src.infer.pdf import render_sample_pdf
from src.infer.pipeline import (
    DEFAULT_STAGE1, DEFAULT_STAGE2, InferenceError, build_features,
    check_x86_pe, extracted_graph, load_models, predict_graph, sha256_file,
)
from src.infer.report import build_report, render_text
from src.extract.cfg_store import load_cfg_summary


def sample_output_paths(workspace: Path, sha256: str) -> tuple[Path, Path]:
    """Return the canonical JSON and PDF paths for one sample."""
    sample_dir = Path(workspace).expanduser() / sha256
    return sample_dir / "report.json", sample_dir / "report.pdf"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="Arrodes",
        description="Score one x86 PE for anti_debug, keylogger, injection "
                    "and localise blocks inside flagged functions."
    )
    parser.add_argument("sample", nargs="?", type=Path,
                        help="path to the x86 PE file")
    parser.add_argument("--binary", type=Path,
                        help="path to the x86 PE file (alias for the positional sample)")
    parser.add_argument("--graph", type=Path,
                        help="optional pre-extracted graph .npz; skips angr")
    parser.add_argument("--stage1", type=Path, default=DEFAULT_STAGE1,
                        help="Stage 1 checkpoint (default: results/train/stage1/best.pt)")
    parser.add_argument("--stage2", type=Path, default=DEFAULT_STAGE2,
                        help="Stage 2 checkpoint (default: results/train/stage2/best.pt)")
    parser.add_argument("--no-stage2", action="store_true",
                        help="function-level scores only")
    parser.add_argument("--workspace", type=Path, default=Path("workspace"),
                        help="output root; each sample goes in workspace/<sha256>/")
    parser.add_argument("--timeout", type=float, default=1800.0,
                        help="angr extraction timeout in seconds")
    parser.add_argument("--rss-limit-gb", type=float, default=3.0,
                        help="angr extraction RSS limit in GiB")
    parser.add_argument("--scratch-dir", type=Path,
                        help="parent directory for temporary extraction files")
    parser.add_argument("--keep-graph", type=Path,
                        help="copy the extracted graph .npz here for debugging")
    parser.add_argument("--threads", type=int,
                        default=min(8, os.cpu_count() or 1))
    parser.add_argument("--all-functions", action="store_true",
                        help="include unselected function scores in the JSON")
    parser.add_argument("--max-blocks-per-function", type=int, default=200,
                        help="display cap per function; 0 means unlimited")
    parser.add_argument("--quiet", action="store_true",
                        help="do not print the text summary")
    parser.add_argument("--debug", action="store_true",
                        help="show a traceback on unexpected errors")
    args = parser.parse_args(argv)
    if args.sample is not None and args.binary is not None:
        parser.error(
            "provide the sample path either positionally or with --binary, not both"
        )
    if args.sample is None and args.binary is None:
        parser.error("a sample path is required")
    return args


def _run_graph(binary: Path, graph_path: Path, args, models, sha: str,
               warnings: list[str], extraction: dict) -> dict:
    arrays, api_stats = build_features(graph_path, binary)
    summary = extraction.get("summary") or {}
    arch = str(summary.get("arch") or "")
    if arch and arch.lower() not in {"x86", "i386", "i686"}:
        raise InferenceError(
            f"this model is x86 PE only; extracted architecture is {arch!r}"
        )
    if not api_stats.get("loaded"):
        warnings.append(
            "PE import resolution failed; API features are zero: "
            f"{api_stats.get('error', 'unknown error')}"
        )
    elif int(arrays.get("n_resolved_api_calls", 0)) == 0:
        warnings.append(
            "no API calls resolved in this binary; keylogger/injection API "
            "features are zero"
        )
    p1, p2 = predict_graph(arrays, models)
    base = int(arrays.get("base_address", 0))
    sample = {
        "path": str(binary),
        "path_absolute": str(binary.resolve()),
        "sha256": sha,
        "size_bytes": binary.stat().st_size,
        "arch": arch or "X86",
        "base_address": base,
        "base_address_hex": f"0x{base:x}",
        "functions": int(len(arrays["func_va"])),
        "blocks": int(len(arrays["node_func"])),
        "edges": int(len(arrays["edge_src"])),
    }
    max_blocks = None if args.max_blocks_per_function == 0 else args.max_blocks_per_function
    return build_report(
        sample=sample, arrays=arrays, p1=p1, p2=p2, models=models,
        extraction=extraction, api_stats=api_stats, warnings=warnings,
        all_functions=args.all_functions,
        max_blocks_per_function=max_blocks,
    )


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    binary = (args.binary or args.sample).expanduser()
    try:
        if not binary.exists() or not binary.is_file():
            raise InferenceError(f"binary not found: {binary}")
        sha = sha256_file(binary)
        warnings: list[str] = []
        try:
            header = check_x86_pe(binary)
            if header.get("warning"):
                warnings.append(str(header["warning"]))
        except InferenceError:
            raise
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"PE header check warning: {exc}")

        stage2 = None if args.no_stage2 else args.stage2
        models = load_models(args.stage1, stage2, threads=args.threads)

        if args.graph is not None:
            graph_path = args.graph.expanduser()
            if not graph_path.exists():
                raise InferenceError(f"graph not found: {graph_path}")
            summary = load_cfg_summary(graph_path)
            extraction = {
                "used_pre_extracted_graph": True,
                "graph_path": str(graph_path),
                "summary": summary,
                "elapsed_seconds": 0.0,
                "peak_mb": None,
            }
            report = _run_graph(
                binary, graph_path, args, models, sha, warnings, extraction
            )
        else:
            with extracted_graph(
                binary,
                timeout=args.timeout,
                rss_limit_gb=args.rss_limit_gb,
                scratch_parent=args.scratch_dir,
            ) as ex:
                if args.keep_graph is not None:
                    args.keep_graph.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(ex["graph_path"], args.keep_graph)
                    warnings.append(f"kept extracted graph at {args.keep_graph}")
                extraction = {
                    "used_pre_extracted_graph": False,
                    "graph_path": str(args.keep_graph) if args.keep_graph else None,
                    "summary": ex["summary"],
                    "elapsed_seconds": ex["elapsed_seconds"],
                    "peak_mb": ex["peak_mb"],
                }
                report = _run_graph(
                    binary, ex["graph_path"], args, models, sha, warnings, extraction
                )

        out_json, out_pdf = sample_output_paths(args.workspace, sha)
        out_json.parent.mkdir(parents=True, exist_ok=True)
        tmp = out_json.with_name(out_json.name + ".tmp")
        tmp.write_text(json.dumps(report, indent=2) + "\n")
        tmp.replace(out_json)
        if not args.quiet:
            print(render_text(report), end="")
            print(f"\nwrote {out_json}")

        try:
            render_sample_pdf(report, out_pdf, open_pdf=True)
        except Exception as exc:  # noqa: BLE001
            print(
                f"error: JSON written to {out_json}, but PDF generation failed: {exc}",
                file=sys.stderr,
            )
            if args.debug:
                raise
            return 2
        if not args.quiet:
            print(f"wrote {out_pdf}")
        return 0
    except InferenceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        if args.debug:
            raise
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        if args.debug:
            raise
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
