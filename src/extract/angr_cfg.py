"""angr CFG extraction primitives.

Phase 1 only needs function/block ranges for label mapping.  The full Phase 2
extractor will add instructions, call targets, and packed per-function edges;
keeping the range recovery here makes the mapping path reusable.
"""

from __future__ import annotations

import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.data.repair_pe import repair_file
from src.label.mapping import AngrBlock, AngrFunction


@dataclass
class FunctionInventory:
    functions: list[AngrFunction]
    base_address: int
    arch: str
    elapsed_seconds: float
    function_count: int
    block_count: int
    rss_after_mb: float = 0.0
    maxrss_mb: float = 0.0

    def summary(self) -> dict[str, Any]:
        return {
            "base_address": self.base_address,
            "arch": self.arch,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "function_count": self.function_count,
            "block_count": self.block_count,
            "rss_after_mb": round(self.rss_after_mb, 1),
            "maxrss_mb": round(self.maxrss_mb, 1),
        }


def extract_function_ranges(
    binary: Path,
    *,
    scratch_dir: Path | None = None,
    normalize: bool = True,
) -> FunctionInventory:
    """Load a PE in angr and recover function/block ranges with CFGFast."""

    import angr

    started = time.time()
    with tempfile.TemporaryDirectory(dir=scratch_dir, prefix="angr-inv-") as temp_dir:
        repaired = Path(temp_dir) / f"{binary.stem}.exe"
        repair_file(binary, repaired)
        project = angr.Project(str(repaired), auto_load_libs=False)
        base = int(project.loader.main_object.mapped_base)
        arch = str(project.arch.name)
        cfg = project.analyses.CFGFast(
            normalize=normalize,
            resolve_indirect_jumps=True,
            data_references=False,
        )

        functions: list[AngrFunction] = []
        block_count = 0
        for func in cfg.kb.functions.values():
            blocks = tuple(
                AngrBlock(block.addr, block.size)
                for block in func.blocks
                if block.size > 0
            )
            if not blocks:
                continue
            functions.append(AngrFunction(func_va=int(func.addr), blocks=blocks))
            block_count += len(blocks)

    functions.sort(key=lambda item: item.func_va)
    import psutil
    import resource

    return FunctionInventory(
        functions=functions,
        base_address=base,
        arch=arch,
        elapsed_seconds=time.time() - started,
        function_count=len(functions),
        block_count=block_count,
        rss_after_mb=psutil.Process().memory_info().rss / (1024 * 1024),
        maxrss_mb=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024,
    )
