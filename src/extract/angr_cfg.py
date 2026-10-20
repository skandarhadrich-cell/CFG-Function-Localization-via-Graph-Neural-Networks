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


@dataclass
class ExtractedCFG:
    """Per-function packed CFG data for one sample.

    Node arrays are indexed by a global node id.  ``func_id`` maps each node to
    its function.  Edges are directed and strictly intraprocedural.
    """

    sample_id: str
    base_address: int
    arch: str
    node_block_addr: list[int]
    node_block_size: list[int]
    node_func_id: list[int]
    node_instruction_addrs: list[list[int]]
    node_mnemonics: list[list[str]]
    node_call_targets: list[list[int]]
    edge_src: list[int]
    edge_dst: list[int]
    dropped_cross_edges: int
    dropped_call_edges: int
    func_va: list[int]
    func_size: list[int]
    function_count: int
    block_count: int
    instruction_count: int
    elapsed_seconds: float
    maxrss_mb: float

    def summary(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "base_address": self.base_address,
            "arch": self.arch,
            "function_count": self.function_count,
            "block_count": self.block_count,
            "node_count": len(self.node_block_addr),
            "edge_count": len(self.edge_src),
            "instruction_count": self.instruction_count,
            "dropped_cross_edges": self.dropped_cross_edges,
            "dropped_call_edges": self.dropped_call_edges,
            "call_target_count": sum(len(t) for t in self.node_call_targets),
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "maxrss_mb": round(self.maxrss_mb, 1),
        }


def extract_cfg(
    binary: Path,
    sample_id: str,
    *,
    scratch_dir: Path | None = None,
    normalize: bool = True,
) -> ExtractedCFG:
    """Extract per-function CFGs with intraprocedural edges and call targets.

    Calls are stored as node features (``node_call_targets``), never as graph
    edges.  Any edge whose endpoints belong to different functions is dropped
    and counted in ``dropped_cross_edges``; it must be zero for the training
    dataset.
    """

    import psutil
    import resource

    import angr

    started = time.time()
    with tempfile.TemporaryDirectory(dir=scratch_dir, prefix="angr-cfg-") as temp_dir:
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

        node_block_addr: list[int] = []
        node_block_size: list[int] = []
        node_func_id: list[int] = []
        node_instruction_addrs: list[list[int]] = []
        node_mnemonics: list[list[str]] = []
        node_call_targets: list[list[int]] = []
        # block address -> node id, scoped per function.  angr can report a
        # block in more than one overlapping function's graph, so a single
        # global map would clobber entries; each function keeps its own map.
        block_to_node_by_func: list[dict[int, int]] = []
        func_va: list[int] = []
        func_size: list[int] = []
        functions: list[Any] = []
        for func in cfg.kb.functions.values():
            # func.graph is the authoritative per-function block graph.  It can
            # include blocks that func.blocks omits when angr's function
            # detection overlaps, and those blocks carry real control flow.
            graph_nodes = [
                node
                for node in func.graph.nodes()
                if int(getattr(node, "size", 0)) > 0
            ]
            if not graph_nodes:
                continue
            functions.append((func, graph_nodes))

        functions.sort(key=lambda item: item[0].addr)
        instruction_count = 0
        for func_id, (func, graph_nodes) in enumerate(functions):
            func_va.append(int(func.addr))
            func_size.append(int(func.size))
            func_map: dict[int, int] = {}
            for node_obj in sorted(graph_nodes, key=lambda n: int(n.addr)):
                addr = int(node_obj.addr)
                if addr in func_map:
                    continue
                model_node = cfg.model.get_any_node(addr)
                block = model_node.block if model_node is not None else None
                if block is None:
                    block = project.factory.block(addr, size=int(node_obj.size))
                node = len(node_block_addr)
                func_map[addr] = node
                node_block_addr.append(addr)
                node_block_size.append(int(block.size))
                node_func_id.append(func_id)
                addrs: list[int] = []
                mnemonics: list[str] = []
                calls: list[int] = []
                for insn in block.capstone.insns:
                    addrs.append(int(insn.address))
                    mnemonics.append(str(insn.mnemonic))
                    instruction_count += 1
                for call_site in func.get_call_sites() or []:
                    if addr <= int(call_site) < addr + int(block.size):
                        target = func.get_call_target(call_site)
                        if target:
                            calls.append(int(target))
                node_instruction_addrs.append(addrs)
                node_mnemonics.append(mnemonics)
                node_call_targets.append(sorted(set(calls)))
            block_to_node_by_func.append(func_map)

        edge_src: list[int] = []
        edge_dst: list[int] = []
        dropped_cross_edges = 0
        dropped_call_edges = 0
        dropped_suspicious = 0
        for func_id, (func, _graph_nodes) in enumerate(functions):
            block_to_node = block_to_node_by_func[func_id]
            graph = func.graph
            for src, dst, data in graph.edges(data=True):
                edge_type = str(data.get("type"))
                outside = bool(data.get("outside"))
                # angr's per-function graph mixes edge kinds:
                #   - "call":        explicit interprocedural call
                #   - "return":      call-return stitching
                #   - "fake_return": tail-call / return-site stitching
                #   - "transition":  intraprocedural basic-block control flow
                # Only intraprocedural transitions may become graph edges.  All
                # others are dropped and logged; call targets are still captured
                # as node features via get_call_target().
                if edge_type == "call":
                    dropped_call_edges += 1
                    continue
                if outside or edge_type != "transition":
                    dropped_cross_edges += 1
                    continue
                src_node = block_to_node.get(int(src.addr))
                dst_node = block_to_node.get(int(dst.addr))
                if src_node is None or dst_node is None:
                    # A non-outside transition whose endpoint is not a known
                    # block of this function is a real extraction bug: it means
                    # intraprocedural control flow would be silently lost.
                    dropped_suspicious += 1
                    continue
                if node_func_id[src_node] != func_id or node_func_id[dst_node] != func_id:
                    dropped_suspicious += 1
                    continue
                edge_src.append(src_node)
                edge_dst.append(dst_node)

        # Refuse to emit a graph that is missing intraprocedural control flow.
        # Interprocedural drops (calls, tail calls, hooks, returns) are expected
        # and recorded in dropped_cross_edges / dropped_call_edges.
        if dropped_suspicious:
            raise RuntimeError(
                f"{sample_id}: dropped {dropped_suspicious} suspicious "
                "intraprocedural edges"
            )

    return ExtractedCFG(
        sample_id=sample_id,
        base_address=base,
        arch=arch,
        node_block_addr=node_block_addr,
        node_block_size=node_block_size,
        node_func_id=node_func_id,
        node_instruction_addrs=node_instruction_addrs,
        node_mnemonics=node_mnemonics,
        node_call_targets=node_call_targets,
        edge_src=edge_src,
        edge_dst=edge_dst,
        dropped_cross_edges=dropped_cross_edges,
        dropped_call_edges=dropped_call_edges,
        func_va=func_va,
        func_size=func_size,
        function_count=len(functions),
        block_count=len(node_block_addr),
        instruction_count=instruction_count,
        elapsed_seconds=time.time() - started,
        maxrss_mb=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024,
    )
