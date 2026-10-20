"""Pack and unpack one sample's extracted CFG to/from a single ``.npz``.

Instruction mnemonics and call targets are variable-length per node, so they
are flattened with an offset index.  This keeps one file per sample and avoids
pickle/``gpickle``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np

from src.extract.angr_cfg import ExtractedCFG


def _flatten(sequences: list[list[int]]) -> tuple[np.ndarray, np.ndarray]:
    values: list[int] = []
    offsets = [0]
    for seq in sequences:
        values.extend(seq)
        offsets.append(len(values))
    return np.asarray(values, dtype=np.int64), np.asarray(offsets, dtype=np.int64)


def _flatten_str(sequences: list[list[str]]) -> tuple[np.ndarray, np.ndarray]:
    values: list[str] = []
    offsets = [0]
    for seq in sequences:
        values.extend(seq)
        offsets.append(len(values))
    return np.asarray(values, dtype=object), np.asarray(offsets, dtype=np.int64)


def save_cfg(cfg: ExtractedCFG, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    insn_addrs, insn_offsets = _flatten(cfg.node_instruction_addrs)
    mnemonics, mnemonic_offsets = _flatten_str(cfg.node_mnemonics)
    call_targets, call_offsets = _flatten(cfg.node_call_targets)
    np.savez_compressed(
        path,
        sample_id=np.asarray([cfg.sample_id], dtype=object),
        base_address=np.asarray([cfg.base_address], dtype=np.int64),
        arch=np.asarray([cfg.arch], dtype=object),
        node_block_addr=np.asarray(cfg.node_block_addr, dtype=np.int64),
        node_block_size=np.asarray(cfg.node_block_size, dtype=np.int64),
        node_func_id=np.asarray(cfg.node_func_id, dtype=np.int64),
        insn_addrs=insn_addrs,
        insn_offsets=insn_offsets,
        mnemonics=mnemonics,
        mnemonic_offsets=mnemonic_offsets,
        call_targets=call_targets,
        call_offsets=call_offsets,
        edge_src=np.asarray(cfg.edge_src, dtype=np.int64),
        edge_dst=np.asarray(cfg.edge_dst, dtype=np.int64),
        dropped_cross_edges=np.asarray([cfg.dropped_cross_edges], dtype=np.int64),
        dropped_call_edges=np.asarray([cfg.dropped_call_edges], dtype=np.int64),
        func_va=np.asarray(cfg.func_va, dtype=np.int64),
        func_size=np.asarray(cfg.func_size, dtype=np.int64),
        function_count=np.asarray([cfg.function_count], dtype=np.int64),
        block_count=np.asarray([cfg.block_count], dtype=np.int64),
        instruction_count=np.asarray([cfg.instruction_count], dtype=np.int64),
    )


def _unflatten(values: np.ndarray, offsets: np.ndarray) -> list[list[Any]]:
    return [
        list(values[int(offsets[i]) : int(offsets[i + 1])])
        for i in range(len(offsets) - 1)
    ]


def load_cfg_summary(path: Path) -> dict[str, Any]:
    with np.load(path, allow_pickle=True) as data:
        return {
            "sample_id": str(data["sample_id"][0]),
            "base_address": int(data["base_address"][0]),
            "arch": str(data["arch"][0]),
            "function_count": int(data["function_count"][0]),
            "block_count": int(data["block_count"][0]),
            "instruction_count": int(data["instruction_count"][0]),
            "node_count": int(data["node_block_addr"].shape[0]),
            "edge_count": int(data["edge_src"].shape[0]),
            "dropped_cross_edges": int(data["dropped_cross_edges"][0]),
            "dropped_call_edges": int(data["dropped_call_edges"][0]),
        }


def functions_from_stored_cfg(path: Path) -> list[AngrFunction]:
    """Rebuild label-mapping inventories from a stored CFG, without angr.

    The mapping stage only needs function/block address ranges.  Reconstructing
    them from the packed ``.npz`` avoids a second, expensive angr pass and
    guarantees the mapping uses exactly the CFG that training will see.
    """
    from src.label.mapping import AngrBlock, AngrFunction

    with np.load(path, allow_pickle=True) as data:
        addrs = data["node_block_addr"]
        sizes = data["node_block_size"]
        func_ids = data["node_func_id"]
        func_va = data["func_va"]

    by_func: dict[int, list[AngrBlock]] = {}
    for addr, size, func_id in zip(addrs, sizes, func_ids):
        by_func.setdefault(int(func_id), []).append(
            AngrBlock(va=int(addr), size=int(size))
        )

    functions: list[AngrFunction] = []
    for func_id, blocks in by_func.items():
        blocks.sort(key=lambda block: block.va)
        functions.append(
            AngrFunction(func_va=int(func_va[func_id]), blocks=tuple(blocks))
        )
    functions.sort(key=lambda func: func.func_va)
    return functions
