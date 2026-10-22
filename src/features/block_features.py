#!/usr/bin/env python3
"""Build the per-block feature matrix and function-label corpus.

The corpus is the frozen v2 clean set (x86 PE, ~2,700 samples).  Every graph is
flattened once into:

  ``block_feats.npy``  float16 [n_blocks, N_FEAT] memmap
  ``graph_meta.npz``   per-graph offsets, per-function labels, eligibility
  ``feature_spec.json`` human-readable feature layout

Block features (N_FEAT = 187):

    dims   0..114  opcode frequency (114 opcodes + "other")
    dims 115..119  log1p(block size), log1p(instructions), log1p(in-degree),
                   log1p(out-degree), is-entry
    dims 120..183  hashed API-reference frequency (64 buckets)
    dim  184       log1p(number of import-resolved calls in the block)
    dim  185       log1p(number of distinct API buckets in the block)
    dim  186       has at least one import-resolved call

The opcode vocabulary includes the anti-debug/system instructions that the
three target rules rely on (``rdtsc``, ``icebp``/``int1``, ``cpuid``,
``pushfd``/``popfd``, ``in``/``out``, ...), not just general integer ops.

The API features are resolved from the PE import table.  Two routes are used:

* a direct call target that is an import thunk start;
* an instruction address whose bytes are ``call/jmp dword ptr [IAT]`` (the
  import-reference site itself).

The second route matters for the keylogger and injection calls that angr's
CFG does not resolve to a call target.  No CAPA rule name, label, or target
string enters the model input.

Labels are the three CAPA target namespaces.  ``eligible`` is 1 for a mapped
function in a sample with at least one CAPA rule; 0 for unmapped functions and
for samples with no rule evidence at all (unlabeled, never negatives).
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import struct
import sys

import numpy as np
import pandas as pd

ROOT = pathlib.Path(__file__).resolve().parents[2]
GRAPH_DIR = ROOT / "data" / "graphs_v2" / "cfg"
DEFAULT_OUT_DIR = ROOT / "results" / "corpus_v2_three_targets"
DEFAULT_LABELS = ROOT / "data" / "labels" / "stage1_full_three_targets.parquet"
DEFAULT_MANIFEST = ROOT / "data" / "versions" / "v2" / "manifest.csv"
DEFAULT_SPLITS = ROOT / "data" / "versions" / "v2" / "splits" / "three_target.json"

LABEL_NAMES = ("anti_debug", "keylogger", "injection")
N_LABELS = len(LABEL_NAMES)

OPCODES = [
    # baseline integer / control flow
    "mov", "push", "pop", "call", "ret", "jmp", "cmp", "add", "sub", "test",
    "lea", "and", "or", "xor", "inc", "dec", "je", "jne", "jg", "jl",
    "jge", "jle", "jb", "ja", "jae", "jbe", "shr", "shl", "nop", "int3",
    "movzx", "movsx", "adc", "sbb", "mul", "div", "rol", "ror", "xchg",
    "leave", "retn", "cld", "std", "rep", "repne", "lodsb", "stosb", "cdq", "neg",
    # anti-debug / anti-VM / system instructions
    "rdtsc", "rdtscp", "rdpmc", "cpuid", "icebp", "int1", "int", "sysenter",
    "syscall", "sysret", "sysexit", "pushfd", "popfd", "pushf", "popf",
    "pushal", "popal", "pushad", "popad", "sahf", "lahf", "cli", "sti",
    "hlt", "in", "out", "insb", "outsb", "xgetbv", "fnstenv", "fldenv",
    "fxsave", "fxrstor",
    # common integer / bit / conditional operations
    "not", "imul", "idiv", "bt", "bts", "btr", "btc", "bsf", "bsr", "bswap",
    "xadd", "cmpxchg", "sete", "setne", "setg", "setl", "setge", "setle",
    "setb", "seta", "setae", "setbe", "cmove", "cmovne", "cmovg", "cmovl",
    "cmovge", "cmovle", "cmovb", "cmova", "cmovae", "cmovbe",
]
VOCAB = {op: i for i, op in enumerate(OPCODES)}
N_OPCODE = len(OPCODES) + 1          # + 'other'
N_STRUCT = 5
N_API_BUCKETS = 64
N_API_SCALAR = 3
API_START = N_OPCODE + N_STRUCT
N_FEAT = API_START + N_API_BUCKETS + N_API_SCALAR
OPCODE_SLICE = slice(0, N_OPCODE)
STRUCT_SLICE = slice(N_OPCODE, API_START)
API_SLICE = slice(API_START, API_START + N_API_BUCKETS)
API_SCALAR_SLICE = slice(API_START + N_API_BUCKETS, N_FEAT)

STATUS_CODES = {"unlabeled": 0, "weak_negative": 1, "positive": 2}


def api_bucket(name: str) -> int:
    """Stable hash of an import name into one of ``N_API_BUCKETS`` buckets."""
    digest = hashlib.blake2b(name.encode("utf-8", "replace"), digest_size=2).digest()
    return int.from_bytes(digest, "little") % N_API_BUCKETS


def load_import_map(pe_path: pathlib.Path, graph_base: int) -> tuple[dict[int, str], dict]:
    """Map absolute call-target VAs to ``dll!function`` names.

    Returns ``(thunk_map, stats)``.  Resolution is deliberately conservative:
    a call is resolved only when its target is a recognised import thunk or an
    IAT slot.  Unresolved calls are internal calls and carry no API feature.
    """
    try:
        import pefile
    except ImportError:  # pragma: no cover - environment guard
        return {}, {"error": "pefile not installed"}

    stats = {"loaded": False, "imports": 0, "thunks": 0}
    try:
        pe = pefile.PE(str(pe_path), fast_load=False)
    except Exception as exc:  # noqa: BLE001 - a broken PE yields zero features
        stats["error"] = f"{type(exc).__name__}: {exc}"
        return {}, stats

    delta = int(graph_base) - int(pe.OPTIONAL_HEADER.ImageBase)
    iat: dict[int, str] = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = entry.dll.decode("utf-8", "replace").lower()
        for imp in entry.imports:
            name = (
                imp.name.decode("utf-8", "replace")
                if imp.name
                else f"ord{imp.ordinal}"
            )
            iat[int(imp.address) + delta] = f"{dll}!{name}"

    thunk: dict[int, str] = {}
    for section in pe.sections:
        # IMAGE_SCN_MEM_EXECUTE
        if not (section.Characteristics & 0x20000000):
            continue
        data = section.get_data()
        base_va = int(graph_base) + int(section.VirtualAddress)
        for pattern in (b"\xff\x25", b"\xff\x15"):
            start = 0
            while True:
                pos = data.find(pattern, start)
                if pos < 0:
                    break
                if pos + 6 <= len(data):
                    target = struct.unpack_from("<I", data, pos + 2)[0] + delta
                    name = iat.get(target)
                    if name:
                        thunk[base_va + pos] = name
                start = pos + 1

    stats.update(
        {
            "loaded": True,
            "imports": len(iat),
            "thunks": len(thunk),
        }
    )
    return thunk, stats


def graph_arrays(d, api_map: dict[int, str] | None = None) -> dict:
    """Compute block features and address maps for one graph.

    ``d`` is an open ``npz`` mapping.  ``api_map`` maps absolute call-target
    VAs to import names; when omitted the API feature block is zeros.
    Returned arrays are local to this graph (node indices start at 0).
    """
    base = int(d["base_address"][0]) if "base_address" in d else 0
    nfi = np.asarray(d["node_func_id"], dtype=np.int32)
    nb = len(nfi)
    moff = np.asarray(d["mnemonic_offsets"], dtype=np.int64)
    mnems = d["mnemonics"]
    es = np.asarray(d["edge_src"], dtype=np.int32)
    ed = np.asarray(d["edge_dst"], dtype=np.int32)
    bsize = np.asarray(d["node_block_size"], dtype=np.int64)
    fva = np.asarray(d["func_va"], dtype=np.int64)
    fsz = np.asarray(d["func_size"], dtype=np.int64)
    call_offsets = np.asarray(d.get("call_offsets", np.zeros(1)), dtype=np.int64)
    call_targets = np.asarray(d.get("call_targets", np.zeros(0)), dtype=np.int64)
    insn_offsets = np.asarray(d.get("insn_offsets", np.zeros(1)), dtype=np.int64)
    insn_addrs = np.asarray(d.get("insn_addrs", np.zeros(0)), dtype=np.int64)

    n_insn = int(moff[-1]) if len(moff) else 0

    ids = np.fromiter(
        (VOCAB.get(str(m).lower(), N_OPCODE - 1) for m in mnems),
        dtype=np.int16, count=n_insn,
    )
    counts = np.zeros((nb, N_OPCODE), dtype=np.float32)
    if n_insn:
        onehot = np.zeros((n_insn, N_OPCODE), dtype=np.float32)
        onehot[np.arange(n_insn), ids] = 1.0
        nonempty = moff[1:] > moff[:-1] if len(moff) > 1 else np.zeros(0, bool)
        if nonempty.any():
            counts[nonempty] = np.add.reduceat(onehot, moff[:-1][nonempty], axis=0)

    n_insn_block = (
        (moff[1:] - moff[:-1]).astype(np.float32)
        if len(moff) > 1 else np.zeros(nb, dtype=np.float32)
    )
    denom = np.maximum(n_insn_block, 1.0)[:, None]
    opcode_freq = counts / denom

    # Edges are local node indices; ignore any out-of-range edge defensively.
    valid = (es >= 0) & (es < nb) & (ed >= 0) & (ed < nb)
    es, ed = es[valid], ed[valid]
    in_deg = np.bincount(ed, minlength=nb).astype(np.float32)
    out_deg = np.bincount(es, minlength=nb).astype(np.float32)

    struct = np.stack([
        np.log1p(bsize.astype(np.float32)),
        np.log1p(n_insn_block),
        np.log1p(in_deg),
        np.log1p(out_deg),
        (in_deg == 0).astype(np.float32),
    ], axis=1)

    # ---- API-reference features ------------------------------------------
    api_counts = np.zeros((nb, N_API_BUCKETS), dtype=np.float32)
    n_resolved = np.zeros(nb, dtype=np.float32)
    if api_map and len(call_targets) and len(call_offsets) >= 2:
        co = call_offsets
        ct = call_targets
        n_calls = max(len(co) - 1, 0)
        if n_calls == nb:
            per_block = np.diff(co)
            block_ids = np.repeat(np.arange(nb, dtype=np.int64), per_block)
            names = [api_map.get(int(t)) for t in ct]
            resolved = np.fromiter((n is not None for n in names), dtype=bool, count=len(names))
            if resolved.any():
                rb = block_ids[resolved]
                rbucket = np.fromiter(
                    (api_bucket(n) for n, keep in zip(names, resolved) if keep),
                    dtype=np.int64, count=int(resolved.sum()),
                )
                np.add.at(api_counts, (rb, rbucket), 1.0)
                n_resolved += np.bincount(rb, minlength=nb).astype(np.float32)

    # Import-reference sites: `call/jmp dword ptr [IAT]`.  These are not
    # call targets in angr's CFG, so keylogger/injection API calls would
    # otherwise lose their API feature.
    if api_map and len(insn_addrs) and len(insn_offsets) >= 2:
        per_block = np.diff(insn_offsets)
        if len(per_block) == nb:
            block_ids = np.repeat(np.arange(nb, dtype=np.int64), per_block)
            names = [api_map.get(int(address)) for address in insn_addrs]
            resolved = np.fromiter(
                (name is not None for name in names), dtype=bool, count=len(names)
            )
            if resolved.any():
                rb = block_ids[resolved]
                rbucket = np.fromiter(
                    (api_bucket(name) for name, keep in zip(names, resolved) if keep),
                    dtype=np.int64, count=int(resolved.sum()),
                )
                np.add.at(api_counts, (rb, rbucket), 1.0)
                n_resolved += np.bincount(rb, minlength=nb).astype(np.float32)

    api_freq = api_counts / denom
    n_buckets = (api_counts > 0).sum(axis=1).astype(np.float32)
    api_scalars = np.stack([
        np.log1p(n_resolved),
        np.log1p(n_buckets),
        (n_resolved > 0).astype(np.float32),
    ], axis=1)

    block = np.concatenate([opcode_freq, struct, api_freq, api_scalars], axis=1)
    if block.shape[1] != N_FEAT:
        raise AssertionError(f"feature width {block.shape[1]} != {N_FEAT}")
    block = block.astype(np.float16)

    rvas = fva - base if base else fva
    return {
        "x": block,
        "edge_src": es.astype(np.int64),
        "edge_dst": ed.astype(np.int64),
        "node_func": nfi.astype(np.int64),
        "func_va": fva,
        "func_rva": rvas,
        "func_size": fsz,
        "base_address": base,
        "block_addr": np.asarray(d["node_block_addr"], dtype=np.int64),
        "block_size": bsize,
        "mnemonic_offsets": moff,
        "mnemonics": mnems,
        "insn_addrs": np.asarray(d["insn_addrs"], dtype=np.int64),
        "insn_offsets": np.asarray(d["insn_offsets"], dtype=np.int64),
        "n_resolved_api_calls": int(n_resolved.sum()),
        "n_calls": int(len(call_targets)),
    }


def load_labels(path: pathlib.Path) -> dict[str, tuple[np.ndarray, np.ndarray, np.ndarray]]:
    """Return ``{sample_id: (func_vas, y[n,3], status[n])}``."""
    frame = pd.read_parquet(path)
    out: dict[str, tuple[np.ndarray, np.ndarray, np.ndarray]] = {}
    columns = [f"label_{name}" for name in LABEL_NAMES]
    for sample_id, group in frame.groupby("sample_id", sort=False):
        vas = group["func_va"].to_numpy(dtype=np.int64)
        y = group[columns].to_numpy(dtype=np.int8)
        status = group["label_status"].map(STATUS_CODES).fillna(0).to_numpy(dtype=np.int8)
        out[str(sample_id)] = (vas, y, status)
    return out


def build(
    sample_ids: list[str],
    labels: dict[str, tuple[np.ndarray, np.ndarray, np.ndarray]],
    zero_rule: set[str],
    *,
    out_dir: pathlib.Path = DEFAULT_OUT_DIR,
    manifest_path: pathlib.Path = DEFAULT_MANIFEST,
) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)

    # First pass: sizes, so the memmap can be allocated exactly.
    per_graph = []
    total_blocks = 0
    total_edges = 0
    total_funcs = 0

    print("pass 1: sizing", flush=True)
    for i, sid in enumerate(sample_ids):
        path = GRAPH_DIR / f"{sid}.npz"
        with np.load(path, allow_pickle=True) as d:
            nb = int(d["block_count"][0])
            nf = int(d["function_count"][0])
            ne = int(len(d["edge_src"]))
        per_graph.append((nb, nf, ne))
        total_blocks += nb
        total_edges += ne
        total_funcs += nf
        if (i + 1) % 500 == 0:
            print(f"  {i + 1}/{len(sample_ids)} graphs, {total_blocks:,} blocks", flush=True)

    print(
        f"totals: blocks={total_blocks:,} edges={total_edges:,} funcs={total_funcs:,}",
        flush=True,
    )

    feats = np.lib.format.open_memmap(
        out_dir / "block_feats.npy", mode="w+", dtype=np.float16,
        shape=(total_blocks, N_FEAT),
    )

    node_off = np.zeros(len(sample_ids) + 1, dtype=np.int64)
    edge_off = np.zeros(len(sample_ids) + 1, dtype=np.int64)
    func_off = np.zeros(len(sample_ids) + 1, dtype=np.int64)

    edge_src_all = np.empty(total_edges, dtype=np.int32)
    edge_dst_all = np.empty(total_edges, dtype=np.int32)
    node_func_all = np.empty(total_blocks, dtype=np.int32)
    func_va_all = np.empty(total_funcs, dtype=np.int64)
    func_rva_all = np.empty(total_funcs, dtype=np.int64)
    func_size_all = np.empty(total_funcs, dtype=np.int64)
    y_all = np.zeros((total_funcs, N_LABELS), dtype=np.int8)
    status_all = np.zeros(total_funcs, dtype=np.int8)
    eligible_all = np.zeros(total_funcs, dtype=np.int8)
    rule_evidence_all = np.zeros(total_funcs, dtype=np.int8)

    # Manifest gives the PE path used to resolve imports.
    manifest = pd.read_csv(manifest_path)
    filepath = dict(zip(manifest["sample_id"], manifest["filepath"]))
    api_stats = {"pe_loaded": 0, "pe_failed": 0, "calls": 0, "resolved_calls": 0}

    bo = eo = fo = 0
    print("\npass 2: features", flush=True)
    for gi, sid in enumerate(sample_ids):
        path = GRAPH_DIR / f"{sid}.npz"
        with np.load(path, allow_pickle=True) as d:
            base = int(d["base_address"][0]) if "base_address" in d else 0
            api_map, stats = load_import_map(
                pathlib.Path(filepath.get(sid, "")), base
            )
            if not stats.get("loaded"):
                api_stats["pe_failed"] += 1
            else:
                api_stats["pe_loaded"] += 1
            a = graph_arrays(d, api_map)

        nb, nf, ne = per_graph[gi]
        assert len(a["x"]) == nb and len(a["edge_src"]) == ne, (
            f"{sid}: edge filtering changed the graph shape"
        )

        feats[bo:bo + nb] = a["x"]
        edge_src_all[eo:eo + ne] = a["edge_src"]
        edge_dst_all[eo:eo + ne] = a["edge_dst"]
        node_func_all[bo:bo + nb] = a["node_func"]

        func_va_all[fo:fo + nf] = a["func_va"]
        func_size_all[fo:fo + nf] = a["func_size"]
        rvas = a["func_rva"]
        func_rva_all[fo:fo + nf] = rvas

        vas, y, status = labels.get(sid, (np.zeros(0, np.int64),
                                         np.zeros((0, N_LABELS), np.int8),
                                         np.zeros(0, np.int8)))
        if len(vas):
            # The label table stores absolute func_va values, exactly as angr
            # reports them; match on that, not on the RVA used for display.
            fvas = a["func_va"]
            pos = np.searchsorted(vas, fvas)
            pos = np.clip(pos, 0, len(vas) - 1)
            hit = vas[pos] == fvas
            y_all[fo:fo + nf][hit] = y[pos[hit]]
            status_all[fo:fo + nf][hit] = status[pos[hit]]
        eligible_all[fo:fo + nf] = (
            (status_all[fo:fo + nf] > 0) & (sid not in zero_rule)
        ).astype(np.int8)
        rule_evidence_all[fo:fo + nf] = 0 if sid in zero_rule else 1

        # Offsets always advance.  A zero-rule sample is retained with
        # eligible=0; dropping it here would corrupt every later offset.
        bo += nb
        eo += ne
        fo += nf
        node_off[gi + 1] = bo
        edge_off[gi + 1] = eo
        func_off[gi + 1] = fo

        api_stats["calls"] += int(a["n_calls"])
        api_stats["resolved_calls"] += int(a["n_resolved_api_calls"])

        if (gi + 1) % 250 == 0:
            print(
                f"  {gi + 1}/{len(sample_ids)} graphs  ({bo:,} blocks, "
                f"{api_stats['resolved_calls']:,} API calls resolved)",
                flush=True,
            )

    feats.flush()
    del feats

    np.savez(
        out_dir / "graph_meta.npz",
        sample_ids=np.array(sample_ids, dtype=object),
        label_names=np.array(LABEL_NAMES, dtype=object),
        node_off=node_off,
        edge_off=edge_off,
        func_off=func_off,
        edge_src=edge_src_all,
        edge_dst=edge_dst_all,
        node_func=node_func_all,
        func_va=func_va_all,
        func_rva=func_rva_all,
        func_size=func_size_all,
        y=y_all,
        status=status_all,
        eligible=eligible_all,
        rule_evidence=rule_evidence_all,
    )

    spec = {
        "n_features": N_FEAT,
        "opcodes": OPCODES,
        "other_index": N_OPCODE - 1,
        "structural": [
            "log1p_block_size", "log1p_n_insn", "log1p_in_degree",
            "log1p_out_degree", "is_entry",
        ],
        "api_buckets": N_API_BUCKETS,
        "api_scalars": [
            "log1p_resolved_calls", "log1p_distinct_buckets", "has_api_call",
        ],
        "opcode_slice": [OPCODE_SLICE.start, OPCODE_SLICE.stop],
        "structural_slice": [STRUCT_SLICE.start, STRUCT_SLICE.stop],
        "api_slice": [API_SLICE.start, API_SLICE.stop],
        "api_scalar_slice": [API_SCALAR_SLICE.start, API_SCALAR_SLICE.stop],
        "labels": list(LABEL_NAMES),
        "label_source": (
            "CAPA namespaces: anti-analysis/anti-debugging, collection/keylog, "
            "host-interaction/process/inject + load-code/pe/inject-"
        ),
        "note": "No CAPA rule identifier or label value is used as model input.",
    }
    (out_dir / "feature_spec.json").write_text(json.dumps(spec, indent=2) + "\n")

    report = {
        "samples": len(sample_ids),
        "blocks": total_blocks,
        "edges": total_edges,
        "functions": total_funcs,
        "feature_width": N_FEAT,
        "label_counts": {
            name: int(y_all[:, i].sum()) for i, name in enumerate(LABEL_NAMES)
        },
        "eligible_functions": int(eligible_all.sum()),
        "zero_rule_samples": len(zero_rule & set(sample_ids)),
        "api": api_stats,
    }
    (out_dir / "build_report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"\nwrote {out_dir / 'block_feats.npy'} "
          f"({total_blocks:,} x {N_FEAT})", flush=True)
    print(json.dumps(report, indent=2), flush=True)
    return report


def main() -> None:
    zero_rule = {
        s["sample_id"]
        for s in json.loads(
            (ROOT / "data" / "labels" / "zero_rule_samples.json").read_text()
        )["samples"]
    }
    splits = json.loads(DEFAULT_SPLITS.read_text())
    sample_ids = sorted(splits["assignments"])
    have = {p.stem for p in GRAPH_DIR.glob("*.npz")}
    sample_ids = [s for s in sample_ids if s in have]

    labels = load_labels(DEFAULT_LABELS)
    print(
        f"{len(sample_ids)} samples with graphs, "
        f"{len(labels)} samples with label rows",
        flush=True,
    )
    build(sample_ids, labels, zero_rule)


if __name__ == "__main__":
    sys.exit(main())
