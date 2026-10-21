# External collection probe — findings

Probe run: 2026-10-21. Purpose: decide whether external collection can fix the
`anti_debug` top-cluster concentration (dominant cluster `imphash:b2c87e30ac`,
274 zbot binaries = 51.3% of positives) before committing to a full pull.

Pre-registered go/no-go bar (in `src/collect/probe_gate.py`):

- **GO** if the probe projects **>= 75 new positive functions** across
  **>= 5 previously unseen imphash clusters**.
- Otherwise widen the family frame; never loosen the quality filter.

## Collection outcome

| Source | Files kept | Pass v2 gate | Clean clusters | Novel clusters |
|---|---:|---:|---:|---:|
| MalwareBazaar | 472 | 218 (47.4%) | 150 | 147 |
| theZoo | 29 | 0 | 0 | 0 |

### MalwareBazaar — viable

218 clean samples in **147 clusters not present in v2**. That is ample cluster
novelty, which is exactly what the `anti_debug` criterion needs.

Filter breakdown on 460 candidates: 208 dotnet, 84 packed, 2 no-imports.

The **45% dotnet rate is structural**, not a bug. The modern RAT families in the
frame (AsyncRAT, QuasarRAT, NanoCore) are .NET by construction, and v2's
`exclude_dotnet` removes them. Remaining native-code yield is concentrated in
Dridex, Pony, AZORult, DarkComet, TrickBot, Berbew.

### theZoo — rejected

151 provenance records succeeded but only 29 distinct binaries resulted: the
archives are highly self-similar (ZeroAccess, PlugX, njRAT re-use the same
few payloads, and plugin DLLs repeat across archives).

More fundamentally, theZoo's Windows PE anti-debug coverage is negligible. The
repository is dominated by Android, Linux, OSX, and pre-2000 virus samples. Of
the 29 files kept, **0 passed the v2 quality gate** (3 .NET, 1 packed among the
4 that were even parseable as candidates).

**Verdict: theZoo is not a useful source for this task and is dropped from the
v3 frame.** It is retained in provenance for auditability.

## Provenance

- `data/external_meta/malwarebazaar.jsonl` — one record per candidate.
- `data/external_meta/thezoo.jsonl` — one record per archive member.
- `data/external_meta/content_index.json` — SHA-256 of every file present.

Every file in `data/raw_external/` is named after its own SHA-256; a mismatch
is a fatal integrity error, checked in tests.

## Tooling notes

Two extractor bugs were found and fixed during the probe:

1. Detecting extracted files by before/after directory diff fails when 7z
   skips existing files — it reported `empty_archive` for 299 samples and
   mislabeled 23 files. Replaced with a post-extraction directory scan plus a
   content-hash index for resume.
2. 7z exits non-zero on Windows-built archives when it cannot restore NTFS
   attributes, despite extracting correctly. Now uses `-aoa -snl` and treats
   that specific error as non-fatal.

Resume is status-aware: only `ok` / `already_present` records block a retry, so
a failed attempt is not permanently skipped.
