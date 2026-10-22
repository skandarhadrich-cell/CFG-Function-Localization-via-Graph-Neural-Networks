# BODMAS disarming and repair (2026-10-22)

`PE_modifier.py` and a README describing the disarm are not present in
`/mnt/hgfs/D/` (only `BODMAS_disarmed_malware_binaries.zip`,
`bodmas_metadata.csv`, `FlraeVM.vdi`) or in the public
`whyisyoung/BODMAS` repository. The behaviour is established empirically.

## What disarming changes

Comparing disarmed BODMAS samples to native theZoo samples of the same family:

| PE header field | disarmed | native | effect |
|---|---|---|---|
| COFF `Machine` | `0x0000` (`IMAGE_FILE_MACHINE_UNKNOWN`) | `0x014c` (x86) / `0x8664` (x64) | **Required** — CAPA rc=17 with "unsupported architecture" for native PE files. |
| Optional header `Subsystem` | `0` | `2` (GUI) / `3` (CUI) | **Not required** — zeroing it does not break CAPA or angr analysis. |
| `TimeDateStamp` | preserved | varies | not disarmed. |
| `Characteristics` | preserved | varies | not disarmed. |
| `NumberOfSections`, `SizeOfOptionalHeader` | preserved | varies | not disarmed. |
| `Checksum` | `0` | often `0` in natives too | not evidence of disarming. |

So disarming zeros **Machine and Subsystem**. Machine is the breaking one.

## Repair

`src/data/repair_pe.py` restores a copy to disk (never mutates the raw
corpus):

- `Machine` is restored **exactly** from the optional-header magic (`0x10b` →
  `IMAGE_FILE_MACHINE_I386`, `0x20b` → `IMAGE_FILE_MACHINE_AMD64`).
- `Subsystem` is set to **CUI (3)** when it is zeroed; this is a **deterministic
  guess**, not a reversal of the original value. The original subsystem cannot be
  recovered. For analysis this does not matter: CAPA ignores subsystem, and angr
  loads fine with CUI.

## Verification

| test | result |
|---|---|
| Native theZoo Bladabindi, machine/subsystem zeroed then repaired | CAPA rule set **identical** to original (7/7). |
| Disarmed BODMAS sample, `Machine` restored only | CAPA **works** (rc=0). |
| Disarmed BODMAS sample, `Subsystem` restored only | CAPA **still fails** (rc=17). |
| Disarmed BODMAS sample, both restored | CAPA **works** with rule set **identical** to the already-stored CAPA output for that sample. |
| Native .NET sample (Bladabindi) with `Machine=0` | CAPA **works** (rc=0) via dnfile; this is a .NET extractor path and does not imply native PE is tolerant. |

**Conclusion:** Repair reverses the disarm sufficiently for CAPA and angr. The
subsystem guess is harmless. The stored CAPA JSON was produced from repaired
copies in the pipeline (or equivalently from header-restored files).
