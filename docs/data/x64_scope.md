# x64 scope (2026-10-22)

The corpus for Stage 1 is **x86 only**. All 855 machine-x64 rows in
`data/versions/v2/manifest.csv` are excluded.

## Why they are excluded

All 855 x64 samples are marked `is_packed=1` and raw files exist at the recorded
paths (`855/855`). They fail the frozen v2 packed filter:

| reason | count | notes |
|---|---|---|
| UPX (sections `UPX0`/`UPX1`/`UPX2` + string `UPX!`) | 845 | Genuinely packed; UPX-unpackable but the pipeline has no unpacking step. |
| `high_entropy_low_imports` only | 9 | High entropy text section, few imports. |
| MPRESS signature | 1 | `string:MPRESS`; entropy 5.95, imports 447, so excluded by signature rather than the entropy rule. |

Median text entropy 7.915 (x64) vs x86 clean median lower; 854/855 satisfy
`text_entropy >= 7.8 and num_imports <= 20`. The exclusion is the frozen packed
rule applied to a subset that is overwhelmingly UPX-packed by construction, not a
bug in repair or detection.

## Not a repair issue

Disarming only zeroes `Machine` and `Subsystem`; x64 samples are all UPX-packed
regardless. Repairing their headers would not make them analysable by CAPA/angr
at function level without unpacking.

## Action

Record the project as **x86-only**. Unpacking UPX (and validating labels before/after)
is a plausible future extension, but it is out of scope and would require a new
pipeline stage with its own verification. No x64 samples are used in v2 splits
or v3 training.
