# Pilot label-contract findings

Date: 2026-10-20

**Verdict: STOP / REVISE.** The three-label pilot does not pass the label-contract gate.
`anti_debug` and `injection` are viable; `keylogger` projects below the ~300-positive
function threshold.

## CAPA census (200/200 pilot samples)

| Label | Pilot positive functions | Projected full clean set | Gate >=300 |
|---|---:|---:|---|
| `anti_debug` | 121 | 473.0 | PASS |
| `keylogger` | 45 | 241.6 | FAIL |
| `injection` | 71 | 1126.7 | PASS |

- CAPA-observed functions: 28,992
- Positive functions: 236
- Weak-negative functions: 28,756
- Function-scope target matches: 169
- Basic-block target matches: 77
- Unresolved CAPA-layout block matches: 0
- All 200 selected samples now have valid CAPA JSON. Six initial 240 s timeouts
  were rerun with 900 s; one keylogger sample initially failed because two
  concurrent runs shared a temporary output name, then succeeded in isolation.

Projection uses the full clean-set bucket counts and the selected pilot
denominator per bucket. `source_bucket` is stratification metadata, not ground
truth.

## Why keylogger fails: packed samples dominate its pilot bucket

`results/pilot/packing_audit.json` flags 27 pilot samples as suspected packed:
26 of 32 keylogger samples and 1 antidebug sample. The Phase 0 `is_packed`
column is **0 for all 27**. The existing filter only flags high entropy when
`num_imports == 0`; these packed files have 3-16 imports and were retained.
CAPA independently reports ASPack or a generic packer on 26 of them.

Keylogger bucket split:

| Group | Samples | CAPA-observed functions | anti_debug | keylogger | injection |
|---|---:|---:|---:|---:|---:|
| Suspected packed | 26 | 73 | 0 | 0 | 0 |
| Non-packed | 6 | 11,366 | 100 | 33 | 4 |

All 33 keylogger positives in the keylogger bucket come from three non-packed
samples: two lokibot and one agenttesla. The other non-packed samples
(two bladabindi, one agenttesla) supply no keylogger positives. This is a fragile
label: two-thirds of the bucket contributes almost no CAPA signal.

Applying a stricter high-entropy + low-import filter (`text_entropy >= 7.8` and
`num_imports <= 20`) removes 81 clean samples (2.9%), including all 26 packed
keylogger samples. Even then, projected keylogger positives are only about
**263** (about 197 from antidebug + 66 from keylogger), still below 300.
A packed-data fix is necessary for data quality, but it does not by itself
rescue the keylogger label.

## CAPA-to-angr mapping subset

A five-sample stratified mapping check was run with the per-sample subprocess
timeout. All five completed:

| Sample | angr functions | CAPA observed | Observed coverage | Target coverage | Keylogger positives | Collisions |
|---|---:|---:|---:|---:|---:|---:|
| `03bd...` | 116 | 77 | 98.70% | 100% | 0 | 0 |
| `0021...` | 1,003 | 359 | 100% | 100% | 0 | 11 |
| `c46c...` | 2,581 | 2,074 | 100% | 100% | 19 | 22 |
| `9039...` | 10,559 | 2,952 | 99.66% | 100% | 6 | 4 |
| `814e...` | 27,213 | 183 | 100% | 100% | 0 | 4 |

The subset maps 5,634 of 5,645 CAPA-observed functions (99.81%) and all 156
target rule matches to an angr function or block; unresolved target rate is 0%.
The mapping contract is therefore viable. The `814e...` sample (94 `anti_debug`
positives) is a pathological bladabindi CFG: 597 s and about 930 MB max RSS.
A 300 s per-sample cap would reject it; the batch runner therefore exposes
`--sample-timeout` and records timeouts for retry rather than silently dropping
a sample.

Measured angr times for the completed subset ranged from 8 s to 597 s per
sample, with max RSS up to about 930 MB. These are pilot measurements, not a
full-set throughput estimate.

## Recommendation

1. **Do not run the full 2,814-sample CAPA/angr job with three labels as-is.**
2. For Stage 1, either:
   - drop `keylogger` and proceed with the two viable labels
     (`anti_debug`, `injection`); or
   - revise the keylogger label contract (for example, add explicit
     keyboard/credential collection rules) and rerun the pilot.
   The first option is the lower-risk path and keeps the current results honest.
3. Fix the Phase 0 packed filter before regenerating any manifest or split.
   Regenerating splits is a separate revision; do not silently mutate the
   frozen Phase 0 artifacts.
4. Keep the three-sigmoid schema in code for a future keylogger revision; do not
   force a three-label result from this pilot.
