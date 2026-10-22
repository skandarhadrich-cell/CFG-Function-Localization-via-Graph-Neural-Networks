# Stage 1 label report — three targets

- Scope: **full v2 clean set**
- Samples in label table: **2,727**
- Graphs: **2,729**
- Active labels: **anti_debug, keylogger, injection**
- Label contract: `stage1-three-target-v1`

## Counts

| label | positive functions | positive samples | clusters | families | top-cluster share | top-binary share |
|---|---:|---:|---:|---:|---:|---:|
| `anti_debug` | 448 | 373 | 21 | 10 | 61.2 % | 2.0 % |
| `keylogger` | 1,255 | 242 | 41 | 12 | 75.7 % | 1.5 % |
| `injection` | 1,349 | 804 | 108 | 12 | 32.9 % | 1.6 % |

`status_counts`: positive **3,044**, weak_negative **377,257**, unlabeled
**2,331,752**. The unit is functions with a positive label; a function can carry
more than one target.

## Mapping

- CAPA-observed functions: **409,510**
- Mapped CAPA functions: **407,772** (99.58 %)
- Target matches: **3,411**
- Mapped target matches: **3,395** (99.53 %)
- Unresolved target matches: **22**
- Many-to-one collisions: **6,642**
- Block-parent mismatches: **0**

Function-scope matches are localised through CAPA's nested evidence locations
(e.g. the `rdtsc` instructions for `execute anti-debugging instructions`). The
label goes to the angr function containing the evidence; the CAPA function start
is kept as a weak negative when it is a different angr function. This reduced
`anti_debug` from 534 (start-only mapping) to 448.

## Gate summary

- Operational count gate (`>=300` positive functions): all three **PASS**.
- Diversity diagnostics (`>=20` binaries, `>=10` clusters, `>=3` families,
  top binary/cluster `<=50 %`): `injection` **PASS**; `keylogger` and
  `anti_debug` **FAIL** on top-cluster share.
- Labels that fail diversity remain trainable, but cannot support a broad
  binary-level generalisation claim. Report per-cluster support with every
  held-out score.

## Concentration caveat

The labels are CAPA rule matches, not ground truth. `keylogger` is dominated by
keyboard-state API presence and one cluster. `anti_debug` is dominated by timing
and instruction patterns and one cluster. `injection` is dominated by RWX
allocation rather than end-to-end injection. The detailed audit is in
`results/audit/label_composition.md`.
