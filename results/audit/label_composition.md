# Label composition and concentration — three targets

Date: 2026-10-22
Source: `data/labels/stage1_full_three_targets.parquet`, derived from the
existing CAPA 9.1.0 JSON and `results/full/mapping_three_target.jsonl`.
Unit: **functions with a positive label**.

This audit records what the three target labels actually measure. It does not
change the targets. It is a caveat that travels with every held-out result.

## 1. Counts

| label | positive functions | positive samples | clusters | families | top-cluster share |
|---|---:|---:|---:|---:|---:|
| `anti_debug` | 448 | 373 | 21 | 10 | 61.2 % |
| `keylogger` | 1,255 | 242 | 41 | 12 | 75.7 % |
| `injection` | 1,349 | 804 | 108 | 12 | 32.9 % |

The v2 clean set has 2,733 samples and 303 clusters; 2,729 graphs were
extracted. `keylogger` and `anti_debug` exceed the pre-registered 50 % top-cluster
concentration limit. `injection` passes.

Function-scope CAPA matches are localised through CAPA's reported evidence
locations (for anti-debug, the `rdtsc`/`icebp` instructions) rather than the
CAPA function start alone. This removed 86 inherited anti-debug positives and
is the reason anti-debug is 448 here rather than 534. It does not fix the
cluster concentration.

## 2. What each label is made of

### `keylogger`

Three rules under `collection/keylog` produce almost all positives:

| rule | what it requires |
|---|---|
| `log keystrokes via polling` | one call to `GetAsyncKeyState`, `GetKeyState`, `GetKeyboardState`, `VkKeyScan`, `VkKeyScanEx`, or `GetKeyNameText` |
| `log keystrokes` | an OR of loose combinations, including `MapVirtualKey` alone or `AttachThreadInput` alone |
| `log keystrokes via application hook` | `SetWindowsHookEx` + `WH_KEYBOARD` / `WH_KEYBOARD_LL` |

The first two rules dominate. `GetAsyncKeyState` is also used for hotkeys,
input polling, and sandbox checks; `MapVirtualKey` is used for keyboard-layout
translation; `AttachThreadInput` is used for foreground-window manipulation.
The label therefore measures keyboard-state API presence more than keylogging.

The label is structurally blind to .NET samples: CAPA does not turn .NET
P/Invoke into the native imports these rules require. AgentTesla is the clearest
example in the corpus. The 75.7 % top-cluster share is a second limitation.

**Decision:** keylogger remains a target because it is part of the project
scope. Its results are reported with the concentration and .NET caveats, not as
keylogging detection.

### `anti_debug`

The label is dominated by timing and instruction patterns:
`rdtsc`/`icebp`, and repeated `QueryPerformanceCounter`/`GetTickCount`. Genuine
debugger-detection rules fire on very few functions. The 61.2 % top-cluster
share means held-out anti-debug performance is partly a single-cluster result.
The evidence-localised label is more precise: in the held-out sample that
previously contributed 94 inherited positives, only the 9 functions containing
the reported evidence remain positive.

### `injection`

The label is dominated by RWX allocation
(`VirtualAlloc`/`VirtualProtect` with `PAGE_EXECUTE_READWRITE`). Genuine
process-injection rules (remote thread, `WriteProcessMemory`, `CreateRemoteThread`
sequences) fire on single-digit function counts. The label is therefore closer
to "RWX allocation" than to end-to-end injection. It is the least concentrated
of the three (32.9 %).

## 3. Consequences for evaluation

1. A high held-out score means the model agrees with the CAPA rule, not that it
   detects the named behaviour.
2. Class 0 means "no target rule matched", not "benign". The corpus is
   malware-only.
3. Keylogger and anti-debug test scores should be reported per cluster; a
   single-cluster test cannot support a generalization claim.
4. The Stage 2 block labels inherit the same weakness: a CAPA block match is the
   block where the rule fired, and an API-call block is where the import was
   called. They are weak localisation labels, not hand annotations.

## Stage 1 split support

The cluster-stratified three-target split holds:

| split | anti_debug | keylogger | injection | samples |
|---|---:|---:|---:|---:|
| train | 394 | 950 | 944 | 1,913 |
| validation | 27 | 152 | 203 | 410 |
| test | 27 | 153 | 202 | 410 |

The supports are function positives on the 2,729 extracted graphs. The test
anti-debug support (27) is the full held-out anti-debug resolution of this
split: the label is concentrated in a few clusters, so a held-out split cannot
produce a larger independent test set. Report this with any anti-debug score.

The Stage 1 held-out result is in `results/train/stage1/report.md`. It is a
function-level result on these supports, not a binary-family claim.

## Stage 2 block-label composition

Stage 2 labels are block-level seeds inside positive functions: CAPA evidence
locations plus blocks containing an import-resolved API reference. Blocks in
the same positive function without either seed are negative blocks; blocks in
weak-negative and unlabeled functions are excluded.

| target | positive blocks | API-seed blocks | positive functions | test positive blocks | test positive functions |
|---|---:|---:|---:|---:|---:|
| `anti_debug` | 1,432 | 800 | 448 | 136 | 27 |
| `keylogger` | 9,504 | 6,889 | 1,255 | 1,344 | 153 |
| `injection` | 15,263 | 14,798 | 1,344 | 2,094 | 202 |

The API-seed share is 55.9 % for anti-debug, 72.5 % for keylogger, and 96.9 %
for injection. The block metrics therefore measure recovery of those seeds, not
every malicious block. The anti-debug Stage 2 threshold selected on 27
validation functions is very conservative (0.94); the block AP is 0.336, so the
ranking is more informative than the thresholded recall. These caveats are
carried in `results/train/stage2/report.md`.
