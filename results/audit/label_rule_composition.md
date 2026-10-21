# Label rule composition audit

Date: 2026-10-22
Scope: `anti_debug`, `injection`, `keylogger` on the full clean set (v2 corpus,
2,731 samples / 2,712,053 functions / 301 clusters).

## Why this audit exists

The corpus-wide diversity gate passed for `injection`, and the external
collection probe lifted `anti_debug` from a 51.3% to a 43.4% top-cluster share.
Neither result validates that a label *measures the capability it is named
after*. A label can be diverse and still be defined by one API call. This audit
decomposes each label into the CAPA rules that produce it, and asks what each
rule actually requires.

Passing a cluster-diversity gate is a necessary condition for generalization
claims. It is not a validity check on the label. This audit is that check.

## Canonical counting unit

Throughout this document and every downstream report, the unit is:

> **functions with a positive label** — `count(label_x > 0)` over
> `data/labels/stage1_full_function_labels.parquet`.

This is the unit the model trains on, so prevalence, cluster share, and loss
weighting are only mutually consistent in this unit. Two other units were in
use previously and are **superseded**:

| unit | example value (`injection`) | source | why it disagreed |
|---|---|---|---|
| functions **(canonical)** | **1,344** | parquet, `meta.label_counts` | — |
| per-sample label units | 1,355 | `census.capa.label_counts` | sums each sample's `label_counts`; a function matching two rules in one label is counted twice |
| rule-hit units | 1,353 | rule-composition script | counts each matching rule separately |

Both non-canonical units over-count by exactly the double-rule functions. There
is no missing data; the 11-function difference is purely a unit artifact. The
canonical `injection` count is **1,344 functions / 799 binaries / 107 clusters**.

The same artifact explains the cluster discrepancy (107 vs 110): 107 counts
clusters containing a positive *function*; 110 counted clusters among *samples*
that emitted the label, including samples with no mapped function. Use 107.

## `anti_debug` — 534 positive functions, 5 distinct rules

| hits | % of hits | rule | namespace | what actually fires it |
|---|---|---|---|---|
| 379 | **71.0%** | `execute anti-debugging instructions` | `anti-analysis/anti-debugging/debugger-detection` | `count(mnemonic(rdtsc)) >= 2` in a function, **or** a single `icebp` |
| 108 | **20.2%** | `check for time delay via QueryPerformanceCounter` | same | `count(api(kernel32.QueryPerformanceCounter)) >= 2` in a function |
| 44 | 8.2% | `check for time delay via GetTickCount` | same | `count(api(kernel32.GetTickCount)) >= 2` + a block containing `sub` and `cmp` |
| 2 | 0.4% | `check for PEB BeingDebugged flag` | same | genuine debugger detection |
| 1 | 0.2% | `check for software breakpoints` | same | genuine debugger detection |

**FLAGGED.** Top-1 = 71.0% (> 70%). Top-2 = **91.2%**. All three dominant rules
are timing or instruction patterns, not debugger detection.

The namespace contains **22 rules**. The 19 debugger-detection rules that require
actual debugger state (`ProcessDebugPort`, `ProcessDebugFlags`, `NtGlobalFlag`,
hardware breakpoints, process debug object, kernel debugger via KUSER_SHARED_DATA,
trap flag, protected handle exception, thread hide, job object, …) fire on
**3 functions in total**.

So the label is approximately **99.4% timing/instruction pattern** and 0.6%
debugger detection. It is re-scoped in configs and reports as
**`anti_debug_timing`**.

## `injection` — 1,344 positive functions, 3 distinct rules

| hits | % of hits | rule | namespace | what actually fires it |
|---|---|---|---|---|
| 1,344 | **99.3%** | `allocate or change RWX memory` | `host-interaction/process/inject` | `VirtualAlloc`/`VirtualProtect` (via `match: allocate memory` or `change memory protection`) in the same basic block as the constant `0x40 = PAGE_EXECUTE_READWRITE` |
| 5 | 0.4% | `inject thread` | same | remote-thread creation family |
| 4 | 0.3% | `inject dll` | same | genuine DLL injection |

**FLAGGED, severely.** A single API call fires **100% of positive functions**
(every one of the 1,344 is rule-hit present; the rule itself accounts for 99.3%
of all rule hits). RWX allocation is used by unpackers, JIT engines, and
shellcode stagers; it is memory-permission hygiene, not injection.

The namespace contains **19 rules**. The genuinely injection-shaped rules
(`inject dll`, `inject pe`, `inject APC`, `inject shellcode using …`,
`hijack thread execution`, `process ghostly hollowing`, Doppelgänging, replacement)
fire on **9 functions in total**.

The label is re-scoped in configs and reports as **`rwx_alloc`**. It remains
useful as a *positive control* (a label known to be trivially recoverable from
API features), never as a capability claim.

## `keylogger` — audit-only, permanently out of Stage 1

534/1,344/1,268-style counting aside, keylogger was already excluded from
`ACTIVE_LABELS`. This audit confirms exclusion was correct, for reasons beyond
volume: see `keylogger_negative_result.md`.

| hits | % of hits | rule | what it requires |
|---|---|---|---|
| 675 | 53.2% | `log keystrokes via polling` | **one** call to `GetAsyncKeyState`, `GetKeyState`, `GetKeyboardState`, `VkKeyScan(Ex)` or `GetKeyNameText` |
| 680 | 53.6% | `log keystrokes` | OR of loose combos, including `MapVirtualKey` **alone** or `user32.AttachThreadInput` **alone** |
| 11 | 0.9% | `log keystrokes via application hook` | `SetWindowsHookEx` + `WH_KEYBOARD*` — the only high-precision rule |

(Totals exceed 100% because a function can match more than one rule: same
double-count artifact as above, which is precisely why the canonical unit is
functions-with-a-positive-label.)

## Census: only 12 of 1,031 rules ever fire

Full table: `results/audit/rule_census.json`. Rules emitting the three audited
labels, per rule: functions / clusters / families / top-cluster share.

| functions | binaries | clusters | families | top-cluster | rule |
|---|---|---|---|---|---|
| 1,349 | 804 | 108 | 12 | 32.9% | `allocate or change RWX memory` |
| 680 | 193 | 26 | 10 | 73.5% | `log keystrokes` |
| 675 | 107 | 23 | 12 | 81.5% | `log keystrokes via polling` |
| 379 | 282 | 4 | 2 | 72.3% | `execute anti-debugging instructions` |
| 108 | 54 | 4 | 5 | 92.6% | `check for time delay via QueryPerformanceCounter` |
| 44 | 35 | 11 | 5 | 45.5% | `check for time delay via GetTickCount` |
| 11 | 11 | 1 | 1 | 100.0% | `log keystrokes via application hook` |
| 5 | 5 | 2 | 2 | 80.0% | `inject thread` |
| 4 | 4 | 1 | 1 | 100.0% | `inject dll` |
| 3 | 3 | 2 | 2 | 66.7% | `register raw input devices` |
| 2 | 2 | 2 | 2 | 50.0% | `check for PEB BeingDebugged flag` |
| 1 | 1 | 1 | 1 | 100.0% | `check for software breakpoints` |

Applying the census gate (`>= 100 functions`, `>= 10 clusters`, `>= 3 families`,
top-cluster share `<= 50%`) leaves exactly **one** rule: `allocate or change RWX
memory`.

## Consequence

There is no rule in this corpus that is simultaneously well-supported, diverse
across clusters and families, and semantically a capability. `rwx_alloc` is
well-supported but is one API call; `anti_debug_timing` is two timing patterns
concentrated in 4 clusters and 2 families; every genuine capability rule fires
on single digits of functions.

## Framing

Two framings were on the table. The census decides it.

- **(a) Capability classification on rules that pass the census.** Not available.
  Exactly one rule passes, and it is `rwx_alloc` — a label whose validity is
  circular by construction (the rule *is* one API call, so a model that recovers
  it has learned the rule, not RWX-allocation behaviour as a concept). No clean
  rule exists to build a capability claim on.

- **(b) Methodology study of CAPA label leakage and structural signal.**
  **Recommended.** Every artefact already produced becomes a result:
  - the census (1,031 rules loaded, 12 fire, 1 capability-grade) is the headline;
  - the rule-composition audits are the leakage measurement;
  - full-API vs no-API quantifies how much apparent CFG-GNN skill is API-name
    memorization;
  - grouped k-fold plus LOFO gives an honest protocol for a label set that would
    otherwise look deceptively strong (see
    `docs/models/evaluation_protocol.md`).

`rwx_alloc` stays in the study as a **positive control**: a label known to be
trivially recoverable from API features, used to calibrate the leakage gap. It
is reported as `rwx_alloc`, never as injection capability. `anti_debug_timing`
is reported as a secondary, conditional label — it fails clusters and families,
so its held-out numbers are descriptive only.

Framing (b) is also the only framing under which the protocol change is
*necessary* rather than convenient: retiring a frozen test split is justified by
"the labels were found invalid", not by "the split gave poor numbers".

