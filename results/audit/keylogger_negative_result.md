# Keylogger label: documented negative result

Date: 2026-10-22
Status: **keylogger is audit-only and permanently outside the Stage 1 target and
loss.** No keylogger collection campaign will be run.
Decision source: user decision, this date.

## Summary

Keylogger was already excluded from `ACTIVE_LABELS`, but it was treated as a
*deferred* decision: the plan was that enough well-diverse samples might make it
trainable later. This audit shows that no quantity of additional samples can fix
it, because the label does not measure keylogging. It measures whether a function
calls one of a small set of keyboard-state APIs.

## Rule composition

1,031 rules were loaded from the pinned rules tree
(`/home/lali/tools/capa-rules`). Three rules in `collection/keylog` produce
essentially the entire label:

| hits | % of hits | rule | what it requires |
|---|---|---|---|
| 675 | 53.2% | `log keystrokes via polling` | **one** call to `GetAsyncKeyState`, `GetKeyState`, `GetKeyboardState`, `VkKeyScan`, `VkKeyScanEx`, or `GetKeyNameText` |
| 680 | 53.6% | `log keystrokes` | OR of loose combinations, including `user32.MapVirtualKey` **alone**, or `user32.AttachThreadInput` **alone** |
| 11 | 0.9% | `log keystrokes via application hook` | `SetWindowsHookEx` + `WH_KEYBOARD`/`WH_KEYBOARD_LL` — the only high-precision rule in the set |

(Hits exceed 100% combined because a function may match more than one rule. All
counts in this document use the canonical unit: functions with a positive label.)

`GetAsyncKeyState` is used for global hotkeys, input polling, and sandbox-evasion
checks. `MapVirtualKey` is used for any keyboard-layout translation, and
`AttachThreadInput` for foreground-window manipulation. None of these is evidence
of keylogging.

Rule-level provenance of every keylogger positive function in the external probe
was identical: only these three rules ever fired. There is no fourth rule to
appeal to.

## The .NET blind spot

The rules match native (`user32`) API imports resolved by CAPA's static analysis.
They do not resolve .NET P/Invoke declarations equivalently. **AgentTesla**, one
of the best-known keyloggers in the corpus, scores **zero** keylogger functions.

This matters for collection planning: 208 of 460 (45%) MalwareBazaar candidates
were .NET (AsyncRAT, QuasarRAT, NanoCore, AgentTesla). A keylogger collection
campaign from that source would spend most of its quota on samples the label is
structurally unable to see.

## The AgentTesla / DarkComet contrast

**Corrected framing (important).** An earlier reading suggested AgentTesla
scoring zero reflected a *family-specific API signature*, i.e. that the rules
were keyed to DarkComet's implementation. That is **not** the conclusion. The
correct explanation is **two compounding causes**:

1. **.NET blindness** — CAPA static analysis does not turn .NET P/Invoke into the
   native imports these rules require.
2. **Rules that are weak by design** — 96% of hits come from two rules where a
   single API call is sufficient.

The 59.1% projected top-cluster concentration was a **symptom** of a label
defined by `GetAsyncKeyState`, not the root cause. The rule audit above is the
actual evidence.

Observed yield on the external probe (215 samples with CAPA output):

| family | samples | keylogger fns | fns/sample |
|---|---|---|---|
| DarkComet (RAT) | 22 | 244 | 11.09 |
| HawkEye (keylogger) | 7 | 50 | 7.14 |
| Pony | 29 | 22 | 0.76 |
| TrickBot | 18 | 12 | 0.67 |
| AZORult | 25 | 8 | 0.32 |
| Formbook | 3 | 1 | 0.33 |
| Dridex | 30 | 2 | 0.07 |
| **AgentTesla (keylogger)** | **5** | **0** | **0.00** |

## Why dilution cannot fix it

The dilution arithmetic was tractable on paper — `1,268 + 339 = 1,607` functions
with a `59.1%` top-cluster share, needing roughly `+293` positives to reach 50%.
The obstacle is not the arithmetic but what the added samples would contribute:

- **New positives are themselves concentrated.** Of the 339 positives from the
  external probe, 160 (47%) landed in one cluster. Bulk collection from the
  families that actually score would reproduce the 74.9% problem under a
  different cluster ID.
- **Families that score are not keyloggers.** The high-yield families are
  DarkComet and HawkEye. Adding them dilutes the cluster share while making the
  label *less* like keylogging.
- **The frozen test set cannot be rebuilt by externals**, which are train/val
  only by decision. Test-side concentration would remain regardless.

Reaching the gate this way would be gaming cluster assignment, not improving
label validity — the exact failure mode the project rules forbid.

## Decision

1. Keylogger is **audit-only**. It is not an `ACTIVE_LABEL`, does not appear in
   targets or loss, and is never trained as zeros.
2. **No keylogger collection campaign.** Quota is not spent on a label that
   cannot be validated.
3. CAPA keylogger evidence (`keylogger_evidence_functions = 1255`) and its audit
   reports are preserved for reproducibility.
4. Keylogger rules must not be added merely to inflate positives.

## If keylogger is wanted later

Use a **small hand-verified set (~30 functions) as a test-only case study**,
never as a training label. Hand verification establishes that each function
genuinely captures keystrokes; the case study then reports whether any model can
find them, with no pretence that the CAPA namespace supports training at scale.

Any future attempt at a training-grade keylogger label would first need a
different measurement instrument — for example requiring a hook
(`SetWindowsHookEx` + `WH_KEYBOARD`) rather than polling. On the current corpus
that reduces genuine positives to single digits, so it is not viable now.
