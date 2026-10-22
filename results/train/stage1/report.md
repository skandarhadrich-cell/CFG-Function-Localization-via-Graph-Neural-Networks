# Stage 1 — three-target function localisation

- Corpus: `results/corpus_v2_three_targets`
- Feature width: **187**
- Labels: **anti_debug, keylogger, injection**
- Split: **three-target-v3** (train=1,909 · val=410 · test=409 graphs)
- Best epoch: **2** (selected on validation macro F1 with per-class thresholds)
- Test: evaluated **once** with the validation-selected thresholds

A function with no target match is the background class (not selected). It is
not a benign sample; the corpus is malware-only. Class 0 means “not selected”.

## Test

- Eligible functions: **91,957**
- Functions with at least one target: **377**

| label | support | threshold | precision | recall | F1 | AP |
|---|---:|---:|---:|---:|---:|---:|
| `anti_debug` | 27 | 0.95 | 0.7895 | 0.5556 | **0.6522** | 0.4836 |
| `keylogger` | 153 | 0.94 | 0.3292 | 0.3464 | **0.3376** | 0.2477 |
| `injection` | 202 | 0.95 | 0.3761 | 0.6535 | **0.4774** | 0.3327 |

- Macro F1 (targets with support): **0.4890**
- Any-target selection: P **0.4355**, R **0.5729**, F1 **0.4948**
- Background: P **0.9982**, R **0.9969**, F1 **0.9976**

## Validation

- Eligible functions: **92,054**
- Functions with at least one target: **379**

| label | support | threshold | precision | recall | F1 | AP |
|---|---:|---:|---:|---:|---:|---:|
| `anti_debug` | 27 | 0.95 | 0.6000 | 0.4444 | **0.5106** | 0.2750 |
| `keylogger` | 152 | 0.94 | 0.3284 | 0.1447 | **0.2009** | 0.0717 |
| `injection` | 203 | 0.95 | 0.4082 | 0.8325 | **0.5478** | 0.4655 |

- Macro F1: **0.4198**; any-target F1 **0.4856**; background F1 **0.9976**

## Reading the result

The test split is cluster-grouped and was not used for model selection. The
per-class thresholds were chosen on validation only. The test result is higher
than validation for anti-debug and keylogger, which means the validation split
is not a worse-case estimate; it does not mean the model generalises across all
malware families.

The labels are CAPA rule matches, not ground truth. The audit in
`results/audit/label_composition.md` records the concentration: keylogger is
75.7 % one cluster, anti-debug is 61.2 % one cluster, and injection is 32.9 %.
The test supports are 27 anti-debug, 153 keylogger, and 202 injection functions.
Those supports are the resolution limit of this split, not a statement that the
targets are equally common in the corpus.

The feature set now resolves both direct import-thunk calls and
`call/jmp dword ptr [IAT]` reference sites. The second route raised resolved API
references from 24,760 to 450,103 and is why keylogger moved from near-random
(AP 0.05) to AP 0.25 on test. Anti-debug uses explicit `rdtsc`/`icebp`/`pushfd`
opcodes; injection remains dominated by RWX-allocation API patterns.
