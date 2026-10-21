"""Stage-specific label contract constants.

The parser and mapping layer still understand all three CAPA capabilities so
the pilot evidence remains reproducible.  Stage 1 training and label tables use
only ``ACTIVE_LABELS``; keylogger is intentionally not a target.

Keylogger status (2026-10-22): **audit-only, permanently excluded.**  A
rule-composition audit found the label is defined by a handful of keyboard-state
APIs (``GetAsyncKeyState`` and friends) rather than by keylogging behaviour, and
that it is structurally blind to .NET samples.  No collection campaign can fix
it, so it is never trained, not even as zeros.  Evidence and the audit are
preserved.  See ``results/audit/keylogger_negative_result.md``.

Label renaming (2026-10-22): the same audit showed that ``anti_debug`` is
~99.4% timing/instruction patterns and ``injection`` is 100% one RWX-allocation
rule.  Neither measures the capability it is named after, so both are re-scoped
to the behaviour they actually measure.  The internal identifiers keep their
historical names (the label tables, splits, and reproductions of earlier phases
depend on them); ``LABEL_DISPLAY_NAMES`` and ``LABEL_DESCRIPTIONS`` carry the
honest names for every config and report.  See
``results/audit/label_rule_composition.md``.
"""

from __future__ import annotations

ALL_LABELS = ("anti_debug", "keylogger", "injection")
ACTIVE_LABELS = ("anti_debug", "injection")

# Honest names for reporting.  These are what configs and reports must use; the
# internal identifiers above are retained only for reproducibility.
LABEL_DISPLAY_NAMES: dict[str, str] = {
    "anti_debug": "anti_debug_timing",
    "injection": "rwx_alloc",
    "keylogger": "keylogger",
}

LABEL_DESCRIPTIONS: dict[str, str] = {
    "anti_debug": (
        "Timing/instruction anti-analysis pattern: rdtsc/icebp, or repeated "
        "QueryPerformanceCounter/GetTickCount. NOT debugger detection - the "
        "genuine debugger-detection rules fire on 3 functions corpus-wide."
    ),
    "injection": (
        "RWX allocation (VirtualAlloc/VirtualProtect with "
        "PAGE_EXECUTE_READWRITE). NOT process injection - the genuine "
        "injection rules fire on 9 functions corpus-wide."
    ),
    "keylogger": (
        "AUDIT-ONLY, never a target. Defined by keyboard-state API presence "
        "(GetAsyncKeyState etc.) and blind to .NET; not validated as a label."
    ),
}

# Set by the census in results/audit/rule_census.json.  Of 1,031 CAPA rules,
# only 12 emit any audited label, and exactly one passes the census gate below.
CENSUS_RULES_LOADED = 1031
CENSUS_RULES_FIRING = 12
CENSUS_RULES_PASSING = 1

LABEL_CONTRACT_VERSION = "stage1-v3"
LABEL_CONTRACT_NAME = "stage1-two-label-rescoped"

# Operational label-count gate.
MIN_POSITIVE_FUNCTIONS = 300

# Pre-registered diversity criteria.  These are diagnostics for claims, not
# thresholds that may be tuned after seeing model performance.
MIN_POSITIVE_BINARIES = 20
MIN_POSITIVE_CLUSTERS = 10
MIN_POSITIVE_FAMILIES = 3
MAX_SINGLE_BINARY_SHARE = 0.50
MAX_SINGLE_CLUSTER_SHARE = 0.50

# Held-out coverage required before claiming binary-level generalization.
MIN_HOLDOUT_POSITIVE_BINARIES = 10
MIN_HOLDOUT_POSITIVE_CLUSTERS = 5

# Per-rule support census gate (2026-10-22).  A rule must clear all four to be
# eligible as a training label.  Thresholds were fixed when only the rule
# composition of the audited labels was known, before the census table was
# read, and must not be tuned afterwards.
#
# MIN_CENSUS_FUNCTIONS is the binding constraint and is not arbitrary: below
# ~100 functions the effective sample size for cluster-bootstrap CIs is too
# small to separate signal from noise.
MIN_CENSUS_FUNCTIONS = 100
MIN_CENSUS_CLUSTERS = 10
MIN_CENSUS_FAMILIES = 3
MAX_CENSUS_TOP_CLUSTER_SHARE = 0.50

# Secondary, reportable-but-not-primary tier.  Admitted only when a rule clears
# the concentration requirement; never promoted after seeing model results.
SECONDARY_CENSUS_FUNCTIONS = 30

# Grouped evaluation protocol (pre-registered 2026-10-22, before any model run).
# The single frozen v2 test split was retired after the label audit because
# anti_debug_timing had only 4 test clusters (89.3% one cluster) and 7
# validation positives.  See docs/models/evaluation_protocol.md.
EVAL_PROTOCOL_VERSION = "grouped-kfold-v3"
N_FOLDS = 5
N_LOFO_REPEATS = 10
