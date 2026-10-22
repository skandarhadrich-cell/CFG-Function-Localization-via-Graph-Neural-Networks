"""Three-target function-localisation label contract.

Reset (2026-10-22): the project targets the three CAPA behaviour families in the
original plan.  Every module that builds, merges, or reports labels uses these
constants.

    anti_debug  anti-analysis/anti-debugging
    keylogger   collection/keylog
    injection   host-interaction/process/inject + load-code/pe/inject-

The labels are CAPA rule matches.  They are observational labels, not
ground-truth annotations: a function that does not match a target rule is a
weak negative (``weak_negative``), never a benign sample.  Samples whose CAPA
output matched no rule at all are unlabeled and excluded from the loss.

Scope: x86 PE only.  The 855 machine-x64 rows in the v2 manifest are excluded
by the packed filter; see ``docs/data/x64_scope.md``.
"""

from __future__ import annotations

ALL_LABELS = ("anti_debug", "keylogger", "injection")
ACTIVE_LABELS = ALL_LABELS
N_OUTPUTS = len(ACTIVE_LABELS)

# Display names are the target names.  The audit that found label leakage is
# kept in ``results/audit`` as a caveat on how strongly each name may be read;
# it does not rename the targets.
LABEL_DISPLAY_NAMES: dict[str, str] = {
    "anti_debug": "anti_debug",
    "keylogger": "keylogger",
    "injection": "injection",
}

LABEL_DESCRIPTIONS: dict[str, str] = {
    "anti_debug": "CAPA anti-analysis/anti-debugging matches.",
    "keylogger": "CAPA collection/keylog matches.",
    "injection": "CAPA process-injection and PE-injection matches.",
}

# A clean sample whose CAPA output matched no rule at all carries no evidence
# either way, so it is excluded from the loss.  It is not a negative.
ZERO_RULE_POLICY = "exclude_from_loss_not_negative"

LABEL_CONTRACT_VERSION = "stage1-three-target-v1"
LABEL_CONTRACT_NAME = "three-target-function-localization"

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

# Split protocol: the three-target cluster-stratified split.
SPLIT_PROTOCOL = "v2-main-split"
