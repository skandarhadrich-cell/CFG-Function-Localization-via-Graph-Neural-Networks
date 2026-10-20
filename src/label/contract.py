"""Stage-specific label contract constants.

The parser and mapping layer still understand all three CAPA capabilities so
the pilot evidence remains reproducible.  Stage 1 training and label tables use
only ``ACTIVE_LABELS``; keylogger is intentionally not a target.
"""

from __future__ import annotations

ALL_LABELS = ("anti_debug", "keylogger", "injection")
ACTIVE_LABELS = ("anti_debug", "injection")

LABEL_CONTRACT_VERSION = "stage1-v2"
LABEL_CONTRACT_NAME = "stage1-two-label"

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
