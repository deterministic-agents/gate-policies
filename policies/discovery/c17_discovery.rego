# GATE C17 - Agent Discovery Classification Policy
# File: policies/discovery/c17_discovery.rego
# Package: gate.discovery
#
# Evaluates a discovered candidate workload (raised by the C17 detection
# mechanisms - network observer, asset inventory integrator, identity
# classifier) and recommends enrol, terminate, or exception. Consumed by
# the C04 Lifecycle service to route candidates.
#
# Inputs expected on `input`:
#   workload_identity         (string)
#   detection_boundary        (string)
#   classification_confidence (number, 0-1)
#   c04_inventory_present     (boolean)
#   asset_tags_present        (boolean)
#   tenant_id                 (string)
#
# Outputs:
#   recommended_action: "enrol" | "terminate" | "exception"
#   reason_codes:       set of strings
#
# Per the v1.3 constraint, this file is independent of
# tool_gateway_baseline.rego and invariants_baseline.rego. Do not add
# rules into either of those.

package gate.discovery

import rego.v1

# Default is the most cautious action, so a missing input never silently
# enrols a candidate.
default recommended_action := "exception"

# Already in the C04 inventory: no remediation needed. The caller logs and
# moves on.
recommended_action := "enrol" if {
    input.c04_inventory_present
}

# High-confidence candidate with owner tags: route to C04 Commission.
recommended_action := "enrol" if {
    not input.c04_inventory_present
    input.classification_confidence >= 0.7
    input.asset_tags_present
}

# High-confidence candidate without owner tags: terminate immediately.
# We cannot route a Commission ticket without an owner; the v1.3 untagged
# asset policy is strict by default.
recommended_action := "terminate" if {
    not input.c04_inventory_present
    input.classification_confidence >= 0.7
    not input.asset_tags_present
}

# Low-confidence candidate: log as an exception with a TTL, do not block
# yet. Re-evaluated on the next detection window.
recommended_action := "exception" if {
    not input.c04_inventory_present
    input.classification_confidence < 0.7
}

# Reason codes - emitted alongside the recommended action for audit.
reason_codes contains "KNOWN_ENROLLED" if {
    input.c04_inventory_present
}

reason_codes contains "HIGH_CONFIDENCE_UNTAGGED" if {
    not input.c04_inventory_present
    input.classification_confidence >= 0.7
    not input.asset_tags_present
}

reason_codes contains "HIGH_CONFIDENCE_TAGGED" if {
    not input.c04_inventory_present
    input.classification_confidence >= 0.7
    input.asset_tags_present
}

reason_codes contains "LOW_CONFIDENCE" if {
    input.classification_confidence < 0.7
}
