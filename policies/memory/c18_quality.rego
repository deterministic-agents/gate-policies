# GATE C18 - Data Quality Gate Policy
# File: policies/memory/c18_quality.rego
# Package: gate.memory.quality
#
# Evaluates a retrieval request inside the Memory Gateway against the
# signed quality bundle and produces an outcome: pass | flag | downgrade
# | deny.
#
# Inputs:
#   input.item.content_class               (string)
#   input.item.freshness_age_seconds       (number)
#   input.item.confidence_score            (number, 0-1)
#   input.item.provenance_uri              (string)
#   input.item.provenance_hash_verified    (boolean)
#   input.quality_bundle.ttl_by_class      (object: class -> seconds)
#   input.quality_bundle.min_confidence_by_class (object: class -> 0-1)
#   input.quality_bundle.provenance_required_by_class (object: class -> bool)
#   input.quality_bundle.action_matrix     (object: tier -> class -> dimension -> action)
#   input.autonomy_tier                    (sandbox | bounded | high_privilege)
#
# Outputs:
#   outcome      ("pass" | "flag" | "downgrade" | "deny")
#   flags_set    (set of strings)
#   reason_codes (set of strings)
#   freshness_pass, confidence_pass, provenance_pass (intermediate booleans)
#
# Action matrix drives promotion to flag/downgrade/deny. This policy file
# does not hardcode actions.
#
# Per the v1.3 constraint, this file does not modify
# tool_gateway_baseline.rego or invariants_baseline.rego.

package gate.memory.quality

import rego.v1

# ---------------------------------------------------------------
# Per-dimension checks (pure functions of input)
# ---------------------------------------------------------------

freshness_pass if {
    ttl := input.quality_bundle.ttl_by_class[input.item.content_class]
    input.item.freshness_age_seconds <= ttl
}

# If no TTL is configured for this content class, freshness defaults to pass.
freshness_pass if {
    not input.quality_bundle.ttl_by_class[input.item.content_class]
}

confidence_pass if {
    minimum := input.quality_bundle.min_confidence_by_class[input.item.content_class]
    input.item.confidence_score >= minimum
}

confidence_pass if {
    not input.quality_bundle.min_confidence_by_class[input.item.content_class]
}

provenance_pass if {
    not input.quality_bundle.provenance_required_by_class[input.item.content_class]
}

provenance_pass if {
    input.quality_bundle.provenance_required_by_class[input.item.content_class]
    input.item.provenance_uri != ""
    input.item.provenance_hash_verified
}

# ---------------------------------------------------------------
# Action matrix lookup
# ---------------------------------------------------------------

action_for(dimension) := act if {
    tier_matrix := input.quality_bundle.action_matrix[input.autonomy_tier]
    class_matrix := tier_matrix[input.item.content_class]
    act := class_matrix[dimension]
} else := "flag"

# ---------------------------------------------------------------
# Outcome resolution (most severe failing dimension wins)
# ---------------------------------------------------------------

severity := {"pass": 0, "flag": 1, "downgrade": 2, "deny": 3}

# Default is pass; promotion is driven by per-dimension failures + the
# action matrix.
default outcome := "pass"

# Promote to the most severe action across failing dimensions.
outcome := worst if {
    failures := failing_actions
    count(failures) > 0
    worst_level := max([severity[a] | a := failures[_]])
    worst := level_to_action[worst_level]
}

failing_actions contains a if {
    not freshness_pass
    a := action_for("freshness")
}

failing_actions contains a if {
    not confidence_pass
    a := action_for("confidence")
}

failing_actions contains a if {
    not provenance_pass
    a := action_for("provenance")
}

level_to_action := {0: "pass", 1: "flag", 2: "downgrade", 3: "deny"}

# ---------------------------------------------------------------
# Flags returned to the caller alongside the outcome
# ---------------------------------------------------------------

flags_set contains "stale" if {
    not freshness_pass
}

flags_set contains "low_confidence" if {
    not confidence_pass
}

flags_set contains "provenance_missing" if {
    input.quality_bundle.provenance_required_by_class[input.item.content_class]
    input.item.provenance_uri == ""
}

flags_set contains "provenance_unverified" if {
    input.quality_bundle.provenance_required_by_class[input.item.content_class]
    input.item.provenance_uri != ""
    not input.item.provenance_hash_verified
}

# ---------------------------------------------------------------
# Reason codes for audit
# ---------------------------------------------------------------

reason_codes contains "FRESHNESS_TTL_EXCEEDED" if {
    not freshness_pass
}

reason_codes contains "CONFIDENCE_BELOW_MINIMUM" if {
    not confidence_pass
}

reason_codes contains "PROVENANCE_FAILED" if {
    not provenance_pass
}
