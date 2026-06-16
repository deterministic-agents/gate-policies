# GATE C19 - Drift Response Policy
# File: policies/assurance/c19_drift_response.rego
# Package: gate.assurance.drift
#
# Routes a drift_decision to a response action based on tier and dimension.
# Response matrix is configuration-driven; this policy does not hardcode
# tier-specific responses.
#
# Inputs:
#   input.drift_decision.dimension  (string)
#   input.drift_decision.decision   ("no_drift" | "drift_detected")
#   input.drift_decision.p_value    (number)
#   input.autonomy_tier             (string)
#   input.response_matrix           (object: tier -> dimension -> action)
#
# Outputs:
#   response_action ("log_only" | "flag" | "review_ticket" |
#                    "tier_reduction" | "emergency_stop")
#   reason_codes    (set of strings)
#
# Per the v1.3 constraint, this file does not modify
# tool_gateway_baseline.rego or invariants_baseline.rego.
#
# Direct emission path: C19 emits response_action events directly. ORM
# consumes them as a downstream signal but is not on the critical path.
# This matches the gate-conformance c19-rebaselining and untagged-asset
# runbooks.

package gate.assurance.drift

import rego.v1

# When there is no drift, every tier returns log_only. This holds even if
# the response matrix has not been configured for the agent's tier.
default response_action := "log_only"

response_action := "log_only" if {
    input.drift_decision.decision == "no_drift"
}

# When drift is detected, the configured action from the response matrix
# is returned. If the matrix does not specify one, default to flag (the
# least-severe non-trivial action) and emit a reason code so operators
# notice the missing configuration.
response_action := act if {
    input.drift_decision.decision == "drift_detected"
    tier_matrix := input.response_matrix[input.autonomy_tier]
    act := tier_matrix[input.drift_decision.dimension]
}

response_action := "flag" if {
    input.drift_decision.decision == "drift_detected"
    tier_matrix := input.response_matrix[input.autonomy_tier]
    not tier_matrix[input.drift_decision.dimension]
}

# Reason codes
reason_codes contains "NO_DRIFT" if {
    input.drift_decision.decision == "no_drift"
}

reason_codes contains "DRIFT_DETECTED" if {
    input.drift_decision.decision == "drift_detected"
}

reason_codes contains "MATRIX_DEFAULT_FALLBACK" if {
    input.drift_decision.decision == "drift_detected"
    tier_matrix := input.response_matrix[input.autonomy_tier]
    not tier_matrix[input.drift_decision.dimension]
}
