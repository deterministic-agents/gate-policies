# GATE C19 - Drift response policy tests
# Run: opa test policies/ -v

package gate.assurance.drift_test

import rego.v1
import data.gate.assurance.drift

# Response matrix used across tests.
matrix := {
    "sandbox": {
        "tool_choice":   "log_only",
        "refusal_rate":  "log_only",
        "output_length": "log_only",
    },
    "bounded": {
        "tool_choice":   "flag",
        "refusal_rate":  "review_ticket",
        "output_length": "flag",
    },
    "high_privilege": {
        "tool_choice":            "review_ticket",
        "refusal_rate":           "tier_reduction",
        "output_length":          "review_ticket",
        "per_tool_arg_distribution": "emergency_stop",
    },
}

# no_drift returns log_only regardless of tier.
test_no_drift_returns_log_only_at_sandbox if {
    drift.response_action == "log_only" with input as {
        "drift_decision": {"dimension": "tool_choice", "decision": "no_drift", "p_value": 0.5},
        "autonomy_tier": "sandbox",
        "response_matrix": matrix,
    }
}

test_no_drift_returns_log_only_at_high_privilege if {
    drift.response_action == "log_only" with input as {
        "drift_decision": {"dimension": "refusal_rate", "decision": "no_drift", "p_value": 0.5},
        "autonomy_tier": "high_privilege",
        "response_matrix": matrix,
    }
}

# drift_detected at bounded uses matrix value.
test_drift_at_bounded_tool_choice_returns_flag if {
    drift.response_action == "flag" with input as {
        "drift_decision": {"dimension": "tool_choice", "decision": "drift_detected", "p_value": 0.001},
        "autonomy_tier": "bounded",
        "response_matrix": matrix,
    }
}

# drift_detected on refusal_rate at high_privilege: tier_reduction.
test_drift_at_high_privilege_refusal_rate_returns_tier_reduction if {
    drift.response_action == "tier_reduction" with input as {
        "drift_decision": {"dimension": "refusal_rate", "decision": "drift_detected", "p_value": 0.001},
        "autonomy_tier": "high_privilege",
        "response_matrix": matrix,
    }
}

# drift_detected on per_tool_arg_distribution at high_privilege: emergency_stop.
test_drift_at_high_privilege_per_tool_arg_returns_emergency_stop if {
    drift.response_action == "emergency_stop" with input as {
        "drift_decision": {"dimension": "per_tool_arg_distribution", "decision": "drift_detected", "p_value": 0.001},
        "autonomy_tier": "high_privilege",
        "response_matrix": matrix,
    }
}

# Drift on a dimension not in the matrix at the given tier: fallback to flag.
test_drift_unknown_dimension_falls_back_to_flag if {
    drift.response_action == "flag" with input as {
        "drift_decision": {"dimension": "unknown_dimension", "decision": "drift_detected", "p_value": 0.001},
        "autonomy_tier": "bounded",
        "response_matrix": matrix,
    }
}

test_drift_fallback_emits_reason_code if {
    "MATRIX_DEFAULT_FALLBACK" in drift.reason_codes with input as {
        "drift_decision": {"dimension": "unknown_dimension", "decision": "drift_detected", "p_value": 0.001},
        "autonomy_tier": "bounded",
        "response_matrix": matrix,
    }
}
