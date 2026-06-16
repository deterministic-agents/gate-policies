# GATE C17 - Discovery policy tests
# Run: opa test policies/ -v

package gate.discovery_test

import rego.v1
import data.gate.discovery

# Known, enrolled workload -> enrol (no further action needed).
test_known_enrolled_returns_enrol if {
    discovery.recommended_action == "enrol" with input as {
        "c04_inventory_present": true,
        "classification_confidence": 0.95,
        "asset_tags_present": true,
    }
}

# High confidence, tagged, not enrolled -> enrol (route to Commission).
test_high_confidence_tagged_returns_enrol if {
    discovery.recommended_action == "enrol" with input as {
        "c04_inventory_present": false,
        "classification_confidence": 0.85,
        "asset_tags_present": true,
    }
}

# High confidence, untagged -> terminate.
test_high_confidence_untagged_returns_terminate if {
    discovery.recommended_action == "terminate" with input as {
        "c04_inventory_present": false,
        "classification_confidence": 0.80,
        "asset_tags_present": false,
    }
}

# Low confidence -> exception.
test_low_confidence_returns_exception if {
    discovery.recommended_action == "exception" with input as {
        "c04_inventory_present": false,
        "classification_confidence": 0.45,
        "asset_tags_present": true,
    }
}

# Reason codes are emitted alongside action.
test_reason_code_high_confidence_untagged if {
    "HIGH_CONFIDENCE_UNTAGGED" in discovery.reason_codes with input as {
        "c04_inventory_present": false,
        "classification_confidence": 0.95,
        "asset_tags_present": false,
    }
}

test_reason_code_known_enrolled if {
    "KNOWN_ENROLLED" in discovery.reason_codes with input as {
        "c04_inventory_present": true,
        "classification_confidence": 0.95,
        "asset_tags_present": true,
    }
}
