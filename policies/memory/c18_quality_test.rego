# GATE C18 - Data Quality Gate policy tests
# Run: opa test policies/ -v

package gate.memory.quality_test

import rego.v1
import data.gate.memory.quality

# Reusable quality bundle for tests.
bundle := {
    "ttl_by_class": {
        "legal_text": 31536000,      # 1 year
        "product_pricing": 86400,    # 1 day
    },
    "min_confidence_by_class": {
        "legal_text": 0.6,
        "product_pricing": 0.8,
    },
    "provenance_required_by_class": {
        "legal_text": true,
        "product_pricing": true,
    },
    "action_matrix": {
        "sandbox": {
            "legal_text":      {"freshness": "flag", "confidence": "flag", "provenance": "flag"},
            "product_pricing": {"freshness": "flag", "confidence": "flag", "provenance": "flag"},
        },
        "bounded": {
            "legal_text":      {"freshness": "deny", "confidence": "deny", "provenance": "flag"},
            "product_pricing": {"freshness": "deny", "confidence": "downgrade", "provenance": "deny"},
        },
        "high_privilege": {
            "legal_text":      {"freshness": "deny", "confidence": "deny", "provenance": "deny"},
            "product_pricing": {"freshness": "deny", "confidence": "deny", "provenance": "deny"},
        },
    },
}

# Fresh, high-confidence, verified provenance: pass.
test_pass_when_all_dimensions_meet_thresholds if {
    quality.outcome == "pass" with input as {
        "item": {
            "content_class": "legal_text",
            "freshness_age_seconds": 1000,
            "confidence_score": 0.9,
            "provenance_uri": "https://example.com/source",
            "provenance_hash_verified": true,
        },
        "quality_bundle": bundle,
        "autonomy_tier": "bounded",
    }
}

# Stale item at bounded tier: deny per action matrix.
test_stale_at_bounded_returns_deny if {
    quality.outcome == "deny" with input as {
        "item": {
            "content_class": "legal_text",
            "freshness_age_seconds": 999999999,
            "confidence_score": 0.9,
            "provenance_uri": "https://example.com/source",
            "provenance_hash_verified": true,
        },
        "quality_bundle": bundle,
        "autonomy_tier": "bounded",
    }
}

# Low confidence at high_privilege: deny.
test_low_confidence_at_high_privilege_returns_deny if {
    quality.outcome == "deny" with input as {
        "item": {
            "content_class": "product_pricing",
            "freshness_age_seconds": 100,
            "confidence_score": 0.3,
            "provenance_uri": "https://example.com/source",
            "provenance_hash_verified": true,
        },
        "quality_bundle": bundle,
        "autonomy_tier": "high_privilege",
    }
}

# Missing provenance at high_privilege: deny.
test_missing_provenance_at_high_privilege_returns_deny if {
    quality.outcome == "deny" with input as {
        "item": {
            "content_class": "legal_text",
            "freshness_age_seconds": 100,
            "confidence_score": 0.9,
            "provenance_uri": "",
            "provenance_hash_verified": false,
        },
        "quality_bundle": bundle,
        "autonomy_tier": "high_privilege",
    }
}

# Missing provenance at bounded for legal_text: flag (per matrix).
test_missing_provenance_at_bounded_flags_for_legal_text if {
    quality.outcome == "flag" with input as {
        "item": {
            "content_class": "legal_text",
            "freshness_age_seconds": 100,
            "confidence_score": 0.9,
            "provenance_uri": "",
            "provenance_hash_verified": false,
        },
        "quality_bundle": bundle,
        "autonomy_tier": "bounded",
    }
}

# Severity rule: deny wins over flag when multiple dimensions fail.
test_deny_wins_over_flag if {
    quality.outcome == "deny" with input as {
        "item": {
            "content_class": "product_pricing",
            "freshness_age_seconds": 100000,
            "confidence_score": 0.3,
            "provenance_uri": "https://example.com/source",
            "provenance_hash_verified": true,
        },
        "quality_bundle": bundle,
        "autonomy_tier": "bounded",
    }
}

# Flags are surfaced alongside outcome.
test_stale_flag_is_set if {
    "stale" in quality.flags_set with input as {
        "item": {
            "content_class": "legal_text",
            "freshness_age_seconds": 999999999,
            "confidence_score": 0.9,
            "provenance_uri": "https://example.com/source",
            "provenance_hash_verified": true,
        },
        "quality_bundle": bundle,
        "autonomy_tier": "bounded",
    }
}
