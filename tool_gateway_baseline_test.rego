# GATE Tool Gateway — Policy Unit Tests
# File: policies/tool_gateway_baseline_test.rego
# Run: opa test policies/ -v
#
# Tests cover: allow/deny decisions, obligation emission,
# ORM threshold gating, financial limits, time windows.
# Add one test per invariant class (see GATE C09).

package gate.toolpolicy_test

import rego.v1
import data.gate.toolpolicy

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

valid_input(agent, tool, category) := {
  "subject": {
    "subject_id": agent,
    "attested": true
  },
  "action": {
    "tool_name": tool,
    "tool_category": category,
    "params": {}
  },
  "context": {
    "orm_risk_score": 0.10,
    "budgets": {
      "tool_calls_remaining": 100,
      "cost_usd_remaining": 50.0
    }
  }
}

# ─────────────────────────────────────────────
# ALLOW: valid identity + tool in allowlist
# ─────────────────────────────────────────────

test_allow_customer_support_read_ticket if {
  inp := valid_input(
    "spiffe://org/agent/customer-support",
    "read_ticket",
    "read_only"
  )
  toolpolicy.allow with input as inp
}

test_allow_invoice_agent_create_dispute if {
  inp := valid_input(
    "spiffe://org/agent/invoice-reconciliation",
    "create_dispute_case",
    "reversible_write"
  )
  toolpolicy.allow with input as inp
}

# ─────────────────────────────────────────────
# DENY: tool not in allowlist
# ─────────────────────────────────────────────

test_deny_customer_support_cannot_transfer_funds if {
  inp := valid_input(
    "spiffe://org/agent/customer-support",
    "transfer_funds",
    "financial"
  )
  not toolpolicy.allow with input as inp
  toolpolicy.deny with input as inp
}

test_deny_unknown_agent if {
  inp := valid_input(
    "spiffe://org/agent/unknown-agent",
    "read_ticket",
    "read_only"
  )
  not toolpolicy.allow with input as inp
}

# ─────────────────────────────────────────────
# DENY: unattested identity
# ─────────────────────────────────────────────

test_deny_unattested_identity if {
  inp := {
    "subject": {
      "subject_id": "spiffe://org/agent/customer-support",
      "attested": false
    },
    "action": {
      "tool_name": "read_ticket",
      "tool_category": "read_only",
      "params": {}
    },
    "context": {
      "orm_risk_score": 0.10,
      "budgets": {"tool_calls_remaining": 100, "cost_usd_remaining": 50.0}
    }
  }
  not toolpolicy.allow with input as inp
}

# ─────────────────────────────────────────────
# ORM THRESHOLDS
# ─────────────────────────────────────────────

test_deny_high_orm_score_blocked if {
  inp := object.union(
    valid_input("spiffe://org/agent/customer-support", "read_ticket", "read_only"),
    {"context": {"orm_risk_score": 0.90, "budgets": {"tool_calls_remaining": 100, "cost_usd_remaining": 50.0}}}
  )
  not toolpolicy.allow with input as inp
  toolpolicy.blocked_by_orm with input as inp
}

test_hitl_required_at_orm_threshold if {
  inp := object.union(
    valid_input("spiffe://org/agent/customer-support", "read_ticket", "read_only"),
    {"context": {"orm_risk_score": 0.70, "budgets": {"tool_calls_remaining": 100, "cost_usd_remaining": 50.0}}}
  )
  toolpolicy.hitl_required_by_orm with input as inp
}

test_allow_below_block_threshold_with_hitl_obligation if {
  inp := {
    "subject": {"subject_id": "spiffe://org/agent/customer-support", "attested": true},
    "action": {"tool_name": "read_ticket", "tool_category": "read_only", "params": {}},
    "context": {"orm_risk_score": 0.70, "budgets": {"tool_calls_remaining": 100, "cost_usd_remaining": 50.0}}
  }
  toolpolicy.allow with input as inp
  hitl_obs := {"type": "hitl_approval", "required": true}
  hitl_obs in toolpolicy.obligations with input as inp
}

# ─────────────────────────────────────────────
# FINANCIAL LIMITS
# ─────────────────────────────────────────────

test_deny_transfer_exceeds_single_limit if {
  inp := {
    "subject": {"subject_id": "spiffe://org/agent/treasury", "attested": true},
    "action": {
      "tool_name": "transfer_funds",
      "tool_category": "financial",
      "params": {"amount_usd": 10000}
    },
    "context": {"orm_risk_score": 0.10, "budgets": {"tool_calls_remaining": 100, "cost_usd_remaining": 50.0}}
  }
  not toolpolicy.allow with input as inp
  toolpolicy.financial_limit_exceeded with input as inp
}

test_allow_transfer_under_limit_with_hitl_obligation if {
  inp := {
    "subject": {"subject_id": "spiffe://org/agent/treasury", "attested": true},
    "action": {
      "tool_name": "transfer_funds",
      "tool_category": "financial",
      "params": {"amount_usd": 1500}
    },
    "context": {"orm_risk_score": 0.10, "budgets": {"tool_calls_remaining": 100, "cost_usd_remaining": 50.0}}
  }
  toolpolicy.allow with input as inp
  hitl_obs := {"type": "hitl_approval", "required": true}
  hitl_obs in toolpolicy.obligations with input as inp
}

# ─────────────────────────────────────────────
# OBLIGATIONS — always emitted on allow
# ─────────────────────────────────────────────

test_audit_log_obligation_always_present_on_allow if {
  inp := valid_input("spiffe://org/agent/customer-support", "read_ticket", "read_only")
  toolpolicy.allow with input as inp
  audit_obs := {"type": "audit_log", "required": true}
  audit_obs in toolpolicy.obligations with input as inp
}

test_sign_action_obligation_for_financial if {
  inp := {
    "subject": {"subject_id": "spiffe://org/agent/treasury", "attested": true},
    "action": {
      "tool_name": "transfer_funds",
      "tool_category": "financial",
      "params": {"amount_usd": 500}
    },
    "context": {"orm_risk_score": 0.10, "budgets": {"tool_calls_remaining": 100, "cost_usd_remaining": 50.0}}
  }
  toolpolicy.allow with input as inp
  sign_obs := {"type": "sign_action", "required": true}
  sign_obs in toolpolicy.obligations with input as inp
}

test_snapshot_response_required_for_irreversible if {
  inp := {
    "subject": {"subject_id": "spiffe://org/agent/devops-automation", "attested": true},
    "action": {
      "tool_name": "rollback_deployment",
      "tool_category": "irreversible_write",
      "params": {}
    },
    "context": {"orm_risk_score": 0.10, "budgets": {"tool_calls_remaining": 100, "cost_usd_remaining": 50.0}}
  }
  toolpolicy.allow with input as inp
  snap_obs := {"type": "snapshot_response", "required": true}
  snap_obs in toolpolicy.obligations with input as inp
}

# ─────────────────────────────────────────────
# REASON CODES
# ─────────────────────────────────────────────

test_allowlist_match_reason_code_on_allow if {
  inp := valid_input("spiffe://org/agent/customer-support", "read_ticket", "read_only")
  "ALLOWLIST_MATCH" in toolpolicy.reason_codes with input as inp
}

test_identity_invalid_reason_code_on_deny if {
  inp := {
    "subject": {"subject_id": "spiffe://org/agent/unknown", "attested": true},
    "action": {"tool_name": "read_ticket", "tool_category": "read_only", "params": {}},
    "context": {"orm_risk_score": 0.10, "budgets": {"tool_calls_remaining": 100, "cost_usd_remaining": 50.0}}
  }
  "IDENTITY_INVALID" in toolpolicy.reason_codes with input as inp
}
