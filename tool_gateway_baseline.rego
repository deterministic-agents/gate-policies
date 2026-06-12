# GATE Tool Gateway — Baseline Policy Bundle
# File: policies/tool_gateway_baseline.rego
# Package: gate.toolpolicy
#
# This is a production-ready starting policy for a bounded-tier GATE deployment.
# Customize allowlists, thresholds, and obligations for your environment.
#
# How to use:
#   1. Copy this file into your OPA bundle directory.
#   2. Update AGENT_ALLOWLIST, TOOL_ALLOWLIST, and FINANCIAL_LIMITS.
#   3. Hash the bundle: sha256sum <bundle.tar.gz>
#   4. Reference the hash in your ABOM as policy_bundle_hash.
#   5. Run tests: opa test policies/ -v
#
# Policy bundle version: gate-policy-baseline-v1.0
# Compatible with GATE: v1.2.8+

package gate.toolpolicy

import rego.v1

# ─────────────────────────────────────────────
# CONFIGURATION — customize per deployment
# ─────────────────────────────────────────────

# Agents permitted to invoke tools. Map agent subject_id → allowed tool categories.
AGENT_ALLOWLIST := {
  "spiffe://org/agent/invoice-reconciliation": ["read_only", "reversible_write"],
  "spiffe://org/agent/customer-support":       ["read_only"],
  "spiffe://org/agent/devops-automation":      ["read_only", "reversible_write", "irreversible_write", "infrastructure"],
  "spiffe://org/agent/treasury":               ["read_only", "reversible_write", "financial"],
}

# Tools explicitly permitted per agent. Empty set = no tools allowed by default.
TOOL_ALLOWLIST := {
  "spiffe://org/agent/invoice-reconciliation": {
    "read_erp_po", "read_erp_invoice", "read_vendor_registry",
    "create_dispute_case", "update_invoice_status"
  },
  "spiffe://org/agent/customer-support": {
    "read_crm_contact", "read_ticket", "read_knowledge_base",
    "create_ticket", "update_ticket_status"
  },
  "spiffe://org/agent/devops-automation": {
    "read_infra_state", "read_deployment_status",
    "deploy_service_canary", "rollback_deployment",
    "restart_pod", "scale_deployment"
  },
  "spiffe://org/agent/treasury": {
    "read_bank_balance", "read_vendor_registry",
    "create_payment_instruction", "transfer_funds"
  },
}

# ORM risk score thresholds
ORM_THRESHOLDS := {
  "auto_execute":      0.20,
  "add_verification":  0.45,
  "require_hitl":      0.65,
  "block":             0.85,
}

# Financial limits by agent
FINANCIAL_LIMITS := {
  "spiffe://org/agent/treasury": {
    "max_single_transfer_usd":  5000,
    "max_daily_transfer_usd":   50000,
    "require_hitl_above_usd":   1000,
  }
}

# ─────────────────────────────────────────────
# MAIN DECISION
# ─────────────────────────────────────────────

# Default deny. Explicit allow required.
default allow := false
default deny  := true

allow if {
  identity_valid
  not blocked_by_orm
  tool_in_allowlist
  category_permitted
  not financial_limit_exceeded
  not time_window_violation
}

deny if {
  not allow
}

# ─────────────────────────────────────────────
# IDENTITY
# ─────────────────────────────────────────────

identity_valid if {
  input.subject.attested == true
  AGENT_ALLOWLIST[input.subject.subject_id]
}

# ─────────────────────────────────────────────
# TOOL ALLOWLIST
# ─────────────────────────────────────────────

tool_in_allowlist if {
  agent_tools := TOOL_ALLOWLIST[input.subject.subject_id]
  input.action.tool_name in agent_tools
}

category_permitted if {
  agent_categories := AGENT_ALLOWLIST[input.subject.subject_id]
  input.action.tool_category in agent_categories
}

# ─────────────────────────────────────────────
# ORM RISK GATING
# ─────────────────────────────────────────────

blocked_by_orm if {
  input.context.orm_risk_score >= ORM_THRESHOLDS.block
}

hitl_required_by_orm if {
  input.context.orm_risk_score >= ORM_THRESHOLDS.require_hitl
  input.context.orm_risk_score < ORM_THRESHOLDS.block
}

verification_required_by_orm if {
  input.context.orm_risk_score >= ORM_THRESHOLDS.add_verification
  input.context.orm_risk_score < ORM_THRESHOLDS.require_hitl
}

# ─────────────────────────────────────────────
# FINANCIAL CONTROLS
# ─────────────────────────────────────────────

financial_limit_exceeded if {
  input.action.tool_name == "transfer_funds"
  limits := FINANCIAL_LIMITS[input.subject.subject_id]
  input.action.params.amount_usd > limits.max_single_transfer_usd
}

hitl_required_financial if {
  input.action.tool_category == "financial"
  limits := FINANCIAL_LIMITS[input.subject.subject_id]
  input.action.params.amount_usd > limits.require_hitl_above_usd
}

# ─────────────────────────────────────────────
# TIME WINDOWS (infrastructure tools)
# ─────────────────────────────────────────────

# Infrastructure changes only permitted during maintenance windows.
# Adjust window times for your timezone and on-call schedule.
time_window_violation if {
  input.action.tool_category == "infrastructure"
  not in_maintenance_window
}

in_maintenance_window if {
  # Weekdays 02:00–05:00 UTC
  hour := time.clock(time.now_ns())[0]
  weekday := time.weekday(time.now_ns())
  hour >= 2
  hour < 5
  weekday != "Saturday"
  weekday != "Sunday"
}

# ─────────────────────────────────────────────
# OBLIGATIONS
# ─────────────────────────────────────────────

# Obligations that the Tool Gateway MUST enforce when allow == true.
# The gateway MUST NOT proceed without enforcing all required obligations.

obligations contains {"type": "audit_log", "required": true} if {
  allow
}

obligations contains {"type": "sign_action", "required": true} if {
  allow
  input.action.tool_category in {"financial", "irreversible_write", "infrastructure"}
}

obligations contains {"type": "hitl_approval", "required": true} if {
  allow
  hitl_required_by_orm
}

obligations contains {"type": "hitl_approval", "required": true} if {
  allow
  hitl_required_financial
}

obligations contains {"type": "verify_destination", "required": true} if {
  allow
  input.action.tool_name == "transfer_funds"
}

obligations contains {"type": "snapshot_response", "required": true} if {
  allow
  input.action.tool_category in {"financial", "irreversible_write", "infrastructure"}
}

obligations contains {"type": "require_idempotency_key", "required": true} if {
  allow
  input.action.tool_category in {"financial", "irreversible_write"}
}

obligations contains {"type": "redact_fields", "required": true, "params": {"fields": ["pan", "cvv", "ssn", "password"]}} if {
  allow
}

# ─────────────────────────────────────────────
# REASON CODES (for policy decision record)
# ─────────────────────────────────────────────

reason_codes contains "ALLOWLIST_MATCH" if { tool_in_allowlist }
reason_codes contains "BUDGET_OK" if { input.context.budgets.tool_calls_remaining > 0 }
reason_codes contains "DENYLIST_MATCH" if { not tool_in_allowlist }
reason_codes contains "IDENTITY_INVALID" if { not identity_valid }
reason_codes contains "ORM_THRESHOLD_EXCEEDED" if { blocked_by_orm }
reason_codes contains "BUDGET_EXCEEDED" if { input.context.budgets.tool_calls_remaining <= 0 }
reason_codes contains "FINANCIAL_LIMIT_EXCEEDED" if { financial_limit_exceeded }
reason_codes contains "TIME_WINDOW_VIOLATION" if { time_window_violation }
