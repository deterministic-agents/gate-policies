# GATE Invariant Bundle — Baseline
# File: policies/invariants_baseline.rego
# Package: gate.invariants
#
# Invariant bundle version: gate-invariants-baseline-v1.0
# Compatible with GATE: v1.2.8+
#
# IMPORTANT: This bundle is evaluated SEPARATELY from the policy bundle (C05).
# It is evaluated AFTER policy returns allow, BEFORE tool execution.
# Invariant halts are NOT overridable at runtime without break-glass procedure.
#
# Change control: Invariant bundle changes require a higher approval bar than
# policy bundle changes. Hash-pin the bundle and update your ABOM.
#
# Run tests: opa test policies/ -v --bundle policies/invariants_baseline.rego

package gate.invariants

import rego.v1

# ─────────────────────────────────────────────
# RESULT
# ─────────────────────────────────────────────

# Default: pass (invariants are additive restrictions, not the base deny)
default invariant_pass := true

invariant_pass if {
  count(invariant_violations) == 0
}

invariant_halt if {
  count(invariant_violations) > 0
}

# ─────────────────────────────────────────────
# INVARIANT RULES
# Each rule in invariant_violations is a halt.
# Rule ID format: INV-<CATEGORY>-<NUMBER>
# ─────────────────────────────────────────────

invariant_violations contains {
  "rule_id": "INV-FINANCIAL-001",
  "description": "Single transfer amount exceeds absolute hard limit",
  "tool": input.action.tool_name,
  "value": input.action.params.amount_usd,
  "limit": 10000
} if {
  input.action.tool_name == "transfer_funds"
  input.action.params.amount_usd > 10000
}

invariant_violations contains {
  "rule_id": "INV-FINANCIAL-002",
  "description": "Destination account not in verified vendor registry",
  "tool": input.action.tool_name
} if {
  input.action.tool_name == "transfer_funds"
  not input.action.params.destination_verified == true
}

invariant_violations contains {
  "rule_id": "INV-DELETE-001",
  "description": "Delete-class tool invoked in prod without exception_id",
  "tool": input.action.tool_name
} if {
  regex.match(`^delete_`, input.action.tool_name)
  input.environment == "prod"
  not input.action.params.exception_id
}

invariant_violations contains {
  "rule_id": "INV-DOMAIN-001",
  "description": "HTTP destination not in allowlisted domains",
  "tool": input.action.tool_name,
  "destination": input.action.params.url
} if {
  input.action.tool_category == "irreversible_write"
  input.action.params.url
  not http_destination_allowed
}

http_destination_allowed if {
  ALLOWED_EXTERNAL_DOMAINS := {
    "api.stripe.com",
    "api.sendgrid.com",
    "hooks.slack.com",
  }
  url_host := urlparse.host(input.action.params.url)
  url_host in ALLOWED_EXTERNAL_DOMAINS
}

invariant_violations contains {
  "rule_id": "INV-RUNLIMIT-001",
  "description": "Irreversible action count within run_id exceeds limit",
  "run_id": input.run_id,
  "count": input.context.run_irrevocable_action_count,
  "limit": 5
} if {
  input.action.tool_category in {"irreversible_write", "financial", "infrastructure"}
  input.context.run_irrevocable_action_count > 5
}

invariant_violations contains {
  "rule_id": "INV-INFRA-001",
  "description": "Infrastructure tool invoked outside maintenance window without override",
  "tool": input.action.tool_name
} if {
  input.action.tool_category == "infrastructure"
  input.action.tool_name in {"delete_cluster", "destroy_environment", "wipe_database"}
  not input.action.params.maintenance_override_id
}

# ─────────────────────────────────────────────
# OUTPUT SHAPE
# ─────────────────────────────────────────────

result := {
  "invariant_pass": invariant_pass,
  "invariant_halt": invariant_halt,
  "violations": invariant_violations,
  "violation_count": count(invariant_violations),
  "failed_rule_ids": [v.rule_id | v := invariant_violations[_]]
}
