# GATE HITL Integration — Worked Example
# File: examples/hitl/hitl_integration_example.md
#
# This example shows a complete HITL approval flow for a transfer_funds
# tool call that exceeds the auto-execute threshold.
#
# Scenario: Treasury agent requests a $2,500 funds transfer.
# ORM score: 0.58 (above require_hitl threshold of 0.45 for add_verification,
#             below require_hitl of 0.65 — but financial tool triggers HITL
#             regardless per tool_gateway_baseline.rego line 93).

## Flow overview

```
Agent Runtime
    │
    ▼
[1] Tool Gateway — evaluates policy
    │   policy decision: allow
    │   obligations: [audit_log, sign_action, hitl_approval, verify_destination,
    │                 snapshot_response, require_idempotency_key]
    ▼
[2] Tool Gateway — enforces hitl_approval obligation
    │   sends approval request to HITL Service
    │   blocks execution
    ▼
[3] HITL Service — notifies approver
    │   approver receives notification with request summary
    ▼
[4] Approver — reviews and signs decision
    │   action: approve
    │   conditions: [must_use_account:primary, max_amount_usd:2500]
    ▼
[5] HITL Service — emits signed HITLDecisionRecord
    │   commits to ledger
    ▼
[6] Tool Gateway — receives approval
    │   verifies signature
    │   verifies approval_id linked to original request_hash
    │   executes tool
    ▼
[7] Tool Gateway — emits evidence
        ToolResponseEnvelope + LedgerEvent + ReplayTraceStep
```

## Step 1: Policy decision record (produced by Tool Gateway)

```json
{
  "schema_version": "v1",
  "event_type": "gate.policy.decision",
  "time": "2026-04-13T14:22:00Z",
  "decision_id": "7f3a1b2c-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
  "run_id": "a1b2c3d4-e5f6-7a8b-9c0d-e1f2a3b4c5d6",
  "trace_id": "trace-treasury-run-001",
  "tenant_id": "acme-corp",
  "environment": "prod",
  "subject": {
    "agent_instance_id": "spiffe://org/agent/treasury#run-a1b2c3",
    "subject_id": "spiffe://org/agent/treasury",
    "attested": true
  },
  "action": {
    "type": "tool.invoke",
    "tool_name": "transfer_funds",
    "tool_category": "financial",
    "risk_tier": "high"
  },
  "inputs": {
    "request_hash": "sha256:3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d",
    "context_hash": "sha256:4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e",
    "orm_risk_score": 0.58
  },
  "bundles": {
    "policy_bundle_hash": "sha256:d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5",
    "tool_schema_hash":   "sha256:e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6"
  },
  "result": {
    "decision": "allow",
    "reason_codes": ["ALLOWLIST_MATCH", "BUDGET_OK"],
    "obligations": [
      { "type": "audit_log",              "required": true },
      { "type": "sign_action",            "required": true },
      { "type": "hitl_approval",          "required": true },
      { "type": "verify_destination",     "required": true },
      { "type": "snapshot_response",      "required": true },
      { "type": "require_idempotency_key","required": true }
    ]
  }
}
```

## Step 2: HITL approval request (sent by Tool Gateway to HITL Service)

```json
{
  "approval_request_id": "req-9a8b7c6d-5e4f-3a2b-1c0d-e9f8a7b6c5d4",
  "run_id": "a1b2c3d4-e5f6-7a8b-9c0d-e1f2a3b4c5d6",
  "policy_decision_id": "7f3a1b2c-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
  "request_hash": "sha256:3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d",
  "notification": {
    "approver_role": "role:treasury-approver",
    "summary": "Transfer funds: $2,500 to vendor ACME-VENDOR-442",
    "tool_name": "transfer_funds",
    "tool_category": "financial",
    "orm_risk_score": 0.58,
    "agent": "spiffe://org/agent/treasury",
    "expires_at": "2026-04-13T14:32:00Z"
  }
}
```

## Step 3: Approver reviews in HITL UI

Approver sees:
- Agent: treasury
- Action: transfer_funds
- Amount: $2,500
- Destination: ACME-VENDOR-442 (verified vendor)
- ORM risk: 0.58 (medium)
- Justification context: [invoice #INV-2026-0441 matched, PO verified]
- Decision deadline: 10 minutes

## Step 4: Signed HITL Decision Record (produced by HITL Service)

```yaml
schema_version: v1
approval_id: appr-1a2b3c4d-5e6f-7a8b-9c0d-e1f2a3b4c5d6
time: "2026-04-13T14:24:33Z"

run_id: a1b2c3d4-e5f6-7a8b-9c0d-e1f2a3b4c5d6
trace_id: trace-treasury-run-001
tenant_id: acme-corp
environment: prod

request:
  tool_name: transfer_funds
  request_hash: "sha256:3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d"
  amount_usd: 2500
  destination_ref: ACME-VENDOR-442

context:
  orm_risk_score: 0.58
  policy_decision_id: 7f3a1b2c-4d5e-6f7a-8b9c-0d1e2f3a4b5c
  ledger_head_ref: "ledger://prod/2026/04/13/00042"

decision:
  approver_id: "user:treasury.manager@acme.com"
  approver_role: "role:treasury-approver"
  action: approve
  justification: "Vendor verified (ACME-VENDOR-442 on approved list), invoice INV-2026-0441 matched to PO-2026-0318. Amount within single transaction limit."
  conditions:
    - "must_use_account:primary"
    - "max_amount_usd:2500"
  expires_at: "2026-04-13T15:24:33Z"

evidence:
  signing_key_id: kid-treasury-approver-2026-04
  signature: "base64url:MEUCIQDx...signature_bytes...AiEA"
  ledger_event_id: "ledger-evt-2b3c4d5e-6f7a-8b9c-0d1e-2f3a4b5c6d7e"
```

## Step 5: Tool Gateway verification before execution

Before executing the tool call, the gateway verifies:

```python
# Pseudocode — implement in your Tool Gateway
def verify_hitl_approval(request_hash: str, approval_id: str) -> bool:
    record = hitl_service.get_decision(approval_id)

    # 1. Approval links to this specific request
    assert record.request.request_hash == request_hash

    # 2. Approval is not expired
    assert datetime.utcnow() < record.decision.expires_at

    # 3. Signature is valid
    assert verify_signature(
        key_id=record.evidence.signing_key_id,
        signature=record.evidence.signature,
        payload=canonical_json(record.decision)
    )

    # 4. Action is approve (not deny or modify)
    assert record.decision.action == "approve"

    # 5. Ledger event exists (approval was committed)
    assert ledger.event_exists(record.evidence.ledger_event_id)

    return True
```

## Step 6: Tool execution and evidence emission

After approval verification, the gateway:
1. Executes transfer_funds with the approved parameters
2. Emits ToolResponseEnvelope with snapshot_uri (obligation: snapshot_response)
3. Signs the action with the agent's workload identity key (obligation: sign_action)
4. Commits LedgerEvent referencing the approval_id
5. Records ReplayTraceStep with step_type: tool_call

## Failure scenario: Approval expires before execution

If the agent does not execute within the approval window (expires_at):

```python
# Gateway behavior on expired approval
if datetime.utcnow() >= record.decision.expires_at:
    emit_policy_decision(
        decision="deny",
        reason_codes=["HITL_APPROVAL_EXPIRED"],
        obligations=[]  # No obligations on deny
    )
    emit_ledger_event(event_type="hitl_approval_expired")
    raise ToolExecutionDenied("HITL approval expired. Request fresh approval.")
```

The agent must request a new approval. The expired approval record
remains in the ledger as evidence.

## Approval fatigue monitoring query

```sql
-- Flag approvers rubber-stamping: >95% approve rate, <30s avg decision time
SELECT
  decision.approver_id,
  COUNT(*) AS total,
  ROUND(COUNTIF(decision.action = 'approve') / COUNT(*) * 100, 1) AS approve_rate_pct,
  ROUND(AVG(TIMESTAMP_DIFF(h.time, created_at, SECOND)), 0) AS avg_decision_seconds
FROM gate_hitl_decisions h
WHERE environment = 'prod'
  AND time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
GROUP BY decision.approver_id
HAVING approve_rate_pct > 95 AND avg_decision_seconds < 30
ORDER BY approve_rate_pct DESC;
```

If this query returns rows, review your HITL obligation thresholds per
Artifact A7 tuning guidance. HITL is scarce capacity — route only
genuinely high-impact actions through it.
