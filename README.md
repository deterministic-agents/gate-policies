# gate-policies

**GATE OPA/Rego policy and invariant bundles - v1.1.1**

Baseline policy bundle, invariant bundle, unit tests, ABOM templates,
tool authorization matrix, and a worked HITL integration example for
GATE-conformant Tool Gateway deployments.

Framework: https://deterministicagents.ai  
Organisation: https://github.com/deterministic-agents  
Documentation: CC BY 4.0 - Andrew Stevens · Code: MIT

---

## Contents

```
gate-policies/
├── tool_gateway_baseline.rego        # Production baseline policy (C05)
├── tool_gateway_baseline_test.rego   # OPA unit tests - run before every deploy
├── invariants_baseline.rego          # C09 invariant bundle (separate from policy)
├── policies/
│   ├── discovery/
│   │   ├── c17_discovery.rego                  # C17 candidate classification (v1.1.0)
│   │   └── c17_discovery_test.rego             # C17 unit tests
│   ├── memory/
│   │   ├── c18_quality.rego                    # C18 quality gate (v1.1.0)
│   │   └── c18_quality_test.rego               # C18 unit tests
│   └── assurance/
│       ├── c19_drift_response.rego             # C19 drift response routing (v1.1.0)
│       └── c19_drift_response_test.rego        # C19 unit tests
└── examples/
    ├── abom/
    │   └── invoice_reconciliation_agent.yaml   # Complete bounded-tier ABOM
    ├── tool-auth-matrix/
    │   └── tool_authorization_matrix.yaml      # Tool auth matrix (8 tools)
    └── hitl/
        └── hitl_integration_example.md         # Worked HITL approval flow
```

---

## Critical distinction: policy bundle vs invariant bundle

These are two separate bundles with separate hashes and separate change-control
requirements.

**Policy bundle** (`tool_gateway_baseline.rego`) - evaluates context to
produce allow/deny/obligations. Configurable. Standard change-control bar.

**Invariant bundle** (`invariants_baseline.rego`) - evaluated after policy,
independent of policy context. Non-overridable at runtime. Requires higher
approval bar to change (see GATE C09).

```
Tool Gateway flow:
  authenticate identity (C01)
    → validate schema (C05)
      → evaluate policy → allow / deny
        → evaluate invariants → pass / HALT   ← independent of policy result
          → enforce obligations (HITL, sign, snapshot...)
            → execute tool
              → emit evidence
```

Never merge invariants into the policy bundle. They serve different governance
purposes.

---

## Quick start

**1. Customise allowlists**

Edit `AGENT_ALLOWLIST` and `TOOL_ALLOWLIST` in `tool_gateway_baseline.rego`:

```rego
AGENT_ALLOWLIST := {
  "spiffe://YOUR_ORG/agent/YOUR_AGENT": ["read_only", "reversible_write"],
}

TOOL_ALLOWLIST := {
  "spiffe://YOUR_ORG/agent/YOUR_AGENT": {"your_tool_1", "your_tool_2"},
}
```

**2. Tune ORM thresholds**

Adjust `ORM_THRESHOLDS` and `FINANCIAL_LIMITS` for your risk profile.
See the GATE framework paper Artifact A7 (ORM Risk Model Worksheet) for
tuning guidance by deployment context.

**3. Add invariant rules**

Add rules to `invariants_baseline.rego` for any new high-impact tools.
Each rule MUST have a unique `rule_id` (format: `INV-<CATEGORY>-<NUMBER>`)
and a corresponding test case.

**4. Run tests before every deploy**

```bash
opa test . -v
# All tests must pass. Zero exceptions.
```

**5. Hash the bundles and update your ABOM**

```bash
sha256sum tool_gateway_baseline.rego
sha256sum invariants_baseline.rego
# or for archives:
sha256sum gate-policy-bundle-v1.x.tar.gz
sha256sum gate-invariant-bundle-v1.x.tar.gz
```

Reference these hashes in your ABOM as `policy_bundle_hash` and
`invariant_bundle_hash`. The Tool Gateway verifies them on every run.

---

## ABOM example

`examples/abom/invoice_reconciliation_agent.yaml` shows a complete Agent
Bill of Materials for a bounded-tier financial reconciliation agent. It
specifies required controls, bundle hashes, identity config, memory
partitions, and per-tool required controls and obligations.

The ABOM is the authoritative manifest of what an agent is allowed to do.
Every agent version MUST have one.

---

## Tool authorization matrix

`examples/tool-auth-matrix/tool_authorization_matrix.yaml` maps tools to
allowed agents, required controls, policy conditions, and invariant rules.
It covers all five tool categories:

- `read_only` - no side effects
- `reversible_write` - recoverable side effects
- `irreversible_write` - permanent side effects (email, CMS publish)
- `financial` - fund movements
- `infrastructure` - deployment, scaling, config changes

Any change to the matrix requires an ABOM update, a policy bundle update,
and a conformance check run.

---

## HITL integration example

`examples/hitl/hitl_integration_example.md` walks through a complete
`transfer_funds` approval flow: policy decision → obligation → approval
request → signed record → gateway verification → tool execution → evidence.

Includes the approval fatigue monitoring SQL query and the expiry handling
pattern.

---

## Dependency

Policy and invariant bundles reference contracts from
[gate-contracts](https://github.com/deterministic-agents/gate-contracts).
Tool schemas used for schema validation in `C05` should be sourced from
there or from your own tool schema registry.

---

## v1.1.0 (2026-06-16)

Adds three new policy bundles for the v1.3 controls. Following the v1.3 contract, new controls get new policy files. Nothing is added to `tool_gateway_baseline.rego` or `invariants_baseline.rego`; those files are unchanged in v1.1.0.

### New files

```
policies/discovery/c17_discovery.rego          # gate.discovery
policies/discovery/c17_discovery_test.rego
policies/memory/c18_quality.rego               # gate.memory.quality
policies/memory/c18_quality_test.rego
policies/assurance/c19_drift_response.rego     # gate.assurance.drift
policies/assurance/c19_drift_response_test.rego
```

### Policy bundle versioning

Each new package is independently versioned. The v1.1.0 release ships:

- `gate-policy-c17-v1.0` (discovery classification)
- `gate-policy-c18-v1.0` (memory quality gate)
- `gate-policy-c19-v1.0` (drift response routing)

Hash the bundle contents and reference each hash from your ABOM where applicable.

### Why new files, not extensions

The v1.3 framework paper requires that new controls produce isolated policy units rather than accreting onto the existing baseline. This keeps the existing tool-gateway policy bundle stable for v1.0.0 implementations and lets v1.3 features roll out independently. Reviewers can read each policy file end to end without context from other files.

### Running the tests

```bash
opa test policies/ -v
```

All v1.0.0 baseline tests continue to pass unchanged. The new files add tests under `gate.discovery_test`, `gate.memory.quality_test`, and `gate.assurance.drift_test`.

---

## Related repos

| Repo | What it is |
|---|---|
| [gate-contracts](https://github.com/deterministic-agents/gate-contracts) | JSON Schema contracts (canonical dependency) |
| [gate-python](https://github.com/deterministic-agents/gate-python) | Python reference library |
| [gate-conformance](https://github.com/deterministic-agents/gate-conformance) | Conformance checks, self-assessment, runbooks |
| [gate](https://github.com/deterministic-agents/gate) | Framework paper, spec site source |
