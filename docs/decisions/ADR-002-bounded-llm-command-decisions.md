# ADR-002: bounded autonomous LLM command decisions

## Status

Accepted

## Context

ADR-001 allowed contextual review only to add human approval. That protects the existing
boundary but cannot reduce prompts for operations already configured to require approval.
The primary goal is now to let the reviewer resolve routine decisions while deterministic
permissions bound the consequences of a mistaken approval.

## Decision

- Local RBAC, denylist, configured freeze windows and OPA remain hard enforcement. Their
  denials skip review and cannot be overridden.
- Non-read-only operations inside that envelope are agent-reviewable unless their command
  class is privileged, which remains human-only.
- A completed review returns `approve`, `deny` or `escalate`. Approve discharges a soft
  approval, deny refuses without prompting, and escalate requests fresh human approval.
- Reviewer failure is equivalent to escalate. Human-only and escalated approvals do not
  reuse JIT grants.
- Reviewer autonomy is disabled when no reviewer URL is configured, preserving existing
  policy and approval behavior.

## Consequences

- Routine operations can complete without human prompts even under `ask-all`.
- A false model denial affects availability; a false approval is bounded by deterministic
  policy and operating-system permissions.
- Privileged and policy-exception work still requires a person.
- Model verdict, risk and identity remain audited and versioned.
- Operators must configure their own production freeze schedule; ssh-mcp does not assume a
  market, exchange calendar or local trading hours.

## Rejected alternatives

- **Keep monotonic escalation only:** cannot meet the automation objective.
- **Let the model override every approval:** gives probabilistic output authority over
  privileged operations.
- **Make risk alone the authorization contract:** obscures whether the model intended to
  approve, refuse or ask for help.
- **Ship built-in trading hours:** incorrect across exchanges, products, holidays and night
  sessions; explicit operator configuration is safer.
