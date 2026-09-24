# ADR-001: isolate contextual command review behind a sidecar

## Status

Superseded by ADR-002

## Context

ssh-mcp makes authorization and execution decisions in one audited pipeline. Deterministic
classification, role bindings, deny rules and OPA are suitable enforcement controls, but
they cannot explain every operational risk in an otherwise permitted command. A language
model can add useful context, but its output is probabilistic, may be prompt-injected and
may be unavailable.

Putting review only in an MCP client or wrapper leaves a bypass around it. Hiding a model
behind the existing OPA endpoint loses uncertainty and explanation because that contract
is boolean and can only preserve or deny the local decision. Embedding a provider SDK in
the SSH process would also give model credentials and network behavior to the process that
holds SSH credentials.

## Decision

- The ssh-mcp pipeline remains the only enforcement and execution point.
- An optional HTTP sidecar performs contextual review in a separate container with no SSH
  material, audit volume, Docker socket or command-execution tools.
- Deterministic local policy and OPA run before review. Their denials are final and skip
  the sidecar.
- Review is monotonic: it may preserve a decision or raise `allow` to
  `require-approval`; it may never lower a restriction or authorize an operation.
- A missing, timed-out or malformed review raises a non-read-only operation to human
  approval instead of silently restoring automatic execution.
- Only redacted command text and minimum policy context cross the process boundary.

## Consequences

- Existing deployments behave exactly as before until a reviewer URL is configured.
- Model failures reduce automation but do not bypass the new control.
- Model latency is added to non-read-only operations while review is enabled.
- The sidecar protocol, model prompt and audit metadata must be versioned and tested.
- Human approval remains the final authority for reviewer-escalated operations.

## Rejected alternatives

- **Client-side reviewer only:** bypassable by direct calls to ssh-mcp.
- **LLM behind the OPA boolean endpoint:** cannot express review, uncertainty or approval
  escalation and conflates deterministic authorization with probabilistic advice.
- **Provider SDK inside ssh-mcp:** unnecessarily expands the SSH process's trusted
  computing base and credential exposure.
- **New SSH execution project:** duplicates the policy, session, transfer and audit paths
  that already form the security boundary.
