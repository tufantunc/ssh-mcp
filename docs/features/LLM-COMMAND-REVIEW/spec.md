---
feature: LLM-COMMAND-REVIEW
stage: spec
status: accepted
branch: feat/llm-command-review
---

# Spec: contextual review for non-read-only operations

## Requirements

1. Review is disabled unless an operator configures a valid HTTP(S) reviewer URL.
2. Local policy and OPA denials remain final and do not call the reviewer.
3. Every policy-allowed operation whose final command class is not `read-only` is reviewed,
   except session release, which remains non-refusable.
4. A completed review returns `approve`, `deny` or `escalate`: approve may discharge a
   soft approval; deny recommends rejection and requires a human; escalate also requires
   a human. No LLM verdict is a final refusal.
5. Review can never change a deterministic deny, and privileged operations remain
   human-only even when review says approve.
6. Reviewer-escalated and human-only approvals are never satisfied by a JIT grant.
7. Review input contains a redacted command, tool, class and host tier, but no SSH
   credentials, host address, remote user, stdin, output or file content.
8. Review status and bounded, redacted findings appear in the approval and audit records.
9. The reviewer runs as an unprivileged, unpublished sidecar using an OpenAI-compatible
   model endpoint and has no SSH or audit mounts.
10. Existing configuration and audit records remain compatible when review is disabled.
11. Operators may configure deterministic weekly freeze windows by host group, IANA time
    zone and weekday/time range; non-read-only operations in an active window are denied
    before OPA or reviewer calls. Windows may cross midnight and no schedule is assumed.

## Design

The pipeline injects an optional `CommandReviewer` after `evaluateWithOpa`. The HTTP
implementation sends a versioned request to `POST /v1/review` and maps a strict response
to a bounded internal `ReviewResult`. Transport or validation failures create an
`unavailable` result rather than throwing past the policy gate.

The merge is a pure function. A deterministic `deny` is returned unchanged. On an
agent-reviewable operation, approve returns allow with an LLM approver; reviewer deny,
escalate and unavailable all require fresh human approval with distinct rule identifiers.
Privileged operations are human-only: approve preserves or raises their human approval.
The pipeline carries the review verdict into elicitation and audit; every remaining prompt
bypasses the JIT grant cache.

Freeze windows are part of deterministic policy and use an injectable clock. They are
checked after command classification and denylist matching but before approval, OPA and
review. Invalid time zones and malformed/equal time ranges fail configuration loading.

The sidecar accepts only JSON with `schemaVersion: 2`, bounds request and response bodies,
and calls an OpenAI-compatible chat-completions endpoint once with no retry or tools. It
requires strict JSON model output and returns an error for malformed content rather than
repairing it. Its fixed prompt treats the command as untrusted data.

## Affected modules

- Policy-gated tool pipeline and MCP approval path.
- Audit record types, redaction and tracing.
- CLI/bootstrap configuration and MCP package manifest.
- Docker image and Compose deployment.
- README security and operations documentation.

No `docs/architecture/` document currently exists for these modules.

## Trade-offs and concerns

- OpenAI-compatible HTTP supports cloud and local backends but only the common
  chat-completions subset is used.
- Always-on redaction protects secrets but can remove context useful to the model.
- Failure-to-approval preserves availability better than hard denial while preventing
  silent automatic execution.
- No shadow mode keeps the first release smaller; operators can disable review but cannot
  collect advisory-only results.
- Reviewer denial still costs human attention, but cannot block legitimate work without a
  person confirming the refusal by declining the approval prompt.
- Autonomous approval reduces prompts but is bounded by role permissions, hard rules,
  freeze windows and the human-only privileged class.
- Session release is intentionally excluded because refusing it can leave a remote command
  running.

## Related ADRs

- [ADR-001: isolate contextual command review behind a sidecar](../../decisions/ADR-001-llm-reviewer-sidecar.md)
- [ADR-002: bounded autonomous LLM command decisions](../../decisions/ADR-002-bounded-llm-command-decisions.md)

## Acceptance criteria

- Type checking, unit/property, integration and end-to-end suites pass.
- Tests prove hard denials cannot be widened, approve discharges soft approval, reviewer
  deny/escalation/failure prompt freshly, and privileged remains human-only.
- Tests prove freeze windows, cross-midnight behavior, time zones, invalid configuration,
  read-only exemption and reviewer short-circuiting.
- A deterministic fake model covers the sidecar's success and failure contract.
- Both Docker targets build and Compose validates without publishing the reviewer port.
