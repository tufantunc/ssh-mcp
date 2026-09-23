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
4. A low-risk review preserves the local decision. Medium, high, unknown and unavailable
   reviews require approval when the local decision was allow.
5. Review can never turn deny into approval/allow or turn approval into allow.
6. Reviewer-triggered approvals are never satisfied by a JIT approval grant.
7. Review input contains a redacted command, tool, class and host tier, but no SSH
   credentials, host address, remote user, stdin, output or file content.
8. Review status and bounded, redacted findings appear in the approval and audit records.
9. The reviewer runs as an unprivileged, unpublished sidecar using an OpenAI-compatible
   model endpoint and has no SSH or audit mounts.
10. Existing configuration and audit records remain compatible when review is disabled.

## Design

The pipeline injects an optional `CommandReviewer` after `evaluateWithOpa`. The HTTP
implementation sends a versioned request to `POST /v1/review` and maps a strict response
to a bounded internal `ReviewResult`. Transport or validation failures create an
`unavailable` result rather than throwing past the policy gate.

The merge is a pure function. `deny` is returned unchanged. Low risk returns the original
evaluation. Medium, high, unknown or unavailable return the existing approval decision or
raise allow to require-approval with a reviewer rule identifier. The pipeline carries the
review into elicitation and audit; if review caused or reinforced the prompt, it bypasses
the JIT grant cache.

The sidecar accepts only JSON with `schemaVersion: 1`, bounds request and response bodies,
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
- Reviewer-triggered prompts ignore JIT grants, adding friction in exchange for preventing
  stale model assessments from reusing an earlier approval.
- Session release is intentionally excluded because refusing it can leave a remote command
  running.

## Related ADRs

- [ADR-001: isolate contextual command review behind a sidecar](../../decisions/ADR-001-llm-reviewer-sidecar.md)

## Acceptance criteria

- Type checking, unit/property, integration and end-to-end suites pass.
- Tests prove the decision merge is monotonic and all non-read-only pipeline operations
  call review while read-only and denied operations do not.
- Tests prove failure escalates, reviewer prompts ignore JIT grants, approval text is
  useful, secrets are redacted and audit hash chaining remains valid.
- A deterministic fake model covers the sidecar's success and failure contract.
- Both Docker targets build and Compose validates without publishing the reviewer port.
