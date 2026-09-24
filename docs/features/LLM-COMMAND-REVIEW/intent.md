---
feature: LLM-COMMAND-REVIEW
stage: intent
status: accepted
branch: feat/llm-command-review
---

# Intent: add contextual safety review before non-read-only remote operations

## Problem

The existing authorization path applies deterministic classification, role policy,
external policy and human approval, but frequent prompts make routine remote operations
expensive. Operators need a contextual reviewer to make most bounded decisions itself,
while deterministic permissions continue to cap what any reviewer may authorize.

## Proposed outcome

Operators can optionally enable a contextual reviewer for non-read-only operations. Inside
the envelope allowed by deterministic policy it may approve routine operations, deny risky
ones, or escalate uncertain cases. Human review is reserved for escalation and explicitly
human-only classes. Configured production freeze windows remain hard denials.

## Affected users and systems

- Operators running ssh-mcp against development, staging or production profiles.
- Humans approving remote commands and file-transfer operations.
- The command authorization, approval, audit, observability and container deployment paths.

## Constraints

- Deterministic denials remain final and are evaluated before contextual review.
- Reviewer failure escalates rather than silently restoring automatic execution.
- Deterministic policy identifies the maximum authority and reviewer-bypassable soft
  approvals; privileged operations remain human-only.
- Command secrets must be redacted before leaving the ssh-mcp process.
- Read-only operations and the non-refusable session-release path retain their current behavior.
- Existing deployments remain unchanged unless the reviewer is explicitly enabled.
- The reviewer receives no SSH credentials, command input, command output or file content.

## Out of scope

- Allowing contextual review to override a deterministic denial.
- Allowing contextual review to authorize privileged operations.
- Reviewing read-only operations, command output, uploaded content or user intent.
- Reviewer caching, retries, shadow mode, model tools or service-to-service authentication.
- Replacing the existing classifier, role policy or OPA integration.

## Open questions

None.
