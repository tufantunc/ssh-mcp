---
feature: LLM-COMMAND-REVIEW
stage: intent
status: accepted
branch: feat/llm-command-review
---

# Intent: add contextual safety review before non-read-only remote operations

## Problem

The existing authorization path applies deterministic classification, role policy,
external policy and human approval, but it cannot explain operational risks that depend
on the meaning and composition of an otherwise permitted command. Operators therefore
either allow such commands without contextual assistance or prompt for every command and
review the raw text unaided.

## Proposed outcome

Operators can optionally enable a contextual reviewer for non-read-only operations. Its
assessment is visible in the approval and audit paths, can require a human decision where
the deterministic policy would otherwise allow execution, and can never weaken an
existing restriction.

## Affected users and systems

- Operators running ssh-mcp against development, staging or production profiles.
- Humans approving remote commands and file-transfer operations.
- The command authorization, approval, audit, observability and container deployment paths.

## Constraints

- Deterministic denials remain final and are evaluated before contextual review.
- Reviewer failure cannot silently restore automatic execution.
- Command secrets must be redacted before leaving the ssh-mcp process.
- Read-only operations and the non-refusable session-release path retain their current behavior.
- Existing deployments remain unchanged unless the reviewer is explicitly enabled.
- The reviewer receives no SSH credentials, command input, command output or file content.

## Out of scope

- Allowing contextual review to override a denial or directly authorize a command.
- Letting contextual review hard-deny an operation in the first release.
- Reviewing read-only operations, command output, uploaded content or user intent.
- Reviewer caching, retries, shadow mode, model tools or service-to-service authentication.
- Replacing the existing classifier, role policy, OPA integration or human approval.

## Open questions

None.
