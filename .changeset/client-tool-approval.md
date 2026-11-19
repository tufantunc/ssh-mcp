---
"ssh-mcp": minor
---

New approval mode for MCP clients that cannot show an elicitation prompt: `approvalPolicy = "client-tool"`. Under the `ask-*` modes such a client never gets to answer, so every destructive and privileged command fails with `APPROVAL_UNAVAILABLE`, and the only way through was `auto`. Under `client-tool` the client's own tool-call consent prompt is the approval. A destructive or privileged command on `run-command` is refused with `APPROVAL_VIA_TOOL` and pointed at the new `destructive-command` tool. That tool, `privileged-command`, `signal-process`, `open-session` and the `sftp-*` transfer tools run gated commands without elicitation, audited as `approver: "client-tool-consent"`. Role bindings, host groups, the denylist, OPA and quotas apply unchanged. `destructive-command` behaves exactly like `run-command` under every other policy. Opt-in and weaker than elicitation: "Always allow" on `destructive-command` in the client makes the profile behave like `auto`.
