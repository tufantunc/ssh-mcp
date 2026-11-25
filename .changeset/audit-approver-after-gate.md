---
"ssh-mcp": patch
---

The audit record of a call that fails after it was approved now names the approver. A failure from that point on, such as a connection dropping while an approved command runs or the daily quota refusing it, used to be recorded without one, although the command may already have changed the host. This applies to elicitation, `client-tool` and approval-grant approvals alike.
