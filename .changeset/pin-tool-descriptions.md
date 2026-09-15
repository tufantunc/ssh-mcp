---
"ssh-mcp": patch
---

**Test:** the text of every tool description is now asserted against what a client actually receives, so a reword cannot ship unnoticed.

A description is what the model reads when deciding whether and how to call a tool, and `run-command` and `privileged-command` execute on a remote host — their wording is part of the approval surface rather than documentation about it. MCP clients ask a user to approve a server once and never re-check, so a reword changes how a remote shell gets driven for someone who approved months ago.

The tool *count* was already pinned in two places. The text was pinned nowhere that runs: the one test for it drives a tool named `exec`, the v1 name, and lives under `test/legacy/`, which vitest excludes.

No behaviour change.
