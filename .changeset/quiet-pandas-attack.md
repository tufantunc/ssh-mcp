---
"ssh-mcp": minor
---

`run-command`, `read-command`, `privileged-command` and both session types now send `AI_AGENT=ssh-mcp` to the host, so an operator can tell an agent's session from a person's. The variable appears in the session only on a host whose `sshd_config` has `AcceptEnv AI_AGENT`; everywhere else the session is unchanged.

The request itself goes to every host regardless, so a host you do not control learns that an agent is driving. The new profile field `announceAgent = false` turns it off per host. Minor rather than patch because of that field: it is new configuration, and a release that adds one is not a fix.
