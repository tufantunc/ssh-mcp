---
"ssh-mcp": patch
---

Announce the tool to the host on every exec channel as `AI_AGENT=ssh-mcp`, so operators can tell agent-driven sessions from human ones on the host. Inert unless the host sets `AcceptEnv AI_AGENT`; no version is sent.
