---
"ssh-mcp": minor
---

Add an optional isolated LLM command-review sidecar that can approve bounded routine operations or escalate risky and uncertain operations to a human. An LLM `deny` is a rejection recommendation with mandatory human review, while deterministic RBAC, denylist, OPA and configurable host-group freeze windows remain final. Privileged operations remain human-only.
