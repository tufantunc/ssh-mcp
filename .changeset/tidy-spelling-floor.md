---
"ssh-mcp": patch
---

`fix(policy)`: the never-allowed rules read the operation rather than one spelling of it — flag clusters in either order, separated flags and long forms, root targets that resolve to `/`, world-writable modes beyond the literal `777`, the `-t`/subcommand device formatters, the firewall policy spelling, and the same operations behind a wrapper's own operands. A mention of a forbidden phrase is no longer refused as though it were an invocation.
