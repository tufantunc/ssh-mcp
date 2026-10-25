---
"ssh-mcp": minor
---

`fix(policy)`: the command classifier reads a command word the same way whether it carries a directory part, a Windows executable suffix or a different case, and reads past the words an exec wrapper takes before the command it runs, using each wrapper's own options. Where those words can be read more than one way, the strictest reading decides. A command that relied on the previous defaults may now prompt for approval, or be refused outright under a profile that does not grant the class it earns. `command -v NAME` and `command -V NAME` are read as the lookups they are and no longer take the class of `NAME`.
