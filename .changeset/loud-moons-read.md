---
'ssh-mcp': minor
---

`fix(policy)`: the command classifier reads option values and environment assignments that carry a command — `git -c`, `apt -o`, `scp -o`, `rsync --rsync-path=`, `tar --use-compress-program=` and `GIT_SSH_COMMAND`-style prefixes — whether the value is attached with `=`, quoted, or glued to its key. A command that relied on the previous default may now prompt for approval, or be refused outright under a profile that does not grant the class it earns.
