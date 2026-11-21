---
"ssh-mcp": minor
---

`split --filter=COMMAND` (GNU coreutils, also installed as `gsplit`) is now read as a carrier: the command it hands to `sh -c` is classified whatever its shape, in every spelling `split` accepts — attached or detached, under any prefix from `--f` up. The command is at least `destructive`, `privileged` when the filter elevates, and the never-allowed list applies to the filter.

Upgrade note: a `split --filter` command that ran as `safe` is now asked for approval, or refused, depending on the role and tier.
