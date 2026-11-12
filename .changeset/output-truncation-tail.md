---
'ssh-mcp': minor
---

Add `commandOutputTruncation` so operators can keep the tail of a command's output. `[defaults] commandOutputTruncation = "head" | "tail"` (per-profile `outputTruncation`) chooses which end survives `commandMaxOutputBytes`. `"tail"` keeps the end of the output, starting at the first whole line, so a `grep` over a large log no longer returns only the oldest matches; the default `"head"` keeps today's behaviour unchanged.
