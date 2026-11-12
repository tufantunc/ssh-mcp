---
'ssh-mcp': minor
---

Add `commandOutputTruncation` so operators can keep the tail of a command's output. `[defaults] commandOutputTruncation = "head" | "tail"` (per-profile `outputTruncation`) chooses which end survives `commandMaxOutputBytes`. `"tail"` keeps the most recent bytes, so a `grep` over a large log no longer returns only the oldest matches; the default `"head"` preserves existing behaviour byte-for-byte.
