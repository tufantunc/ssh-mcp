---
"ssh-mcp": minor
---

`sort --compress-program=<path>` no longer classifies `read-only`.

GNU sort runs that program for every temporary file it spills, so a reader becomes a launcher. `sort` is on the read-only allowlist, so the whole command classified `read-only` — the one class a `readOnly` profile permits — and a viewer could run an arbitrary program through `read-command` while running that same program directly was refused.

It now classifies `destructive`, through `DISQUALIFYING_ARGS`, the table that already held `find`'s `-exec` family for the same reason. Ordinary sorting is unaffected: `sort -u`, `sort -k2 -n`, `sort --reverse` and a filename that merely contains the word all stay `read-only`.
