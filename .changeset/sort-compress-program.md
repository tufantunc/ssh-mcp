---
"ssh-mcp": minor
---

`sort --compress-program=<path>` no longer classifies `read-only`.

GNU sort runs that program for every temporary file it spills, so a reader becomes a launcher. `sort` is on the read-only allowlist, so the whole command classified `read-only` — the one class a `readOnly` profile permits — and a viewer could run an arbitrary program through `read-command` while running that same program directly was refused.

It now classifies `destructive`, through `DISQUALIFYING_ARGS`, the table that already held `find`'s `-exec` family for the same reason. Ordinary sorting is unaffected: `sort -u`, `sort -k2 -n`, `sort --reverse` and a filename that merely contains the word all stay `read-only`.

The first version of this fix closed the four exact spellings it was written against (`-o`, `--output` and `--compress-program`, joined and separate) and left GNU sort's own option grammar open around them. Two escapes, both closed now:

- A short-option cluster is scanned left to right, and GNU sort lets any of its own *argument-less* short flags sit ahead of `-o` without consuming it — `sort -mo out in` writes `out` exactly as `sort -o out in` does. `-m` (merge) was the one argument-less flag missing from that set.
- `getopt_long` resolves a `--` word by unambiguous-prefix matching, not exact spelling: `--o`, `--ou`, `--out`, `--outp` and `--outpu` all mean `--output`, and `--co` through `--compress-progra` all mean `--compress-program`. `--c` alone is excluded on purpose — it names both `--check` and `--compress-program`, so real `sort` refuses to run rather than guess.

Every short flag and every long-option prefix is derived from `sort --help` and measured against the real binary. `sort -tofile`, `sort -t: -k2,2n`, `sort -ko`/`-So`/`-To` and `sort --c=…` are unaffected: each hands its value to a flag other than `-o`, or (for the ambiguous `--c`) never runs at all.
