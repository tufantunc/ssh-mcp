---
"ssh-mcp": minor
---

A command handed to a binary this classifier does not recognise could carry an elevated command through as `safe` — the one class that runs on `run-command` with no approval prompt, whatever the role or approval policy. That gap is now closed: an operand of an unrecognised binary that nothing more specific has already read is classified as a command in its own right, so an elevation it carries is found and the command classifies `privileged` like any other.

This does mean a command that used to run silently can now prompt for approval or be refused outright under a profile that does not grant `privileged`. The one case worth knowing about ahead of time: classification looks at the *first word* of an operand, so `git commit -m "sudo fix the thing"` now classifies `privileged` and needs approval, where `git commit -m "fix the sudo thing"` still classifies as it always did. If a `run-command` you relied on starts asking for approval, check whether a commit message, comment, or similar free-text argument happens to start with `sudo`, `doas`, `pkexec`, or `su`.

The interpreter table also gains `osascript`, `lua`, `Rscript`, `bun`, `tclsh`, `deno eval`, and `pwsh`/`powershell`, so a program handed to one of them now classifies the same way a program handed to `python3 -c` or `node -e` already did. `pwsh -EncodedCommand`'s base64 payload is decoded so what it carries is classified rather than merely counted as opaque.

Reported by @MartOcd1709.
