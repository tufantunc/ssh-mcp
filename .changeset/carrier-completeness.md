---
"ssh-mcp": minor
---

A command handed to a binary this classifier does not recognise could carry an elevated command through as `safe` — the one class that runs on `run-command` with no approval prompt, whatever the role or approval policy. That gap is now closed: an operand of an unrecognised binary that nothing more specific has already read is classified as a command in its own right, so an elevation it carries is found and the command classifies `privileged` like any other.

This does mean a command that used to run silently can now prompt for approval or be refused outright under a profile that does not grant `privileged`. The one case worth knowing about ahead of time: classification looks at the *first word* of an operand, so `git commit -m "sudo fix the thing"` now classifies `privileged` and needs approval, where `git commit -m "fix the sudo thing"` still classifies as it always did. If a `run-command` you relied on starts asking for approval, check whether a commit message, comment, or similar free-text argument happens to start with `sudo`, `doas`, `pkexec`, or `su`.

The interpreter table also gains `osascript`, `lua`, `Rscript`, `bun`, `tclsh`, `deno eval`, and `pwsh`/`powershell`, so a program handed to one of them now classifies the same way a program handed to `python3 -c` or `node -e` already did. `pwsh -EncodedCommand`'s base64 payload is decoded so what it carries is classified rather than merely counted as opaque.

`tclsh` carries no `-c` entry: a differential fuzz run against this branch found that `tclsh -c 'exec systemctl stop nginx'` had been classifying `destructive` on the strength of a `-c` flag real `tclsh` does not have — it takes a script file or reads one from stdin, the same as every other interpreter in the table without an inline-program flag. That invocation now classifies `safe`, correctly: `tclsh` is still a recognised, unreadable interpreter, so `echo … | tclsh` (the genuine carrier, a program on stdin) still classifies `destructive`.

A command whose effective command word resolves to this table is also now a *certain* carrier for the one unconditional denylist (`shutdown`, `reboot`, `halt`, `poweroff`, `eval`, and the never-allowed patterns), not merely for its class. Previously, a value-taking option of the interpreter's own — `bash -o pipefail -c '…'`, `python3 -W ignore -c '…'`, `perl -I /tmp -e '…'`, `bash --rcfile /tmp/x -c '…'` — sat between the interpreter and its program flag and made the payload invisible to that denylist scan specifically, even though the command still classified `destructive` through the ordinary path. Those forms now deny outright, like the canonical `sh -c '…'` spelling already did. This does not widen the denylist to unrecognised binaries: `whatever -o pipefail -c 'shutdown -h now'` still only reaches `destructive`, not an unconditional deny — the class it already had before this change.

Reported by @MartOcd1709.
