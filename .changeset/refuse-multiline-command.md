---
"ssh-mcp": patch
---

**Fix:** a `command` containing a line break is now refused instead of being silently joined into one line ([#198](https://github.com/tufantunc/ssh-mcp/issues/198)).

The constraint itself does not change — a newline inside `command` would let a second command ride along past a classifier that only parsed the first — but the enforcement does. Replacing the break with a space returned no error and ran something the caller never asked for: two lines joined, so `ls\necho x` ran `ls echo x`; or a `#` comment in a `python3 -c` body pulled onto the same line, commenting out the rest. Sometimes that raises. Sometimes it runs and quietly does half the work.

An embedded null byte is likewise named rather than turned into a space — and a command that was *only* a null byte used to be reported as empty, which was a lie about what was sent.

Leading and trailing breaks are still trimmed, so a client that appends a newline keeps working; only a break between two pieces of a command is refused. The error names `sftp-upload` as the way to run a multi-line script, and `read-command`, `run-command` and `privileged-command` now say so in their descriptions.
