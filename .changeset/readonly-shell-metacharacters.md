---
'ssh-mcp': patch
---

**Security.** Treat every shell metacharacter as disqualifying when deciding whether a command is read-only.

The gate that decides whether an allowlisted binary counts as `read-only` tested
only `>`, `;` and `|`. Command substitution — `$(...)` and backticks — was not in
that set, so a command like `ls $(...)` was classified read-only, accepted by
`read-command`, and expanded by the remote shell, which ran the inner command.
The `read-command` tool is what the `viewer` role is restricted to, so its
read-only guarantee could be escaped.

The gate now rejects every character with syntactic meaning to a shell —
`; & | < > \` $ ( ) { }` and newlines — rather than enumerating dangerous
constructs, which is a list that is never finished.

**Behaviour change:** commands using shell syntax are no longer classified
read-only even when the binary is allowlisted. `echo $HOME` and `ls | grep x` now
fall to the `safe` class, which `read-command` refuses and `run-command` accepts
under the profile's approval policy. If you granted a client standing permission
for `read-command`, that permission is now narrower — which is what it was
supposed to be.

Reported privately. Upgrading is recommended for anyone relying on the `viewer`
role or on `read-command` as a security boundary.
