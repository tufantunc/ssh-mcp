---
"ssh-mcp": patch
---

**Fix:** `sftp-list` and `sftp-download` are usable on a `readOnly` profile, which is what they already advertised ([#217](https://github.com/tufantunc/ssh-mcp/issues/217)).

Both carry `readOnlyHint: true`, `sftp-list`'s description ends "Read-only.", and the README marks both read-only — but neither classified `read-only`, so both fell through to `safe`. A profile with `readOnly = true` refuses `safe` outright, so the one tool whose annotation targets that profile class was the one tool that profile class could not run. A `viewer` role bound to `read-only` hit the same wall.

It failed safe, never open, so nothing was exposed — but an operator reading the docs got a refusal the docs do not explain.

Lowering a class is a widening, so it needs an argument rather than a shrug: **this grants a `readOnly` profile nothing it did not already hold.** `cat /etc/shadow` and `ls /root` classify `read-only` today, so the authority to read any file the SSH user can read is already granted. These two reach it through SFTP instead of a shell.

The lowering is expressed as its own set rather than as two more entries in the read-only allowlist, because that allowlist is dual-purpose: `operandsAreData` reads it too, to decide whether a segment's operands are data rather than commands. Putting the verbs there switched the interpreter-carrier scan off for them — measured, `sftp:list /tmp sh -c 'sudo id'` fell from `privileged` to `read-only`, because `sh -c` is the one carrier form that carries no shell metacharacter and so is the one the scan is load-bearing for. Separating the two consumers restores every affected decision to what it was.

**Also fixed, because this is what would have exposed it:** `sftp-upload` and `sftp-download` interpolated the caller's raw remote path into the string that policy classifies, that a human approves, and that goes into the hash-chained audit record. `synthetic: true` skips `sanitizeCommand`, so nothing refused a bidirectional override or a zero-width character in a path that is quoted back in all three places. Both now hold the same bar as the streaming tools: `sanitizeRemotePath` as a `preCheck`, inside the pipeline, so a refused call still leaves an audit record. The sink predates this change; lowering `sftp:download` is what would have opened it to every `readOnly` profile rather than only to roles holding `safe`.

A remote path that begins or ends with whitespace, or carries a control, bidirectional or zero-width character, is now refused by `sftp-upload` and `sftp-download` as it already was by the streaming tools.
