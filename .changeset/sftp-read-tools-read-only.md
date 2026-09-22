---
"ssh-mcp": minor
---

**Fix:** `sftp-list` and `sftp-download` are usable on a `readOnly` profile, which is what they already advertised ([#217](https://github.com/tufantunc/ssh-mcp/issues/217)).

Both carry `readOnlyHint: true` and the README marks both read-only, but neither classified `read-only`, so both fell through to `safe`. A profile with `readOnly = true` refuses `safe` outright, so the one tool whose annotation targets that profile class was the one tool that profile class could not run. A `viewer` role bound to `read-only` hit the same wall. It failed safe, never open — but an operator reading the docs got a refusal the docs do not explain.

Lowering a class is a widening, so it needs an argument: **this grants a `readOnly` profile nothing it did not already hold.** `cat /etc/shadow` and `ls /root` classify `read-only` today, so the authority to read any file the SSH user can read is already granted.

**Minor rather than patch**, because three things now refuse input that 2.9.1 accepted.

### `sftp:` and `session:` are now a reserved command namespace

`run-command` and `read-command` refuse a command whose first word begins `sftp:` or `session:`, in any quoting. The classifier cannot tell a string this server synthesises from one a caller typed, so giving `sftp:list` a read-only class also taught `read-command` to accept it — a `readOnly` viewer could send `read-command "sftp:list /tmp sudo id"` and it ran. Reserving the namespace also makes an `sftp:*` audit record provably tool-generated, where before a forged one was identical in every field.

### `sftp-upload` and `sftp-download` validate their remote path

Both interpolated the caller's raw path into the string policy classifies, a human approves, and the hash-chained audit record stores; `synthetic: true` skips `sanitizeCommand`, so nothing refused a bidirectional override or a zero-width space. They now hold the streaming tools' bar: `sanitizeRemotePath` as a `preCheck`, inside the pipeline, so a refused call still leaves an audit record.

Newly refused on these two tools: an empty path, a path over 4096 characters, a path that begins or ends with whitespace, and a path carrying a control, bidirectional or zero-width character. The `sftp-download` half follows from the lowering — that is what would have opened the sink to every `readOnly` profile. The `sftp-upload` half does not: it keeps its `destructive` floor, so no new profile class reaches it. It was hardened alongside for parity, not because #217 exposed it.

### Zero-width joiners are no longer refused

`sanitizeRemotePath` swept up U+200C and U+200D with the rest of the zero-width block when it shipped in 2.9.0, which refused real filenames — ZWNJ and ZWJ are orthographically required in Persian and the Indic scripts and structural inside an emoji sequence. They are accepted now. U+200B, the BOM and the bidi controls stay refused: those are invisible *and* meaningless, which is what makes two different paths render identically.

### Under the hood

The lowering is expressed as its own set rather than as two more entries in the read-only allowlist, because that allowlist is dual-purpose: `operandsAreData` reads it too, and putting the verbs there switched the interpreter-carrier scan off for them — measured, `sftp:list /tmp sh -c 'sudo id'` fell from `privileged` to `read-only`, `sh -c` being the one carrier form that carries no shell metacharacter.

Still true and unchanged: a path carrying a shell metacharacter drops back to `safe`, a path carrying a command is raised by what it carries, and `sftp-upload`, `sftp-upload-file` and `sftp-download-file` remain `destructive`.
