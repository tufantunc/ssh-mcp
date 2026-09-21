---
"ssh-mcp": patch
---

**Fix:** `sftp-list` and `sftp-download` are usable on a `readOnly` profile, which is what they already advertised ([#217](https://github.com/tufantunc/ssh-mcp/issues/217)).

Both carry `readOnlyHint: true`, `sftp-list`'s description ends "Read-only.", and the README marks both read-only — but neither was on the classifier's read-only allowlist, so both fell through to `safe`. A profile with `readOnly = true` refuses `safe` outright, so the one tool whose annotation targets that profile class was the one tool that profile class could not run. A `viewer` role bound to `read-only` hit the same wall.

It failed safe, never open, so nothing was exposed — but an operator reading the docs got a refusal the docs do not explain.

Lowering a class is a widening, so it needs its own argument rather than a shrug: **this grants a `readOnly` profile nothing it did not already hold.** `cat /etc/shadow` and `ls /root` classify `read-only` today, so the authority to read any file the SSH user can read is already granted. These two reach it through SFTP instead of a shell, which is *narrower* — no shell parses the path.

Both guards that stood before still stand, and each is now pinned by a test that fails without it: a path carrying a shell metacharacter drops back to `safe` even when it starts no second command, and a path carrying an actual command is raised by the class of what it carries. `sftp-upload`, `sftp-upload-file` and `sftp-download-file` are untouched — each writes, so none is a read.
