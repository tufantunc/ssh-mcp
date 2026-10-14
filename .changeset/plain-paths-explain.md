---
"ssh-mcp": patch
---

A reader refused `read-only` because its command carries a shell metacharacter now says so (#224). The refusal used to name only the profile ("Clear readOnly on the profile"), so `sftp-list` on a path like `/srv/backup(old)` read as a profile problem; it now names the character, and for `sftp-list` and `sftp-download` says the character is in the remote path. Nothing is refused or allowed that was not before.
