---
"ssh-mcp": patch
---

`sftp-upload`'s approval prompt and audit record now describe what it does, not only where it does it: `sftp:upload /etc/crontab --overwrite --bytes=142 --sha256=9f86d081884c`.

The tool has always replaced an existing file at that path unconditionally, while its sibling `sftp-upload-file` refuses unless you pass `overwrite: true` and spells `--overwrite` into its own string. Both rendered the same way, so an approver was shown a string that means "will not clobber" on one tool while approving an unconditional replacement on the other — with content that appeared nowhere, since `sftp-upload` takes its bytes as an argument rather than naming a local file. Approval grants key on that string, so one approval covered two different uploads to the same path.

No behaviour change: the same uploads still succeed and still replace. What changes is the string, which means an existing approval grant for an `sftp-upload` no longer matches and will be asked for again.
