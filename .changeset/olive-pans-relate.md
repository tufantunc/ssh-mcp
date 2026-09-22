---
"ssh-mcp": minor
---

`sftp-upload`'s approval prompt and audit record now describe what it does, not only where it does it: `sftp:upload --overwrite --bytes=142 --sha256=<32 hex> /etc/crontab`.

The tool has always replaced an existing file at that path unconditionally, while its sibling `sftp-upload-file` refuses unless you pass `overwrite: true` and spells `--overwrite` into its own string. `sftp-upload` named a destination and no effect, and said nothing at all about the bytes — it takes its content as an argument rather than naming a local file — so two different uploads to one path produced one string. One thing for the approver to decide, one entry for an approval grant to key on, one indistinguishable audit record.

No behaviour change: the same uploads still succeed and still replace.

**If you write your own `[policy].denylist`, check it.** Patterns are matched against the whole approved string, and that string changed. A rule anchored on the path still works — the path deliberately comes last — but a rule anchored on the whole string, such as `^sftp:upload /root/.*$`, silently stops matching and the refusal degrades to an approval prompt with no warning. Anchor on the path segment instead. The same applies to a Rego rule matching the full `input.resource.command`. Minor rather than patch for this reason: a denylist that refused yesterday can prompt today.

Approval grants are per-process and in-memory, so an upgrade clears them regardless; there is nothing to re-approve that a restart would not have re-asked anyway.
