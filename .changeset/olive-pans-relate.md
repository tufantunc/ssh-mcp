---
"ssh-mcp": minor
---

`sftp-upload`'s approval prompt and audit record now describe what it does, not only where it does it: `sftp:upload /etc/crontab --overwrite --bytes=142 --sha256=<32 hex>`.

The tool has always replaced an existing file at that path unconditionally, while its sibling `sftp-upload-file` refuses unless you pass `overwrite: true` and spells `--overwrite` into its own string. `sftp-upload` named a destination and no effect, and said nothing at all about the bytes — it takes its content as an argument rather than naming a local file — so two different uploads to one path produced one string. One thing for the approver to decide, one entry for an approval grant to key on, one indistinguishable audit record.

No behaviour change: the same uploads still succeed and still replace.

**If you write your own `[policy].denylist`, check it.** The approved string is longer than it was, so any pattern anchored on the end — `authorized_keys$`, `^sftp:upload /etc/sudoers$` — stops matching and the rule silently stops firing, falling back to an approval prompt instead of a refusal. Nothing warns you. Drop the `$` or anchor on the path segment. The same applies to a Rego rule using `endswith(input.resource.command, …)`. Minor rather than patch for this reason: a denylist that refused yesterday prompts today.

Approval grants are per-process and in-memory, so an upgrade clears them regardless; there is nothing to re-approve that a restart would not have re-asked anyway.
