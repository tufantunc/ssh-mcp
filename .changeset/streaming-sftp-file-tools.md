---
"ssh-mcp": minor
---

**Feature:** three streaming SFTP tools — `sftp-list`, `sftp-upload-file` and `sftp-download-file` — that move files between the remote host and local disk without their contents passing through model context ([#185](https://github.com/tufantunc/ssh-mcp/issues/185)).

`sftp-upload`/`sftp-download` carry file contents as a tool argument and a tool response, which is right for a config snippet and wrong for anything binary or large. The new tools stream instead: the response is a byte count and two paths.

They are off until `defaults.transferRoot` names a directory, and refuse with an explanation until then. That directory is the whole of their local reach, and it is verified on every call rather than at startup: `0700`, owned by this account, no group- or world-writable parent, and not overlapping the installation, the config directory, the audit log directory or `~/.ssh`. Caller paths are confined to it, symlinks are refused rather than followed, and a download is staged as a sibling `.part` and published atomically. On Windows the root cannot yet be verified private, so the two transfer tools refuse there.

Two new settings come with them, in `[defaults]` and per profile: `transferMaxBytes` (default 256 MiB) and `transferTimeoutMs` (default 5 minutes). The timeout is an **idle** budget, re-armed on progress, not a total one — so a slow transfer of a large file survives it while a stalled channel still fails within one window, and the byte cap does not have to be divided by it ([#206](https://github.com/tufantunc/ssh-mcp/issues/206)). Both are separate from `commandTimeoutMs`, so buying a transfer window no longer buys a hang budget for every shell command on the same profile.

Nothing on local disk happens before the call is authorized ([#207](https://github.com/tufantunc/ssh-mcp/issues/207)). The audited string policy evaluates is built from the remote path alone, which is validated without touching a filesystem; the staged file, the existence check and the errors that quote the operator's configuration all live after the approval. The resolved local path is appended to the audit record afterwards, and the pipeline enforces that such an append can only elaborate what was approved, never replace it.
