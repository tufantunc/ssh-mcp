---
"ssh-mcp": patch
---

**Policy:** `sftp:upload-file` and `sftp:download-file` now carry a `destructive` floor.

Each writes a file — the first on the remote host, the second inside the operator's transfer root — but from the verb alone both classified `safe`, which is the class an `operator` binding already allows. The floor is added ahead of the tools that emit these verbs, so the authorization decision is reviewable on its own rather than arriving inside a larger change.

`sftp:list` deliberately keeps `safe`, for the same reason `sftp:download` does: a `read-only` entry would be a lowering, and lowering a class is a widening. It would also be inert, since the synthetic class can only raise.
