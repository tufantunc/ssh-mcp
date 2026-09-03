---
"ssh-mcp": minor
---

Add bounded remote directory listing and binary-safe streaming SFTP transfers through an explicitly configured, private local transfer directory. Transfers use already-open file handles, enforce byte and operation deadlines, include both endpoints and overwrite intent in approval/audit metadata, stage uploads as mode-0600 remote files, and publish transfers atomically. No-overwrite remote publication uses the OpenSSH hardlink extension and fails closed when unavailable.
