---
'ssh-mcp': patch
---

Re-establish the connection when opening a session or exec channel, instead of retrying a dead one.

Channel opens run under `openWithRetry`, but the callbacks reached for the SSH
client directly. `openSession` checks the link first, so an already-dead
connection is rebuilt there — the gap is a link that dies *after* that check,
while the channel is opening. Every retry then called `getClient()` on a null
client and threw the same `SSH connection not established`, so the retry re-ran a
dead connection three times and gave up.

Dropbear drops the whole connection under channel churn rather than refusing the
individual channel, so it hits this readily; any server that closes connections
under load can. `SftpClient` already re-established inside its retry — the
session and exec paths now do the same.
