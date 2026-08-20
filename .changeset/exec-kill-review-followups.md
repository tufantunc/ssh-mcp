---
"ssh-mcp": patch
---

Make the stop actually verifiable: fix three ways the new kill ladder could still fail silently.

Follow-up to the [#146](https://github.com/tufantunc/ssh-mcp/issues/146) fix, from a review round on it. All three are the same shape as the bug they follow — a stop that reports success without having happened.

- **A signal could be "delivered" through a dead socket.** ssh2 hands every packet to `onWrite`, which is `if (isWritable(sock)) sock.write(data)` — an unwritable socket drops it with no error and no return value. Measured: immediately after `client.end()`, `sock.writable` is false while the channel's outgoing state is still `eof`, so every guard passed and the signal call returned without throwing. The transport is now checked before either path claims dispatch. Reachable whenever a connection is closed under a running command, including by the idle reaper.
- **A timeout that fired before the exec channel existed left the command running.** ssh2 invokes the exec callback on `CHANNEL_SUCCESS`, which OpenSSH sends *after* forking the command, and the channel open is retried up to three times before that. The caller was told the command timed out; the command then started, ran to completion, held a channel and had its output discarded. A late channel is now stopped on arrival.
- **`close-session` on a background session dropped the channel without signalling** — the rung this project measured as stopping nothing. It reported `status: "closed"` while `tail -f` kept running. It now goes through the same ladder as `exec`.

Two claims were also corrected rather than the code:

- The return value says the request was **dispatched**, not that the process stopped. SSH does not acknowledge a signal request, and the request reaches the command's session leader rather than its process group: measured, `sh -c 'trap "" INT TERM; sleep 30'` loses the shell to `SIGKILL` and leaves `sleep` orphaned. The error's wording, the span attribute and a new test all reflect that limitation instead of implying it away. `SECURITY.md` now documents the ladder, including that cancellation reaches `SIGKILL` without a separate policy check.
- The comment claiming this file's ssh2 workaround would retire itself was wrong — our own copy of ssh2's condition would keep refusing the public path even after [mscdex/ssh2#1510](https://github.com/mscdex/ssh2/pull/1510) lands, and the test meant to announce that upgrade grepped for substrings the upstream diff preserves. There is now one named predicate to widen and a tripwire that calls ssh2's real method instead of reading its source.

`ssh.unstopped` is now set on all three settle paths (both cancellation paths computed it and dropped it before the span, so it could never be true for a cancelled command), and `ssh2` is pinned to an exact version for as long as the internals workaround exists.
