---
"ssh-mcp": patch
---

Verify the stop instead of assuming it — and audit the one path that signals a host without a record.

Follow-up to the [#146](https://github.com/tufantunc/ssh-mcp/issues/146) fix, from two review rounds on it. Every item is the same shape as the bug it follows: a stop that reports success without having happened.

**A signal could be reported as delivered through a socket ssh2 will not write to.** ssh2 hands every packet to `onWrite`, which is `if (isWritable(sock)) sock.write(data)` — a socket that fails that check drops the packet with no error and no return value. The transport is now checked before either path claims dispatch, using all three of `isWritable`'s conjuncts rather than only `sock.writable`: measured, a half-open socket sits at `writable = true` while `isWritable()` is false, indefinitely, and a ProxyJump connection's transport is exactly that case because ssh2's channels default to `allowHalfOpen`. An unreadable transport now fails closed.

**A timeout that fired before the exec channel existed left the command running.** ssh2 invokes the exec callback on `CHANNEL_SUCCESS`, which OpenSSH sends *after* forking the command, and the channel open is retried up to three times before that. The caller was told the command timed out; the command then started, ran to completion, held a channel and had its output discarded. A late channel is now stopped on arrival, and the outcome is recorded on its own span — the exec span has already ended by then, and an attribute set on an ended span is silently dropped.

**`close-session` signalled a remote process with no audit record.** Closing a background session now stops its command (INT, then TERM, then KILL) instead of only dropping the channel — which was measured to stop nothing. That turned a call that did nothing on the host into one that delivers `SIGKILL`, so it now writes an audit record naming the session's kind, and its tool description says what it does.

It is audited but deliberately **not** policy-gated. Routing it through the policy engine — the first shape of this fix — made the stop refusable: `session:close <name>` classifies as `safe`, so a `readOnly` profile, which *can* open a background session because a `tail -f` classifies `read-only`, was denied permission to close it and had no other way to stop the command until the session's 1-hour cap expired. `ask-all` prompted on every close and an exhausted `commandQuotaPerDay` wedged the profile outright. A control whose refusal mode is "the thing you asked me to stop keeps running" is worse than the unaudited stop it replaced, so the record is kept and the veto is not. The record carries `ruleId: session-release` to distinguish it from an engine decision, and its exit code distinguishes a confirmed close from one that could not be dispatched.

Two more paths reach the same escalation without a tool call — the session reaper and connection teardown — and neither is policy-checked or audited. `SECURITY.md` now lists all six triggers with what each does and does not record.

**The escalation was abandoned mid-ladder.** The rungs after the first are timers, and `SSHConnection.close()` tears the transport down as soon as its sessions are closed — so a background command that ignored `SIGINT` received nothing further and survived, which is the case `SIGKILL` was added for. Closing a background session now waits for the escalation, bounded by the ladder's own length, and skips the wait entirely when nothing was dispatched (measured: 3.5s of dead time, since no later rung can reach a transport that refused the first).

Sessions and connections now close **concurrently**. Awaiting them one at a time was measured at 10.0s for five commands that ignore `INT` and `TERM` — past Docker's 10s default stop grace, so the container was killed mid-teardown and the later sessions got no escalation at all, which is worse than before the wait existed. Shutdown also flushes the audit log first and bounds the teardown at 5s, and the compose service sets an explicit `stop_grace_period`. The session reaper now awaits its closes before the idle-connection reaper runs; firing them without awaiting tore the transport down microseconds after the first signal, discarding `TERM` and `KILL`.

## Corrections

**The process-group claim in the previous release note was wrong.** It said a signal reaches the command's session leader and orphans its children. OpenSSH answers a `signal` channel request with `killpg()` on the process group (`session.c`, `session_signal_req`), so an ordinary process tree does die — measured against 10.3p1, a shell and its child share one process group and both are gone after a single `SIGKILL` request. The "orphan" cited as evidence was debris leaked by an earlier experiment, and the test built on it was red on a clean container and green only on its second run. `SECURITY.md` states the corrected behaviour, along with the caveats that make it a server property rather than a guarantee: RFC 4254 does not specify delivery semantics, sshd refuses signal requests for forced-command and subsystem sessions, and other servers may differ.

**`SECURITY.md` also claimed `signal-process` classifies its signals as destructive.** It does not: `kill -KILL <pid>` classifies as `safe`, so `approvalPolicy = "ask-destructive"` never prompted for it. The document now says so and names the settings that do gate it. The classifier itself is unchanged in this release.

`ssh.unstopped` is set on every settle path (both cancellation paths computed it and dropped it before the span, so it could never be true for a cancelled command), the deferred case is marked `ssh.stopDeferred` rather than asserting a clean stop it cannot know about, and the signal name is a union type so a name ssh2 would reject is a compile error rather than a runtime warning that blames the wire.

`close-session`'s tool description changed, so its `--dump-tool-hashes` value changes with it — the first such change since that flag shipped. An operator pinning tool-description hashes will see `close-session` move, and that is expected here rather than a sign of tampering.
