---
"ssh-mcp": patch
---

Stop a timed-out or cancelled command on the host, instead of only reporting that we did.

Reported as [#146](https://github.com/tufantunc/ssh-mcp/issues/146). `exec` closes stdin as soon as the command is dispatched, because a command that reads stdin would otherwise wait for input nobody will send. ssh2's `Channel.signal()` writes the request only while the channel is `writable` and its outgoing state is `open`, and closing stdin clears both — without throwing or reporting anything. So every signal sent to stop a command was discarded inside ssh2, and the command ran to completion on the host while the caller was told it had timed out.

Measured against OpenSSH 10.3p1, one channel per row, a 30-second `sleep` as the victim:

| what the client did | at +4s | at +9s |
| --- | --- | --- |
| `end()`, then INT / TERM / `close()` — the shipped behaviour | alive | alive |
| INT / TERM without closing stdin first | gone | gone |
| `end()`, then `close()` and no signal | alive | alive |
| `end()`, then the signal sent past ssh2's check | gone | gone |

Two things follow. A delivered signal is the only thing that stops a non-tty command — closing the channel does not, for the same reason killing a local `ssh host 'sleep 30'` leaves the sleep running. And this was never visible in the error: the message said "timed out" and was correct about the timeout.

**Cancellation was affected too**, which the report did not mention: the same closed stdin sits in front of the abort handler, so a command an operator explicitly cancelled also kept running. For a server whose job is to gate what an agent may run, "stopped" is a claim it makes on every timeout and every cancellation, and it was not true for either.

The signal now goes out past ssh2's check, so the fix needs no upstream release ([mscdex/ssh2#1510](https://github.com/mscdex/ssh2/pull/1510) is the proper repair, and ssh2 releases roughly annually). The escalation gained a rung: `INT`, `TERM`, `KILL`, then drop the channel — the old last rung was `close()`, which was measured to stop nothing, so a command ignoring the first two signals used to run forever.

`KILL` never being deliverable would now be said out loud rather than assumed: if no signal reaches the wire, the error adds *"The remote command could not be signalled and may still be running on the host."* That should be unreachable today; it exists so that a future ssh2 which moves what this depends on brings back a visible failure rather than a silent one.

Interactive sessions were never affected — they write `^C` into a live pty and do not close stdin while a command runs.
