---
'ssh-mcp': patch
---

Fix an event-loop stall on remote command output, and derive session markers from a CSPRNG.

- **Interactive session output could stall the whole server.** Trailing newlines
  were trimmed with `/\n+$/`, which is unanchored at the start: on output that is
  mostly newlines but does not end in one, the regex engine retries from every
  offset. The session buffer holds up to 2 MB of whatever the remote command
  printed, where that measured at roughly 25 minutes of blocked event loop —
  shared by every session and connection the server has open. Trimming is now
  done by index.

- **Session markers came from `Math.random()`.** Markers separate a command's
  output from the trailer carrying `$?` and `$PWD`, so predicting one is enough
  to forge an exit code or working directory — a failed command recorded as
  successful. Every marker is written to the remote host in the clear, and
  `Math.random()` is reconstructible from observed output. They now come from
  `crypto.randomBytes`.

- **Denylist patterns no longer depend on a distant length cap.** The forbidden
  patterns for `curl … | sh`, `wget … | sh`, `dd … of=/dev/…` and `chown -R … /`
  paired `\s+` with `.*`, letting both claim the same run of spaces. Reaching
  them requires passing `sanitizeCommand`, which caps commands at
  `profile.maxChars` (5000 by default), so this was not exploitable at stock
  settings — but that limit is configurable to any value and lives three layers
  away. The patterns match the same commands as before, which is covered by
  tests.
