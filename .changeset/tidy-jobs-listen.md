---
'ssh-mcp': patch
---

Reading a live session now counts as activity.

`lastActivity` only moved when the channel produced a byte, so a background
command whose output is redirected to a file — the normal way to run a long job
— froze its idle clock at creation. A caller polling such a session every minute
was indistinguishable from one that had walked away, and the idle reaper closed
the session (and signalled the command) at exactly the timeout: measured at
10m22s and 10m56s against a real host with the default 10-minute TTL, while the
job was being read every 90 seconds.
