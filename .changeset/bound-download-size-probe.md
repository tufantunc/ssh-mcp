---
"ssh-mcp": patch
---

**Fix:** `sftp-download` can no longer hang forever on a server that accepts its size probe and never answers.

Before downloading, the tool asks the server how big the file is, so it can refuse an oversized one without transferring it. That probe was an unbounded promise with no reject path and no timeout: a server that accepted `SSH_FXP_STAT` and never replied left the tool call suspended for the life of the connection — no error, no progress, and nothing for the caller to act on. It is the same shape as the `exec` hang reported in #197, on the SFTP side.

The probe is now bounded by the profile's command timeout, which is what every other step of a tool call already answers to. A probe that expires is treated exactly as an unavailable one always was: the size is unknown, and the byte cap is enforced on the stream as it flows.
