---
"ssh-mcp": patch
---

A fatal startup message longer than 64KB now reaches stderr in full on macOS. When stderr was a pipe, which is the case under the stdio transport, the message was cut off at 65,536 bytes. The write now continues until the whole message is out, and retries a full pipe for up to two seconds before it gives up.
