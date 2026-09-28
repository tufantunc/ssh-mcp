---
"ssh-mcp": minor
---

Policy: command classification reads a command under both shell dialects a target host may run — POSIX and cmd.exe — and holds it to the stricter reading when they disagree, instead of assuming the POSIX one. Path stripping now accepts backslash-separated command words, and quote removal inside double quotes follows POSIX byte for byte (a backslash before an ordinary character is kept). Commands without a backslash classify exactly as before. One deliberate change within that: a name written inside quotes with backslashes keeps its bytes now and classifies as the name a shell would actually pass in argv, where before the backslashes were silently removed.
