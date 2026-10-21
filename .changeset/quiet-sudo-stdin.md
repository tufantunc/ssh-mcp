"ssh-mcp": patch
---

`privileged-command`: harden how the sudo password reaches sudo, and always scrub the configured sudo password from command output. The wrapped command now runs with stdin at EOF; approval prompts and audit records show `exec 0</dev/null;` inside the wrapped `sudo … sh -c` string.
