---
"ssh-mcp": minor
---

Unknown command-line flags are now refused at startup instead of being silently ignored, and a likely misspelling gets a suggestion (`Unknown flag: --allowUncheckedConfigAc (did you mean --allowUncheckedConfigAcl?)`). The refusal comes before the config file is read.

**Upgrade note:** a launch command or wrapper script that passes a flag this server does not read — a typo, or a flag from another tool — previously started anyway and now exits with status 2 and names the flag. Remove or correct it; the accepted flags are the "CLI Flags (v2)" table in the README.
