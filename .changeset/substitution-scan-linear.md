---
"ssh-mcp": patch
---

The classifier finds the end of every `$(…)`, `<(…)` and `>(…)` in one pass over the command. It looked for each one separately, so a command with many substitutions that never close took time in proportion to the square of its length (0.8 s for 60 KB; 0.26 s now). No class and no never-allowed answer changes.
