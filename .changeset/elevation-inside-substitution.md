---
"ssh-mcp": patch
---

Classify commands hidden inside a command ([GHSA-v8jh-gv7v-3gvq](https://github.com/tufantunc/ssh-mcp/security/advisories/GHSA-v8jh-gv7v-3gvq)).

`classifyCommand` decides two things at once: whether the caller's role may run the command, and whether the human approval gate fires — only `destructive` and `privileged` raise a prompt. The elevation scan reached that decision through tokens produced by splitting on `;`, `&`, `|` and whitespace, so it only ever saw the outer command. `echo $(sudo id)` tokenised to `["echo", "$(sudo", "id)"]`, `echo` was taken to be the real command, and no elevation was found — while the remote shell expanded the substitution and ran `sudo id` for real.

Measured against the compiled-in default rules, that mattered most exactly where the matrix is strictest: on the `prod` tier `privileged` is granted to **no role at all**, not even `admin`, while `safe` is granted to both `operator` and `admin`. So the bypass handed out the one class that tier withholds, with no approval prompt, and the audit record said `safe`.

The asymmetry that caused it was visible all along — `echo $(rm -rf /)` classified correctly, because the destructive scan reads the raw command text while the elevation scan read tokens.

Commands that carry other commands are now classified as the higher of the two, and the class names the inner binary so the audit record points at the process that actually runs. Four carriers are read: `$(...)`, backticks, process substitution `<(...)` / `>(...)`, and a shell invoked with `-c`.

The last of those was not in the report and does not involve substitution at all: `sh -c "sudo id"` classified `safe` for the same reason, and a fix that only parsed `$(...)` would have left it open.

Substitutions that carry nothing elevated or destructive are unchanged — `echo $(date)` stays `safe`, and arithmetic expansion is not treated as a command, so `echo $((1 + 1))` does not start raising prompts.
