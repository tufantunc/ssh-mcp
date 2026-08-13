---
"ssh-mcp": patch
---

Make command classification linear, so an unbounded command cannot stall the server.

Four of the fourteen never-allowed patterns were quadratic: `dd\s.*\bof=/dev/`, the two `curl`/`wget` pipe-into-shell forms, and `chown\s+-R\s.*\s/\s*$`. Each has a cheap literal head, so the engine matched it at O(n) offsets and dragged a `.*` or `[^|]*` across the remainder from each one. A command built by repeating those literals cost 255 ms at 64 KB and **65 seconds at 1 MB**, all of it blocking the single-threaded event loop.

The stall sits inside `classifyCommand`, which runs *before* the approval gate and before the allow/deny decision — so `approvalPolicy = "ask-all"`, `role = "viewer"` and `readOnly = true` gave no protection. One `run-command` call was enough to stop every other profile, session and in-flight command on the server.

The four are now segment checks over the same tokenizer that already decides power-state invocations: split on shell separators, read the head binary past any `sudo`, and look at its arguments. Nothing there can backtrack. The same 1 MB command now classifies in 45 ms, and behaviour is unchanged — `curl x | sh`, `dd if=x of=/dev/sda`, `chown -R root:root /` and the rest are refused exactly as before, while `curl http://x/data.json`, `dd if=/dev/zero of=/tmp/scratch` and `chown -R app:app /srv/app` still are not.

`classifier.ts` predicted this in writing: *"a policy check should not depend on a limit set three layers away and configurable to any value."* Until now `sanitizeCommand`'s `maxChars` was that limit and the default 5000 kept the cost invisible. Letting a config file say `commandMaxChars = 0` removed it, which is what turned a latent property into a reachable one. The check no longer depends on it either way.

Also in this change: `[defaults].commandMaxChars = 0` is now mapped to the same sentinel as the per-profile `maxChars`, so no literal `0` survives anywhere in the resolved config — a value that would otherwise reject every non-empty command if any caller copied it into a profile. And the README's annotated production profile no longer demonstrates the uncapped spelling on a host it calls `prod-web-1`; the `[defaults]` line documents it instead.
