---
"ssh-mcp": patch
---

**Fix:** an awk program that starts a process or writes a file is no longer classified `safe` ([#184](https://github.com/tufantunc/ssh-mcp/issues/184)).

Split out of GHSA-qvx5-rxrj-9vfh, whose fix shipped in 2.6.0 and deliberately left awk out. Until now `awk 'BEGIN{system("sudo id")}'` ran with no approval prompt for any role holding `safe`, and `awk 'BEGIN{print "…" > "/root/.ssh/authorized_keys"}'` reached `authorized_keys` without a shell or a `system()` call at all.

Five forms are closed: `system()`, a command piped out of `print`, a command piped into `getline`, output redirection, and a program that pipes its output *into* an interpreter — the awk spelling of `echo "sudo id" | sh`, which this repo already gated at the shell level. The first three are handed to the classifier and come out as *what they actually run* — `awk 'BEGIN{system("sudo id")}'` is `privileged` and its audit record names `id`, rather than being flattened to "an awk program did something". Redirection is `destructive`, except to `/dev/stdout`, `/dev/stderr` and `/dev/null`, which scripts write to routinely.

Two review rounds had produced five attempts at this, each holed by the next, and both root causes were structural:

- **awk's program is a positional operand, not a flag's value.** There is no `-c` to prove awk was invoked rather than named, so keying on any word that said "awk" made `readlink -f /usr/bin/awk` and `man awk` destructive. The evidence is now that awk is the segment's *command word*.
- **The four implementations disagree about which flags consume a value.** gawk consumes for `-i` and `-W`, mawk rejects `-i`, and BWK awk — `awk` on macOS, the BSDs and Debian's `original-awk` — ignores an unknown option *without* consuming it and runs the next operand as the program. Only the three flags all four agree on are skipped; any other flag makes the program's position unknowable, and that is reported rather than guessed. `-f progfile` is unreadable for the same reason `python3 -c` is.

String escapes are decoded the way awk decodes them, including `\ddd` and `\xhh`, because those change which bytes reach the shell: `system("\163udo id")` runs `sudo id`, and the raw spelling also slips past the never-allowed list, which matches on the text as sent. A command assembled from concatenated literals, or from anything that is not a single literal, is reported as unreadable rather than classified from the half that can be read.

The escapes are found by reading the program under awk's own grammar rather than by pattern. That is what separates `awk 'NR>1'` from `awk '{print $1 > $2}'` — the `>` is a redirection only while an unparenthesised output statement is open, which is awk's rule and why `print (a>b)` needs its parentheses. Three of the five earlier holes were in a regex approximating that, and a fourth was the quadratic backtracking the approximation needed: 192KB of `print` tokens cost 8.7s inside the policy gate. The reader is a single pass with no backtracking, and the same seed is now a test.

One shared fix came with it: the shell tokenizer dropped a quoted empty word, so `awk -F '' 'program'` arrived one argument short. Any reader that works by position — this one does — then consumes the program as the flag's value. A quoted empty word is now preserved.

Ordinary awk is unaffected: `awk '{print $1}'`, `awk -F: '{print $1}'`, `awk 'NR>1'`, `awk '$1 == "root"'`, `df -h | awk '{print $5}'` and the rest of the set that broke the earlier attempts all stay `safe`.
