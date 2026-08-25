---
"ssh-mcp": patch
---

Require approval for a command this server cannot name ([GHSA-fj9r-f47j-c73x](https://github.com/tufantunc/ssh-mcp/security/advisories/GHSA-fj9r-f47j-c73x)).

`classifyCommand` decides the class — and with it whether the approval gate fires — from the literal text of the command word. When that word is a shell variable expansion, what will actually run is not knowable here, and the unresolvable word was treated as an ordinary binary: `safe`. The remote shell then expanded it and ran whatever it named.

```
S=sudo; $S id    ->  safe   (allowed, no prompt)
$S id            ->  safe
xargs $S         ->  safe
```

Measured against the compiled-in defaults on the `prod` tier — where `privileged` is granted to no role at all and `safe` to both `operator` and `admin` — that reached root with no prompt and an audit record reading `safe`.

Distinct from [GHSA-v8jh-gv7v-3gvq](https://github.com/tufantunc/ssh-mcp/security/advisories/GHSA-v8jh-gv7v-3gvq), fixed in 2.4.1, and **not** fixed by it: that one hid elevation inside a carrier — `$(...)`, backticks, `sh -c` — which is statically readable and is now read. This hides it behind a name, which is not readable at all. Resolving the variable is not available as a fix: a session run keeps the caller's shell state, so `S=sudo` and `$S id` can arrive as two separate calls, and a variable exported in the target's own profile is never visible to this process.

So the classifier now says what it knows. A segment whose command word carries `$` or a backtick is classified `destructive` — not `privileged`, because this is "cannot tell" rather than "this is root". It requires approval instead of refusing outright, which keeps `$PREFIX/bin/tool` usable.

**One behaviour change worth planning for.** Only the command word counts, never the arguments, so `echo $HOME` and `grep $PATTERN file` are untouched. But a command whose *name* comes from a variable now needs the `destructive` class on the tier. Under the default rules that means such a command is refused for `operator` on `prod` where it previously ran, and prompts for `admin`. If a deployment runs `$PREFIX/bin/...` on production under an operator role, grant that role `destructive` on the tier or spell the path literally.
