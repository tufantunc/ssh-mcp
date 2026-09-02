---
"ssh-mcp": minor
---

The remaining findings from the source review behind GHSA-qvx5-rxrj-9vfh, none of them
exploitable on their own.

**The fork-bomb rule tolerates the spacing bash tolerates.** The pattern allowed whitespace
around the braces but not at the five positions bash also allows it — before the parentheses,
inside them, either side of the pipe, and before the ampersand — so `: () { : | : & } ; :`
ran and classified `safe` while `:(){ :|:& };:` was refused.

Three spellings still escape, named here rather than implied away: the same bomb under
another name (`f(){ f|f& };f`), a body separating the two calls with `&` or `;` instead of
`|` (`:(){ :&:& };:`), and a comment between the tokens. The first needs a backreference
over an unbounded body and this file has already shipped one ReDoS; the others would widen
a list no role, tier or approval mode can override. The impact is a denial of service
against the target host rather than against this server, which is why neither trade is
worth making — but this is a narrower hole, not a closed door.

**`--opaFailClosed`.** When `--opaUrl` is set and the sidecar is unreachable, evaluation
falls back to the local decision and logs one warning per minute. That stays the default —
OPA is an additional deny layer, and an outage that stopped all work would be a worse
failure than one that narrows the policy. But an operator who deployed OPA *as* the
authorization gate loses it during an outage, with the only signal on a stderr stream MCP
clients usually discard. The new flag makes the gate being down mean no. The refusal
carries `ruleId: "opa-unavailable"` rather than `"opa"`, so an audit record says the gate
was down instead of implying a policy refused the command.

A 200 that carries no boolean `result` counts as unavailable, in both modes. That is what
OPA answers for an undefined document, so a misnamed package or an unactivated bundle is
the ordinary way an OPA gate is down while the process is still listening — and reading it
as consent meant the flag missed exactly the case operators buy it for. The default mode
warns there too now, where a permanently broken bundle used to log nothing at all. The
request is bounded at two seconds: a sidecar that accepts the connection and never answers
used to hold every tool call for undici's five-minute timeout. `--opaUrl` written with a
space, and `--opaFailClosed` given without a URL, are refused at startup rather than
silently dropping the flag. And the refusal text is a fixed string — it carried the sidecar
URL, and any credential embedded in it, out to the MCP client.

**Interactive sessions are outside name-based classification, and that is now written
down.** `run-command` classifies each input on its own, but an interactive session keeps
the remote shell's state, so `alias ls='sudo id'` classifies `safe` and the following `ls`
classifies `read-only` and runs it. The same holds for a shell function and for a prepended
`PATH` entry. The classifier already refuses a command word containing `$` — `S=sudo` then
`$S id` — but an alias is an ordinary name and nothing about it looks wrong.

No fix is offered for that last one, because classifying harder cannot reach it: the state
is in the remote shell, not in this server. What changed instead is its reachability —
opening an interactive session became `destructive` in 2.6.0, so under the default rules
`operator` cannot open one on `prod` at all where before it was `safe`. SECURITY.md now says
so, and says that `ask-all` is the control that covers the second call as well as the first.
