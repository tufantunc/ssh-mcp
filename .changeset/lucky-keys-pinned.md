---
"ssh-mcp": minor
---

Make `--hostKeyMode=strict` work, and make `trustedHostKey` able to satisfy it.

`strict` refused every host on every connection, and had since the mode was
introduced. The store it consults is an in-memory `Map` shared by every profile,
and the only write to it is the trust-on-first-use accept at the bottom of
`verifyHostKey` — below the strict branch, so strict never reached it. Measured on
2.7.0: two consecutive calls both threw `HOST_KEY_UNKNOWN` with the store still at
zero entries, while `tofu` populated it on the first call. Since the mode is fixed
at startup, no earlier `tofu` connection could seed it either.

A pin did not rescue it. `trustedHostKey` was a reject-only gate in
`connection.ts`: it could refuse a wrong key, but a *matching* pin fell through to
`verifyHostKey` and was refused anyway for the empty store. So `strict` plus a
correct pin — the combination that reads like the secure configuration — connected
to nothing, and the refusal's own advice, "pin the key with trustedHostKey", was
the advice that did not work.

The pin is now answered in `verifyHostKey` ahead of every other branch, and it
neither reads nor writes the store. Keeping it out of the store is the point rather
than an omission: `knownHostsStore` is one `Map` for all profiles, so seeding it
from the pin — the obvious fix, and the one this replaced — made two profiles
pinning different keys for the same `host:port` produce a false
`HOST_KEY_MISMATCH` against each other's entry. A pinned host has no use for
trust-on-first-use memory; the pin already is that memory.

`strict` therefore means "every host must be pinned". That is the honest
description of what it can do while the store lives only for the process, and it is
still worth setting: it turns a missing pin into a refusal instead of a first-use
accept.

### Behaviour changes

- **A key that contradicts a pin now raises `HOST_KEY_PIN_MISMATCH`.** It was
  already refused — the old gate returned `false` — but ssh2 turned that into a
  generic handshake failure that named nothing. The refusal now names the pin as
  what decided, prints both fingerprints, and deliberately offers no mode as a way
  out, because none overrides a pin. The check still runs before the mode is
  consulted, so `insecure` does not bypass it; that ordering is preserved from the
  old gate rather than newly chosen, and losing it would have been a regression
  dressed as a cleanup.
- **A matching pin now wins over a store entry for the same `host:port`.**
  Previously it threw `HOST_KEY_MISMATCH`. Reachable with the shared store: one
  profile learns a key under `tofu`, a second profile pins a different one for the
  same host and port. This is a widening — a case that refused now connects — and
  it is intended: an explicit pin is operator configuration and a store entry is
  trust-on-first-use memory. If you were relying on the old refusal, you were
  relying on two profiles disagreeing about one host.

- **A blank `trustedHostKey` is now a startup error.** `z.string().optional()`
  accepted `trustedHostKey = ""`, and the gate that read it tested truthiness — so
  the line was inert and the operator who wrote it believed the profile was
  pinned. That is the worst outcome this field has, and it is now refused at load
  time with `trustedHostKey cannot be empty`. Surrounding whitespace is trimmed
  rather than refused, for the mirror-image reason: the comparison against the
  presented fingerprint is exact, so a trailing newline from a heredoc refused
  every key with nothing in the message pointing at the stray character. A config
  carrying a blank pin previously started and now does not.

  This one exists because the first draft of this change used `!== undefined`
  where the old gate used truthiness, which would have turned `trustedHostKey = ""`
  from inert into "refuse every host on every connection". Measured both ways.
  The runtime predicate is truthiness again, and the schema is the primary guard.

Unchanged: `strict` without a pin still refuses with `HOST_KEY_UNKNOWN`; `tofu`
learns and compares exactly as before; `insecure` without a pin still accepts
anything; and the store still does not persist across a restart, which
[SECURITY.md](./SECURITY.md#host-key-trust-does-not-survive-a-restart) covers.
