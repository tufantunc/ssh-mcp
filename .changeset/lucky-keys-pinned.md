---
"ssh-mcp": minor
---

Make `--hostKeyMode=strict` work, and make `trustedHostKey` able to satisfy it.

`minor` rather than `patch` because a config that started yesterday can refuse to
start today — see **Behaviour changes** — and because one combination that
previously refused now connects.

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
never *reads* the store. That is the point rather than an omission:
`knownHostsStore` is one `Map` for all profiles, so consulting it for a pinned host
means two profiles pinning different keys for the same `host:port` collide with a
false `HOST_KEY_MISMATCH` — once the host presents each of them its own key, which
is the only way that state arises.

It does still *write*, under `tofu`, and only into an empty slot. Both halves of
that were found by measurement rather than reasoning, in two passes.

Dropping the write entirely was a draft of this fix and it cost a real refusal: on
2.7.0 a matching pin fell through into the trust-on-first-use accept, so a pinned
profile seeded the shared store and an unpinned profile on the same `host:port` was
compared against a pin-verified fingerprint. Without the write that profile
trust-on-first-uses whatever it is served, and the store then holds the attacker's
key — so the next connection served the genuine one is refused, with the diagnostic
naming the real server as the impostor.

Restoring it as an unconditional `set` then broke a different profile. 2.7.0's write
lived in the else-branch of `if (stored)`, so it only ever filled; overwriting made
the entry order-dependent, and with two profiles pinning different keys for one
`host:port` whichever connected last decided what an *unpinned* profile was compared
against — giving that profile a false `HOST_KEY_MISMATCH` for a key the other pin had
authorised. Only a three-connection sequence shows it; the single-call matrix does
not. It is `!knownHosts.has(key)` now, matching what it replaced.

Not written under `strict` at all, because there the store is the only thing that can
admit an *unpinned* profile and seeding it would mean pinning one profile silently
admitted every other; nor under `insecure`, where 2.7.0 returned before reaching the
write.

The net effect is worth stating plainly, because it is simpler than the reasoning
behind it: **nothing an unpinned profile experiences differs from 2.7.0.** Every
behaviour change below is about a profile that carries a pin.

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
  Previously it threw `HOST_KEY_MISMATCH`. It needs the entry to be stale relative
  to the key the host presents now — an earlier `tofu` connection learned a key the
  host has since rotated away from, or learned one from an interceptor. (Two
  profiles merely pinning different keys does not reach it: whichever pin disagrees
  with the served key is stopped before the store is consulted.) This is a widening
  — a case that refused now connects — and it is intended: an explicit pin is
  operator configuration, a store entry is unauthenticated first-use memory. If you
  were relying on the old refusal, you were relying on a store entry that no longer
  matches the host.

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
without a pin learns and compares exactly as before; `insecure` without a pin still
accepts anything; a key contradicting a pin is still refused in every mode; and the
store still does not persist across a restart, which
[SECURITY.md](./SECURITY.md#host-key-trust-does-not-survive-a-restart) covers.

Note what `--insecureHostKey` does *not* do: it has never lifted a pin, and now
that the pin is a documented guarantee rather than an accident, that is worth
stating. A profile with `trustedHostKey` set verifies its host under every mode.
