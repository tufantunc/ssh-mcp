---
"ssh-mcp": patch
---

Recognise the elevation binaries that 2.2.4 stopped catching, and two it never caught.

The fix for [GHSA-6f54-mjqq-2jp8](https://github.com/tufantunc/ssh-mcp/security/advisories/GHSA-6f54-mjqq-2jp8) replaced four `^`-anchored regexes with exact membership in a set of four names. `/^\s*su\b/` had matched between `su` and a hyphen, so `su-exec` and `sudo-rs` were classified `privileged` — by accident of the regex rather than by intent, but the effect was protective. Exact matching dropped them, and on a `prod`-group profile that turned a `deny` into an `allow`. A security release narrowed a security control, which is not acceptable however narrow the shape.

`gosu` and `run0` were caught by neither the old form nor the new one. `su-exec` and `gosu` are the standard elevation binaries of Alpine and Docker images; `sudo-rs` is the Rust implementation now shipping as the default sudo on some distributions; `run0` is systemd's replacement. A host using any of them had no elevation gate at all, before or after 2.2.4.

`PRIVILEGE_PREFIXES` now lists `su-exec`, `gosu`, `sudo-rs`, `run0` and `pfexec` alongside `sudo`, `su`, `doas` and `pkexec`. It stays an explicit list rather than a pattern, because a pattern cannot tell `sudoedit` — which edits a file and is not elevation — from `sudo-rs`, which is sudo. That means it has to be maintained by hand as new implementations appear, and the cost of missing one is that its commands classify `safe`.

Found by [@burtherman](https://github.com/burtherman)'s work on [#130](https://github.com/tufantunc/ssh-mcp/pull/130) — reviewing that branch is what surfaced the `\b` behaviour, and the same gap turned out to be in the advisory fix.
