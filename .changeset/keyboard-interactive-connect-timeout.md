---
"ssh-mcp": minor
---

Two opt-in profile settings for hosts that cannot be logged in to with the `password` method in one quick round: `keyboardInteractive` and `connectTimeoutMs`.

ssh2 only offers the `keyboard-interactive` method when `tryKeyboard` is set, and ssh-mcp never set it. Two common kinds of host were then unreachable with a correct password, both ending in `All configured authentication methods failed`:

- **VMware ESXi** with the usual hardening `PasswordAuthentication no`. sshd takes passwords only through keyboard-interactive, as one hidden `Password:` prompt, and refuses the `password` method.
- **Dell iDRAC7/8** accepts the password with partial success (PuTTY prints "Further authentication required") and then runs one more keyboard-interactive round with no prompts. Measured against an iDRAC7 on firmware 2.65.65.65: `none`, then `password` (partial success), then `keyboard-interactive` with no prompts, then success.

`keyboardInteractive` takes `"off"` (the default when unset), `"empty"` or `"password"`:

- `"empty"` offers the method and answers every prompt with an empty string. That covers the iDRAC. A real question gets `''`, so the login fails at once instead of waiting for a person.
- `"password"` does the same, except that a round of exactly one hidden prompt that asks for a password is answered with the profile's password, at most once per login. That covers ESXi. A one-time code, several prompts, a prompt that echoes, or a second password round after a refused one all still get `''`: the password never reaches a question it was not meant for, and a wrong one is not retried against the server's failed-login limit.

It stays off by default because every extra attempt counts against a server's failed-login limit.

`connectTimeoutMs` (default 20000, unchanged) is the ceiling on connecting and logging in. It replaces the two fixed 20 s bounds, the handshake limit and the connect timer. That iDRAC took 10 to 40 s per login, so the fixed limit refused a login that was going to succeed.

Both are connection fields: changing either one on a reload closes the live connection.
