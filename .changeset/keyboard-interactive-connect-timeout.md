---
"ssh-mcp": minor
---

Two opt-in profile settings for hosts that cannot be logged in to with the `password` method in one quick round: `keyboardInteractive` and `connectTimeoutMs`.

ssh2 only offers the `keyboard-interactive` method when `tryKeyboard` is set, and ssh-mcp never set it. Two common kinds of host were then unreachable with a correct password, both ending in `All configured authentication methods failed`:

- **VMware ESXi** with the usual hardening `PasswordAuthentication no`. sshd takes passwords only through keyboard-interactive, as one hidden `Password:` prompt, and refuses the `password` method.
- **Dell iDRAC7/8** accepts the password with partial success (PuTTY prints "Further authentication required") and then runs one more keyboard-interactive round with no prompts. Measured against an iDRAC7 on firmware 2.65.65.65: `none`, then `password` (partial success), then `keyboard-interactive` with no prompts, then success.

`keyboardInteractive` takes `"off"` (the default when unset), `"empty"` or `"password"`:

- `"empty"` offers the method and answers every prompt with an empty string. That covers the iDRAC. A real question gets `''`, so the login fails at once instead of waiting for a person.
- `"password"` does the same, except that a round of exactly one hidden prompt that asks for a password is answered with the profile's password. That covers ESXi. A one-time code, several prompts, or a prompt that echoes all still get `''`, so the password never reaches a question it was not meant for.

With either mode on, the password goes out at most once per login: by the `password` method when the server lists that method, or else by the one prompt. A wrong password is not sent a second time within the login, and the `password` method is not tried on a server that does not offer it (ESXi with `PasswordAuthentication no`), where it would only count as a failed login.

It stays off by default because every extra attempt counts against a server's failed-login limit.

`connectTimeoutMs` (default 20000, unchanged; 1000 to 600000) is the ceiling on connecting and logging in. It replaces the two fixed 20 s bounds, the handshake limit and the connect timer. That iDRAC took 10 to 40 s per login, so the fixed limit refused a login that was going to succeed. The timeout error now names the limit and the setting.

On a config reload, a change to `keyboardInteractive` closes the live connection, as a change to `auth` does. A change to `connectTimeoutMs` leaves it open and applies from the next login. Writing either default out (`"off"`, `20000`) is not a change.
