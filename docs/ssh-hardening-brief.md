# Production-Grade SSH Client Hardening — Research Brief for ssh-mcp v2

**Scope.** Hardening the `ssh2`-based client layer of `tufantunc/ssh-mcp` (a Node.js SSH MCP gateway). All RFC text and `ssh2` API signatures below were verified against primary sources (RFC-editor HTML, the `ssh2` README at `mscdex/ssh2@master`, and upstream library docs). Where a URL could not be verified, it is omitted or flagged.

---

## A. Host key verification

Server host-key verification is the single most important MITM defense in SSH. RFC 4251 §4.1 defines three trust models: (1) a local per-host name→key database (`known_hosts`), (2) a trusted Certification Authority, and (3) "the server name–host key association is not checked when connecting to the host for the first time." The RFC is explicit that option (3) "is vulnerable to active man-in-the-middle attacks" and that "Implementations SHOULD NOT normally allow such connections by default" [4251 §4.1]. §4.4 reinforces: "the protocol allows the verification to be left out, but this is NOT RECOMMENDED." RFC 4251 §9.3.4 ("Man-in-the-middle") and §4.1 both describe the classic first-connection attack where an in-path attacker substitutes its own key.

**What `ssh2` exposes.** The `connect(config)` `hostVerifier` option is a function with signature `(key[, callback])`, where `key` is "either a hex *string* of the hash of the key if `hostHash` was set, otherwise it is the raw host key in *Buffer* form." The application returns `true` to continue or `false` to disconnect, or uses the optional `callback(true|false)` for asynchronous checks. Critically, **the documented default is "auto-accept if `hostVerifier` is not set."** [ssh2 README, `hostVerifier`/`hostHash`] The negotiated key type is also reported via the `handshake` event (`negotiated.srvHostKey`) and the `hostkeys` event, and the `algorithms.serverHostKey` list lets the client restrict which host-key algorithms it will accept.

**Comparison with peer libraries.**

- **Paramiko** (`SSHClient.set_missing_host_key_policy`): ships `RejectPolicy` (the *default*), `AutoAddPolicy` (TOFU that persists the key), and `WarningPolicy` (accept with a log warning). `connect()` raises `BadHostKeyException` on a mismatch against `load_system_host_keys`/`load_host_keys` [Paramiko `client` API]. The secure default is `RejectPolicy`.
- **Go `golang.org/x/crypto/ssh`**: `ClientConfig.HostKeyCallback` is the verification hook. It provides `FixedHostKey(key)` (pin one key), `InsecureIgnoreHostKey()` (explicitly named "insecure"), and `ParseKnownHosts`/`knownhosts` helper for an OpenSSH-format `known_hosts` file [pkg.go.dev `golang.org/x/crypto/ssh`].
- **Ansible**: defaults `host_key_checking=True` (in older versions `False`, changed for safety); users pass `--ssh-common-args='-o StrictHostKeyChecking=…'` or set `ansible_ssh_common_args`.
- **Terraform**: relies on the underlying communicator; its SSH communicator honors `host_key`/`bastion_host_key` plus a `host_key_algorithm`, and historically failed *open* if neither was supplied — the operator must provide a key or fingerprint.

**Recommended UX for ssh-mcp v2.** Strict-by-default, fail closed:

1. **Default:** verify the presented key against `~/.ssh/known_hosts` (OpenSSH format, hashed or plaintext). On unknown host or mismatch → error with a clear remediation message.
2. **Pin by fingerprint:** `--hostFingerprint <SHA256:…>` (or MD5 for legacy). The verifier compares `ssh2.utils.parseKey()`-derived fingerprint, constant-time, exactly as the v1 PR #65 added.
3. **Explicit TOFU opt-in:** `--acceptNewHostKey` writes the presented key to a managed known_hosts file on first sight (mimicking Paramiko's `AutoAddPolicy`). Must never be combined with silent acceptance.
4. **Explicit opt-out:** `--insecureHostKey` (already in #65) — prints a loud warning. Documented as "for ephemeral CTF/test hosts only."
5. **Never** silently disable verification. The v1 default of auto-accept (the `ssh2` library default) is the root cause of issue #33's "lethal trifecta" concern and must not return.

RFC 4254 §11 additionally recommends that "implementations disable all the potentially dangerous features (e.g., agent forwarding, X11 forwarding, and TCP/IP forwarding) if the host key has changed without notice" — a useful policy hook for v2.

---

## B. Algorithms (KEX, ciphers, MACs, host-key, pubkey)

RFC 9142 (Jan 2022) is the authoritative IETF guidance, reflected in the IANA "OK to Implement" column. Its headline rules [9142 §3–4]:

| Method | RFC 9142 guidance | Notes |
|---|---|---|
| `curve25519-sha256` | **SHOULD** | Fast, constant-time, preferred |
| `ecdh-sha2-nistp256/384/521` | **SHOULD** | 128/192/256-bit |
| `diffie-hellman-group16-sha512` | **SHOULD** | 4096-bit FFC |
| `diffie-hellman-group14-sha256` | **MUST** (MTI) | 2048-bit, 112-bit security |
| `ext-info-c` / `ext-info-s` | **SHOULD** | RFC 8308 extension negotiation |
| `diffie-hellman-group14-sha1` | MAY | Legacy, "put at the end" |
| `diffie-hellman-group-exchange-sha1`, `diffie-hellman-group1-sha1` | **SHOULD NOT** | Group1 ~80-bit; SHA-1 |
| `rsa1024-sha1` | **MUST NOT** | No forward secrecy; 80-bit |

RFC 9142 §5 states the floor: "MODP groups with a modulus size less than 2048 bits are too small" and "The use of SHA-1 for use with any key exchange may not yet be completely broken, but it is time to retire all uses of this algorithm as soon as possible." It sets **112 bits** as the minimum security strength and recommends SHA-2 (SHA2-256 ≈ 128-bit) as the floor hash. NIST SP 800-131A Rev2 ("Transitioning the Use of Cryptographic Algorithms and Key Lengths") drives the same SHA-1/RSA-1024 disallowance schedule in the U.S. federal context; RFC 9142's normative references to NIST.SP.800-57pt1r5 underpin the 112/128/192/256-bit security strength table the RFC uses [9142 §1.1, §1.2].

RFC 8308 §3.1 defines `server-sig-algs`, the server-sent extension that lets the client pick `rsa-sha2-256`/`rsa-sha2-512` instead of the broken `ssh-rsa` (RFC 8332). Advertising `ext-info-c` in the KEX list is what triggers this. RFC 8308 §2.1: "When acting as client: 'ext-info-c'" must be added to `kex_algorithms`.

**`ssh2` allows-list.** The `algorithms` ConnectConfig field accepts, for each of `cipher`, `compress`, `hmac`, `kex`, `serverHostKey`, either an exact array (most-preferred first) or an object `{ append, prepend, remove }`. Defaults are already modern (KEX: `curve25519-sha256`, `curve25519-sha256@libssh.org`, `ecdh-sha2-nistp256/384/521`, `diffie-hellman-group-exchange-sha256`, `diffie-hellman-group14-sha256`, …; ciphers: `chacha20-poly1305@openssh.com`, `aes128/256-gcm`, AES-CTR; MAC: `hmac-sha2-256/512-etm@openssh.com`; serverHostKey: `ssh-ed25519`, ECDSA, `rsa-sha2-512/256`, `ssh-rsa`) [ssh2 README, `algorithms`].

**Recommended explicit allow-list for ssh-mcp v2** (defense against future default drift and ssh2 upgrades):

```js
algorithms: {
  kex: [
    'curve25519-sha256', 'curve25519-sha256@libssh.org',
    'ecdh-sha2-nistp521', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp256',
    'diffie-hellman-group-exchange-sha256',
    'diffie-hellman-group16-sha512', 'diffie-hellman-group14-sha256',
    // ext-info-c is auto-added by ssh2; do not strip it
  ],
  cipher: [
    'chacha20-poly1305@openssh.com',
    'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com',
    'aes256-ctr', 'aes192-ctr', 'aes128-ctr',
  ],
  serverHostKey: [
    'ssh-ed25519', 'ecdsa-sha2-nistp521', 'ecdsa-sha2-nistp384',
    'ecdsa-sha2-nistp256', 'rsa-sha2-512', 'rsa-sha2-256',
    // ssh-rsa removed: forces rsa-sha2 via RFC 8332/8308
  ],
  hmac: [
    'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com',
    'hmac-sha2-256', 'hmac-sha2-512',
  ],
},
```

Deliberately **excluded**: `ssh-dss`, `ssh-rsa` (raw), `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`, all `*-sha1` MACs, all CBC/RC4/3DES ciphers. Enforce this at the gateway's `SSHConnectionManager.connect()` boundary, never per-tool.

The Mozilla OpenSSH guidelines ("Modern" client block) recommend essentially the same KEX/Cipher/MAC list and additionally put cert host-key algorithms first (`ssh-ed25519-cert-v01@openssh.com`, …) [infosec.mozilla.org/guidelines/openssh].

---

## C. SSH certificates (OpenSSH CA)

OpenSSH user/host certificates (signed by a CA with `ssh-keygen -s`) eliminate per-host `authorized_keys` sprawl and enable short-lived, revocable credentials. RFC 4251 §4.1 explicitly anticipates "a trusted certification authority (CA)" as the second trust model. `ssh2` exposes certificate material through `utils.parseKey()` (which yields a parsed key with `.type` like `ssh-ed25519-cert-v01@openssh.com` and a `.cert`/cert chain) and accepts cert-bearing private keys in `privateKey`. Cert auth is appropriate when the deployment has a CA (e.g. Vault SSH secrets engine, Teleport, or a hand-rolled CA); raw keys are fine for ad-hoc single-host gateways.

**Recommendation:** support both, defaulting to raw keys. Add a profile-level `cert: true` / `caFingerprint` option: when set, `hostVerifier` validates the server's host *certificate* against a pinned CA public key (mimicking Go's `CertChecker.IsHostAuthority`), and user auth prefers the cert-bearing key. Do not roll a custom cert format; use OpenSSH `ssh-ed25519-cert-v01@openssh.com` etc. so admins can rotate with standard tooling.

---

## D. SSH agent (`SSH_AUTH_SOCK`) & agent forwarding

`ssh2` supports `agent: <socket-path>` for key material retrieval (via `OpenSSHAgent`/`createAgent`), and `agentForward: true` for OpenSSH's `auth-agent@openssh.com` channel — defaulted to `false` [ssh2 README]. This mirrors OpenSSH `ForwardAgent`/`ssh -A`.

**Risk.** Agent forwarding exposes the *agent socket* on the remote host. Mozilla's guidance is unambiguous: "SSH Agent forwarding exposes your authentication to the server you're connecting to. By default, an attacker with control of the server (i.e. root access) can communicate with your agent and use your key to authenticate to other servers without any notification (i.e. impersonate you)… Defaulting to always forwarding the agent is strongly discouraged." [infosec.mozilla.org/guidelines/openssh] RFC 4251 §9.5.2 and §4.3 ("MUST NOT allow connections to the authentication agent unless forwarding such connections has been requested") are the protocol-level basis.

**Recommendation:**

- **DO** honor `SSH_AUTH_SOCK` for sourcing the user's key material locally on the gateway host (a clean improvement over embedding `privateKey` blobs in config). This also fixes issue #25 (encrypted private-key passphrase) for users who load their key into the agent.
- **DO NOT** enable `agentForward`. It is off by default in `ssh2` and v2 must keep it off; there is no MCP use case that benefits from a second hop using the gateway's agent. If bastion hopping is needed, use `sock`-based `ProxyJump` (section E) instead, which keeps the agent local.

---

## E. ProxyJump / bastion / jump hosts

`ssh2` exposes `sock: <ReadableStream>` on `connect()`, documented as "useful for connection hopping." The README's "Connection hopping" example chains two `Client`s: `conn1.forwardOut(...)` yields a stream that is passed as `conn2.connect({ sock: stream, ... })`. This is exactly how OpenSSH `ProxyJump`/`ProxyCommand ssh jumphost -W %h:%p` works at the wire level, and it keeps authentication and host-key verification independent per hop.

**Recommendation for v2:** add a profile field `via: <profile-name>` (or `via: [profileA, profileB]` for multi-hop). Resolution: build the chain of `Client`s, each with its own strict host-key check and its own KEX allow-list, and thread `forwardOut` streams through `sock`. Reuse the Mozilla recommendation that `ProxyJump` is "safer alternatives to SSH agent forwarding" [infosec.mozilla.org/guidelines/openssh]. Do **not** implement jumping by agent forwarding.

---

## F. Connection lifecycle & `MaxSessions` (Issue #34)

This is the highest-impact architectural fix for v2. Issue #34 documents that v1's `--suPassword` feature used `conn.shell()` to build a persistent interactive PTY shell, fed `su -` into it, and reused that shell for every subsequent command. Result: server-side PTY allocations accumulated (`who` showed `pts/1`…`pts/24+`) until OpenSSH's `MaxSessions` (default **10** per connection) was hit, after which every command failed with `Channel open failure: open failed`. v1's attempted fixes (`stream.destroy()`, keepalives) did not help because the leak is server-side.

**Why this happens, protocol-wise.** RFC 4254 §5 multiplexes "terminal sessions, forwarded connections, etc." as *channels* on a single authenticated connection. §6.1 opens a `"session"` channel; §6.2 `pty-req` allocates a PTY; §6.5 starts a `shell`/`exec`/`subsystem`. OpenSSH's `sshd_config MaxSessions` caps simultaneous *session channels* per connection. `shell()` + PTY keeps the channel open for the life of the stream; `exec()` opens a channel that closes on `SSH_MSG_CHANNEL_CLOSE` (§5.3) once the command exits.

**Recommendations:**

1. **Prefer `exec()` over `shell()`.** Each `exec()` call opens one session channel, runs the command, emits `exit`/`close`, and the channel is reclaimed. No PTY is allocated unless explicitly requested (section G). This is what #34's reporter verified fixes the leak: switching `--suPassword` users to `--sudoPassword` (which uses `sudo -S` via stdin on an `exec()` channel) left the session count flat at 31 across 15 commands.
2. **Pool only the base `Client` connection**, not channels. One authenticated transport per profile; many short-lived `exec()` channels.
3. **Channel-per-request.** Never share a `shell()` stream across MCP tool calls.
4. **Idle reaping + reconnect-on-error.** Track last-activity time per `Client`; if a channel open fails (`SSH_OPEN_RESOURCE_SHORTAGE`, RFC 4254 §5.1 reason code 4) or `MaxSessions` is exhausted, `end()` the `Client`, open a fresh one, and retry once.
5. **Max-concurrency cap.** Gate concurrent `exec()` calls per profile (e.g. semaphore of `MaxSessions - 1`) to stay below the server limit.
6. **Call `openssh_noMoreSessions()`** on the base connection *only* when the profile is single-shot — otherwise leave it off, since it disables all future session channels for the life of the connection.

`--suPassword` itself should be deprecated or removed (per #34's recommendation); persistent root shells are the wrong primitive for a request/response MCP gateway.

---

## G. PTY vs non-PTY, "input device is not a TTY" (Issue #31)

Issue #31 reports `sudo -S` failing with `the input device is not a TTY` when commands run without a PTY. Root cause: many programs (`sudo` without `-S`, `systemctl`, pagers, anything calling `isatty(0)`) refuse to read passwords from or render output to a non-tty stdin. `ssh2`'s `exec(command, { pty: true | <settings> }, cb)` lets the caller opt into a PTY per channel; the default is no PTY.

**Recommendation:**

- Default: **no PTY** (`exec()` with `pty` unset). This is correct for 95% of MCP commands and avoids the `MaxSessions` leak of §F.
- Per-call opt-in: expose a tool argument `tty: boolean` (default `false`). When `true`, call `exec(cmd, { pty: { term: 'xterm-256color', cols: 200, rows: 50 } }, cb)`. Never make it persistent across calls.
- For `sudo`, prefer `sudo -S` with the password piped via the channel's `stdin` (`stream.write(password + '\n'); stream.end()`), which is what PR #65 implemented and what resolves both #31 and the password-in-`ps` leak of #43. Reserve `tty: true` for commands that genuinely require a TTY (e.g. interactive reinstallers the operator explicitly invokes).
- Document that `tty: true` allocates a server-side PTY and counts against `MaxSessions`.

---

## H. SFTP subsystem (Issue #38)

Use the SFTP subsystem for all file transfer, never `scp`/`cat`/`dd` over `exec`. `ssh2` exposes `sftp([env,] callback)` which opens an SFTP session via the `"subsystem"` channel type (RFC 4254 §6.5 `"subsystem"` with name `"sftp"`). Issue #38's PR adds `upload-file`/`download-file` MCP tools backed by `sftp().writeFile()`/`readFile()` with `utf8`/`base64` encodings — this is the right design.

Two reinforcing facts:

1. **OpenSSH 9.0 (Apr 2022) switched `scp(1)` to use the SFTP protocol by default** precisely because the legacy RCP protocol "performs wildcard expansion of remote filenames … through the remote shell" requiring "double quoting of shell meta-characters," which is itself a command-injection vector [openssh.com/txt/release-9.0]. v2 should not regress to `cat`/`dd` workarounds that reintroduce that class of bug (cf. v1 issue #44's description-injection vuln).
2. **SFTP channels are sessions under `MaxSessions` too.** Pool a single long-lived SFTP session per profile *or* open/close per transfer; do not open one SFTP session per file in a tight loop without closing.

**Recommendation:** ship `upload-file`, `download-file`, and consider `list-files`/`stat-file`/`delete-file` as SFTP-backed tools. Pass `encoding` through. Stream large files rather than buffering.

---

## I. Per-user least privilege at the SSH layer (defense-in-depth on the target)

The gateway can only do so much; the *target* host must also enforce least privilege. This is the SSH-layer mitigation for the "lethal trifecta" raised in issue #33. OpenSSH provides several primitives the operator should be told to use:

- **`authorized_keys` restrictions:** per-key options like `command="..."`, `no-pty`, `no-X11-forwarding`, `no-agent-forwarding`, `no-port-forwarding`, `permitopen=...`, `from="..."`. A gateway key can be pinned to a single forced command or `restrict` (all-of-the-above).
- **`ForceCommand`** in `sshd_config`: overrides whatever command the client sent (the gateway's `exec()` command becomes the argument to `$SSH_ORIGINAL_COMMAND`).
- **`Match` blocks:** `Match User gateway-bot Address 10.0.0.0/8` → `AllowTcpForwarding no`, `PermitTTY no`, `X11Forwarding no`, `AllowAgentForwarding no`, `ForceCommand internal-sftp` (chrooted SFTP-only).
- **Restricted shells:** `rbash`/`rshell`, or `Match` + `ChrootDirectory` for file-transfer-only accounts.
- **`sudoers` command-specific rules:** `gateway-bot ALL=(root) NOPASSWD: /usr/bin/systemctl status *, /usr/bin/journalctl *` — far better than blanket `sudo -S` with a root password.
- **SSH certificates with `critical options`:** `force-command=...`, `source-address=...`, `verify-required` (FIDO) bound into the cert so the restriction follows the credential, not the host config.

Document a "target-side hardening" appendix recommending `restrict`-style `authorized_keys` entries and a `Match` block for the gateway account. The Mozilla machine-key guidance ("Using a ForceCommand returning only the needed results… is preferred"; "Restrict privileges of the account") is a citable precedent [infosec.mozilla.org/guidelines/openssh].

---

## J. Hardening checklist for the `ssh2` layer

Concrete, auditable items for the v2 client:

- [ ] **KEX allow-list** pinned per §B; `ext-info-c` preserved so `server-sig-algs` works.
- [ ] **Cipher/MAC allow-list** EtM-only, AES-GCM/ChaCha20/CTR; no CBC, no RC4, no 3DES.
- [ ] **serverHostKey allow-list** without raw `ssh-rsa`/`ssh-dss`.
- [ ] **Host-key verification strict by default** (`hostVerifier` checks `known_hosts`); fail closed on mismatch.
- [ ] **Fingerprint pin** path (`--hostFingerprint`), constant-time compare.
- [ ] **TOFU opt-in** only (`--acceptNewHostKey`); **never** silent auto-accept.
- [ ] **No agent forwarding** (`agentForward` always `false`).
- [ ] **`SSH_AUTH_SOCK` supported** for local key material (fixes #25 passphrase flow).
- [ ] **`exec()` over `shell()`** for all request/response tools (#34).
- [ ] **Per-call `tty: boolean`** opt-in, default `false` (#31).
- [ ] **SFTP subsystem** for all file transfer (#38); no `cat`/`dd`/`scp`-via-shell.
- [ ] **`readyTimeout`** (connect/handshake) set (e.g. 15–20 s; `ssh2` default is 20000 ms).
- [ ] **`keepaliveInterval`** (e.g. 15 s) and **`keepaliveCountMax`** (e.g. 3) — `ssh2` defaults are 0/3; enable keepalives to detect dead peers.
- [ ] **Idle reaping:** close idle `Client`s after N minutes; reconnect transparently.
- [ ] **Concurrency cap** per profile at `MaxSessions - 1`; retry-on-`RESOURCE_SHORTAGE` with fresh connection.
- [ ] **`openssh_noMoreSessions()`** only for single-shot profiles.
- [ ] **No passwords in argv** (#42): read all secrets from env vars or a secrets file with `0600` perms.
- [ ] **Sudo password via channel stdin**, never embedded in the command string (#43).
- [ ] **Sanitize all caller-supplied metadata** (descriptions, filenames) of CR/LF before any shell context (#44).
- [ ] **Log negotiated algorithms** at connect (emit `handshake` event payload to structured logs) for auditability.

---

## K. Concrete recommendations for ssh-mcp v2

The v2 `ssh2` `ConnectConfig` should be assembled by a single `buildConnectConfig(profile)` function so policy lives in one place. Sketch (TypeScript, illustrative):

```ts
import { Client, utils } from 'ssh2';
import { readFileSync } from 'fs';

const STRICT_ALGORITHMS = {
  kex: [
    'curve25519-sha256', 'curve25519-sha256@libssh.org',
    'ecdh-sha2-nistp521', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp256',
    'diffie-hellman-group-exchange-sha256',
    'diffie-hellman-group16-sha512', 'diffie-hellman-group14-sha256',
  ],
  cipher: [
    'chacha20-poly1305@openssh.com',
    'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com',
    'aes256-ctr', 'aes192-ctr', 'aes128-ctr',
  ],
  serverHostKey: [
    'ssh-ed25519',
    'ecdsa-sha2-nistp521', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp256',
    'rsa-sha2-512', 'rsa-sha2-256',
  ],
  hmac: [
    'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com',
    'hmac-sha2-256', 'hmac-sha2-512',
  ],
} as const;

function buildHostVerifier(profile: Profile) {
  // Strict by default. Priority: pinned fingerprint > known_hosts > error.
  return (presented: Buffer, cb?: (ok: boolean) => void): boolean => {
    const parsed = utils.parseKey(presented);
    const fp = `${parsed.type === 'ssh-ed25519' ? 'SHA256' : 'SHA256'}:` +
               sha256Fingerprint(presented); // constant-time elsewhere
    if (profile.hostFingerprint) {
      const ok = timingSafeEqualIgnoreCase(profile.hostFingerprint, fp);
      if (cb) return cb(ok) ?? false; else return ok;
    }
    if (profile.insecureHostKey) { console.warn('INSECURE: host key not verified'); 
      if (cb) return cb(true) ?? false; else return true; }
    const known = lookupKnownHosts(profile.host, parsed);
    if (cb) cb(!!known); return !!known;
  };
}

function buildConnectConfig(profile: Profile) {
  const creds = loadSecrets(profile); // env var / 0600 file, never argv (#42)
  return {
    host: profile.host, port: profile.port ?? 22, username: profile.user,
    password: creds.password,
    privateKey: creds.privateKeyPath ? readFileSync(creds.privateKeyPath) : undefined,
    passphrase: creds.keyPassphrase,           // fixes #25
    agent: process.env.SSH_AUTH_SOCK ?? undefined,  // local key material only
    agentForward: false,                       // never (§D)
    algorithms: STRICT_ALGORITHMS,             // §B
    hostVerifier: buildHostVerifier(profile),  // §A, strict default
    readyTimeout: 20_000,
    keepaliveInterval: 15_000,
    keepaliveCountMax: 3,
    strictVendor: true,
    debug: profile.debug ? (s: string) => log.debug(s) : undefined,
  };
}
```

**Tying to the issues:**

- **#34 (PTY/`MaxSessions` leak):** delete `--suPassword` and the `shell()`-based persistent-root design. All tools use `exec()`. Add a per-profile concurrency semaphore (e.g. `p-limit`) sized to `MaxSessions - 1`. Add reconnect-on-`RESOURCE_SHORTAGE`.
- **#65 (security hardening PR):** v2 should bake in everything #65 added as defaults, not options: strict host-key verification, secrets via env, sudo password via stdin, sentinel-based shell protocol (if any shell is retained at all), description CRLF sanitization. The v2 `buildHostVerifier` above makes strict-by-default the only path.
- **#31 (not a TTY):** expose `tty?: boolean` on `exec`/`sudo-exec` tool schemas, default `false`. When `true`, pass `{ pty: DEFAULT_PTY }` to `ssh2.exec()`.
- **#38 (SFTP):** adopt the `upload-file`/`download-file` design as first-class tools; add `list-files`, `stat-file`, `rm-file`. Use `conn.sftp()` per transfer or a pooled SFTP session with explicit close.
- **#33 (lethal trifecta), #42/#43/#44 (vulns):** addressed structurally by §A (no MITM), §B (no weak crypto), §D (no agent forwarding), §I (target-side least privilege docs), and the checklist's no-argv-secrets / stdin-password / metadata-sanitization rules.

**Opinionated closing.** v1's security posture was "convenient first, secure if you read the docs." v2 must invert that: secure-by-default with explicit, loudly-warned opt-outs. The four highest-leverage changes are (1) strict host-key verification as the only default, (2) `exec()`-only with a concurrency cap, (3) a frozen modern algorithm allow-list, and (4) secrets-via-env with no `shell()`-based elevation. Everything else in §J is hardening depth; those four are the load-bearing walls.

---

## Sources

1. **RFC 4251** — Ylonen & Lonvick, "The Secure Shell (SSH) Protocol Architecture," Jan 2006. https://www.rfc-editor.org/rfc/rfc4251.html — §4.1 (host keys/trust models), §4.4 (verification NOT RECOMMENDED to omit), §9.3.4 (MITM), §9.5.2 (proxy/agent forwarding), §9.5.3 (X11).
2. **RFC 4252** — "The Secure Shell (SSH) Authentication Protocol," Jan 2006. https://www.rfc-editor.org/rfc/rfc4252.html
3. **RFC 4253** — "The Secure Shell (SSH) Transport Layer Protocol," Jan 2006. https://www.rfc-editor.org/rfc/rfc4253.html — §7 algorithm negotiation.
4. **RFC 4254** — Ylonen & Lonvick, "The Secure Shell (SSH) Connection Protocol," Jan 2006. https://www.rfc-editor.org/rfc/rfc4254.html — §5 (channels), §6.1 (session open), §6.2 (`pty-req`), §6.5 (`shell`/`exec`/`subsystem`), §5.1 reason codes (incl. `SSH_OPEN_RESOURCE_SHORTAGE`), §11 (disable dangerous features on key change).
5. **RFC 8308** — Bider, "Extension Negotiation in the Secure Shell (SSH) Protocol," Mar 2018. https://www.rfc-editor.org/rfc/rfc8308.html — §2.1 (`ext-info-c`/`ext-info-s`), §3.1 (`server-sig-algs`).
6. **RFC 8332** — Bider, "Use of RSA Keys with SHA-256 and SHA-512 in the Secure Shell (SSH) Protocol," Mar 2018. https://www.rfc-editor.org/rfc/rfc8332.html — `rsa-sha2-256`/`rsa-sha2-512`.
7. **RFC 9142** — Baushke, "Key Exchange (KEX) Method Updates and Recommendations for Secure Shell (SSH)," Jan 2022. https://www.rfc-editor.org/rfc/rfc9142.html — §3–§4 (MUST/SHOULD/MAY/MUST NOT tables), §5 (2048-bit MODP floor, SHA-1 retirement, 112-bit minimum).
8. **NIST SP 800-131A Rev2** — Barker, "Transitioning the Use of Cryptographic Algorithms and Key Lengths," (referenced normatively by RFC 9142 §1.1–1.2 via NIST.SP.800-57pt1r5). https://csrc.nist.gov/pubs/sp/800/131/a/r2/final — SHA-1/RSA-1024 transition schedule, security-strength floors.
9. **`ssh2` README / API** — mscdex, `ssh2` npm module, `ConnectConfig`, `hostVerifier`, `hostHash`, `algorithms`, `exec`/`shell`/`sftp`/`subsys`, `agent`/`agentForward`, `sock`, `keepaliveInterval`/`keepaliveCountMax`, `readyTimeout`, `openssh_noMoreSessions`. https://github.com/mscdex/ssh2 (README at `master`).
10. **Mozilla OpenSSH guidelines** — "OpenSSH" (Modern client/server config; agent-forwarding risk; ProxyJump as safer alternative). https://infosec.mozilla.org/guidelines/openssh
11. **OpenSSH 9.0 release notes** — "switches scp(1) from using the legacy scp/rcp protocol to using the SFTP protocol by default"; default KEX `sntrup761x25519-sha512@openssh.com`. https://www.openssh.com/txt/release-9.0 (Apr 2022).
12. **Paramiko** — `SSHClient`, `set_missing_host_key_policy`, `RejectPolicy`/`AutoAddPolicy`/`WarningPolicy`, `connect(allow_agent, look_for_keys, disabled_algorithms)`. https://docs.paramiko.org/en/stable/api/client.html
13. **Go `golang.org/x/crypto/ssh`** — `HostKeyCallback`, `FixedHostKey`, `InsecureIgnoreHostKey`, `ParseKnownHosts`/`knownhosts`, `CertChecker`, `SupportedAlgorithms`/`InsecureAlgorithms`, algorithm-name constants. https://pkg.go.dev/golang.org/x/crypto/ssh
14. **ssh-mcp issue #34** — "PTY Session Accumulation Causes 'Channel open failure' When Using `--suPassword`." https://github.com/tufantunc/ssh-mcp/issues/34 (root-cause analysis, MaxSessions=10 default).
15. **ssh-mcp issue #65** — "Security hardening: host key verification, sudo/su fixes, and dependency updates" (PR description). https://github.com/tufantunc/ssh-mcp/pull/65
16. **ssh-mcp issue #31** — "the input device is not a TTY." https://github.com/tufantunc/ssh-mcp/issues/31
17. **ssh-mcp issue #38** — "feat: Add SFTP file transfer tools (`upload-file`, `download-file`)." https://github.com/tufantunc/ssh-mcp/pull/38
18. **ssh-mcp issue #33** — "Security Concerns: The Lethal Trifecta." https://github.com/tufantunc/ssh-mcp/issues/33
19. **ssh-mcp issue #25** — "Failed to Connect via SSH When Using Encrypted Private Key." https://github.com/tufantunc/ssh-mcp/issues/25
20. **ssh-mcp issues #42 / #43 / #44** — credential-exposure and command-injection vulnerabilities (argv secrets, sudo password in remote `ps`, description newline injection). https://github.com/tufantunc/ssh-mcp/issues/42, `/43`, `/44`

> **Note on unverified sources.** The `ssh-audit.com/hardening_guides.html` page could not be fetched (TLS certificate SAN mismatch at fetch time); its specific recommendations are therefore not cited here. The `ssh-audit` tool itself (https://github.com/jtesta/ssh-audit) is a useful runtime auditor and is referenced only as a tool, not as a cited source of specific text. CNSSP 15 and NSA SSH guidance were not directly fetched; their substance (disallow SHA-1, disallow group1, prefer ECDHE/Curve25519) is consistent with and subsumed by RFC 9142 §4.
