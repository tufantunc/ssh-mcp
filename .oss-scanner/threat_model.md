# Threat model

Read this with `SECURITY.md` and the README's policy sections, which are the
contract this file summarises. Where they describe a limit as known and
documented, behaviour matching that description is not a finding; behaviour
that is worse than it describes is.

## What this project does and where untrusted input enters

ssh-mcp is an MCP server that lets an LLM agent run commands, open interactive
shell sessions and transfer files on remote hosts over SSH. Every call passes a
policy gate first: a command classifier (`src/policy/classifier.ts`,
`src/policy/reader-grammar.ts`), per-profile roles and host groups
(`src/policy/engine.ts`), a never-allowed list, quotas, and human approval for
some classes. That gate is the security boundary this project exists to provide.

Untrusted input:

- **Tool-call arguments.** Treat the agent as attacker-controlled: it may have
  been prompt-injected by anything it read. Commands, paths, session input and
  transfer requests are all attacker-chosen. This is the main entry point.
- **The HTTP transport** (`src/transport/http.ts`), when enabled. Anyone who can
  reach the port is untrusted until the bearer token is checked; the rate and
  auth-failure limits apply to them.
- **What remote hosts send back:** command output, file contents, file names,
  and SFTP listings. A target host may be compromised. This data flows to the
  agent, into the audit log, and onto the local disk through downloads.
- **The SSH server before its host key is verified** (`src/ssh/host-key.ts`).

Trusted: the config file and its directory (the server checks their
permissions), environment variables, command-line flags, and the local account
the server runs as.

## Components that matter most / least

Most:

- `src/policy/`: command classification, role and group rules, the
  never-allowed list, remote path handling. A command reaching a host that the
  configured policy should refuse, or should hold for approval, is the core
  failure.
- `src/guard/`: approval grants and elicitation, the sanitizer, the redactor.
- `src/tools/`: the tool handlers, local path containment for transfers
  (`local-path.ts`, `forbidden-dirs.ts`), and what each tool hands the policy.
- `src/transport/http.ts`: authentication, session handling, rate limits.
- `src/ssh/host-key.ts`, `src/ssh/algorithms.ts`: host key trust and the
  algorithm allow-list.
- `src/config/`: credential resolution and config permission checks.

Least, or out of scope:

- `test/`, `docker/`, `scripts/`, `docs/`. The passwords in the test fixtures
  are deliberate.
- `src/observability/`.
- Vulnerabilities in dependencies (`ssh2`, the MCP SDK, …) unless ssh-mcp's own
  use of them is what makes them reachable.

## How to exercise it

- `build/` is already compiled; `node build/index.js --help` lists the flags.
  The server speaks MCP over stdio by default and over HTTP with
  `--transport=http`.
- `npm run test:unit` runs offline. The classifier can be driven directly:
  `classifyCommand` in `build/policy/classifier.js`.
- For a real SSH target, run `.oss-scanner/test-servers.sh start` as root.
  It starts OpenSSH on ports 2222–2226 and dropbear on 2227, with the users
  from `docker-compose.yml`. Then
  `SSH_MCP_REQUIRE_SERVERS=1 npm run test:integration` runs the integration
  suite against them, and `test/integration/fixtures.ts` shows how to build
  profiles for your own experiments. One test is expected to fail here:
  "encrypted private key" in `tty-and-passphrase.test.ts` calls `docker exec`
  to install a key, and there is no Docker in this image. The Windows suite
  skips.
- `test/e2e/harness.ts` drives the built server as a separate process, the way
  an MCP client does.

## How you rate severity

- **Critical:** without a valid bearer token, an HTTP client runs a command or
  transfers a file on a target host, or reads a credential.
- **High:**
  - A tool call runs a command on a remote host that the configured policy
    should refuse.
  - A tool call bypasses approval it should have needed.
  - A write goes through on a `readOnly` profile.
  - A never-allowed command or write path gets through.
  - A transfer writes or reads a local file outside the paths it is confined to.
  - A credential (password, private key, passphrase, sudo password, bearer
    token) reaches the agent, a log or the audit store.
  - A pinned `trustedHostKey` is bypassed.
- **Medium:**
  - A command classified one tier too low where the role would still have
    allowed it.
  - A tool call or unauthenticated HTTP client that can crash, hang or exhaust
    the server.
  - Audit records that can be dropped or forged by a tool call.
  - Rate or quota limits that can be bypassed.
- **Low:** leaks of non-secret information, problems that need a trusted input
  (the config file, flags, environment) to be hostile.

When the reachable role and host group change the impact, rate it at the
default configuration and say what changes it.

## Anything to leave alone

- A command that the policy allows doing what that command does. Shell access to
  remote hosts is the purpose of the tool. An `admin` role running `sudo` after
  approval is working as intended.
- The limits `SECURITY.md` documents as known, reported as if new:
  - Host key trust under `tofu` lasting one process.
  - Interactive sessions keeping shell state between calls.
  - `ask-destructive` gating less than its name suggests.

  A case that is worse than the documentation says is in scope.
- Anything that needs control of the config file, the environment, or the local
  account running the server.
- Windows-only code paths (`src/config/windows-acl.ts`, `src/config/sddl.ts`)
  cannot run in this image; read them, but say so in the report.
