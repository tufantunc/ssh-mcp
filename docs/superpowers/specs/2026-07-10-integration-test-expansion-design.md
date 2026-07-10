# v2 Integration Test Expansion — Design Spec

**Date:** 2026-07-10
**Status:** Approved
**Goal:** Comprehensive integration test coverage for SSH MCP Server v2's multi-host, session, policy, and security features using 3 role-based Docker containers.

---

## Context

v2 introduced multi-host ConnectionRegistry, interactive/background sessions, policy engine with RBAC, sudo-via-stdin, in-band signal cancellation, and audit logging. Current integration tests (21 tests across 3 files) only cover basic exec, interactive session CWD/env persistence, and SFTP round-trip on a single container. The following v2 features are completely untested at the integration level: multi-host parallel operations, background sessions, sentinel edge cases, concurrent sessions, policy E2E across roles, session TTL reaper, sudo password piping, command cancellation, and audit log verification.

## Docker Infrastructure

Three `linuxserver/openssh-server` containers, each with a different user privilege level to simulate real-world role separation:

| Container | Port | User | Sudo | Simulated Role | Password |
|-----------|------|------|------|----------------|----------|
| `ssh-admin` | 2222 | admin | yes | admin (all classes) | secret |
| `ssh-viewer` | 2223 | viewer | no | viewer (read-only only) | viewpass |
| `ssh-operator` | 2224 | operator | yes | operator (read-only + safe + destructive) | oppass |

All three run under `docker compose --profile test up -d`. The CI workflow starts all three before running tests. If any container is unavailable, integration tests skip gracefully via `describe.skipIf`.

### docker-compose.yml additions

```yaml
services:
  ssh-admin:
    image: lscr.io/linuxserver/openssh-server:latest
    profiles: ["test"]
    environment:
      - USER_NAME=admin
      - PASSWORD_ACCESS=true
      - USER_PASSWORD=secret
      - SUDO_ACCESS=true
    ports: ["2222:2222"]

  ssh-viewer:
    image: lscr.io/linuxserver/openssh-server:latest
    profiles: ["test"]
    environment:
      - USER_NAME=viewer
      - PASSWORD_ACCESS=true
      - USER_PASSWORD=viewpass
      - SUDO_ACCESS=false
    ports: ["2223:2222"]

  ssh-operator:
    image: lscr.io/linuxserver/openssh-server:latest
    profiles: ["test"]
    environment:
      - USER_NAME=operator
      - PASSWORD_ACCESS=true
      - USER_PASSWORD=oppass
      - SUDO_ACCESS=true
    ports: ["2224:2222"]
```

## Shared Fixtures (`test/integration/fixtures.ts`)

One fixture module that all test files import. Provides:

- **`profiles`** — 3 `Profile` objects (admin, operator, viewer) with correct host/port/user/role mapping to the 3 containers.
- **`waitForAllServers()`** — Probes ports 2222, 2223, 2224; returns a `{ admin, operator, viewer }` boolean map. Called once per test file in `beforeAll`.
- **`allServersUp`** — Cached promise from `waitForAllServers()`. Used in `describe.skipIf()`.
- **`createRegistry()`** — Returns a `ConnectionRegistry` with all 3 profiles configured.
- **`createPolicyEngine()`** — Returns a `PolicyEngine` with `DEFAULT_RULES`.
- **`createConnection(profileName)`** — Returns a connected `SSHConnection` for a single profile. Sets the correct env var for credential resolution. Uses `'insecure'` host key mode (test containers generate ephemeral keys).
- **`setupEnv()`** — Returns `{ save(), restore() }` for snapshotting `process.env`. Each test file calls `save()` in `beforeAll`, `restore()` in `afterAll`.

### Profile definitions

```typescript
const SSH_HOST = process.env.SSH_HOST || '127.0.0.1';

const baseProfile = {
  auth: 'password' as const,
  tty: false,
  timeout: 15000,
  maxChars: 5000,
  readOnly: false,
  approvalPolicy: 'ask-destructive' as const,
  cert: false,
  sessionMaxPerConnection: 5,
  sessionIdleTimeoutMs: 60000,
};

export const profiles = {
  admin: { ...baseProfile, name: 'admin', host: SSH_HOST, port: 2222, user: 'admin', role: 'admin' },
  operator: { ...baseProfile, name: 'operator', host: SSH_HOST, port: 2224, user: 'operator', role: 'operator' },
  viewer: { ...baseProfile, name: 'viewer', host: SSH_HOST, port: 2223, user: 'viewer', role: 'viewer', readOnly: true },
};
```

### Credential env mapping

Each container's password is set via env var using the profile-specific prefix:

| Profile | Env Var | Value |
|---------|---------|-------|
| admin | `SSH_MCP_ADMIN_PASSWORD` | secret |
| operator | `SSH_MCP_OPERATOR_PASSWORD` | oppass |
| viewer | `SSH_MCP_VIEWER_PASSWORD` | viewpass |

Admin sudo password: `SSH_MCP_ADMIN_SUDO_PASSWORD=secret`, `SSH_MCP_OPERATOR_SUDO_PASSWORD=oppass`.

## Test Files

### 1. `multi-host.test.ts` — ConnectionRegistry multi-host

| Test | What it verifies |
|------|------------------|
| Connects to all 3 profiles independently | `getOrCreate()` returns connected `SSHConnection` for each |
| Parallel exec across 3 hosts | `Promise.all([admin.exec, operator.exec, viewer.exec])` — results don't cross-contaminate |
| Cached connection reuse | 2nd `getOrCreate('admin')` returns same object reference |
| `listConnections()` reports 3 profiles | All 3 show `status: 'connected'` |
| Close one, others stay alive | `close('viewer')` → viewer disconnected, admin+operator still connected |
| Wrong profile name throws | `getOrCreate('nonexistent')` → error |

### 2. `background-session.test.ts` — BackgroundSession lifecycle

| Test | What it verifies |
|------|------------------|
| Open background session with `tail -f` | `isRunning()` returns true |
| Write to file, `readOutput()` sees new lines | Poll returns appended content |
| `close()` kills remote process | `pgrep -f tail` returns empty after close |
| `sleep 5` background session | Exit code captured after completion |
| Ring buffer overflow | Write 200K+ lines, `readOutput(50)` returns last 50, memory bounded |

### 3. `sentinel-edge.test.ts` — InteractiveSession sentinel robustness

| Test | What it verifies |
|------|------------------|
| Multiline output (`seq 1 100`) | All 100 lines returned, exit code 0 |
| Output containing `#` (`echo "a#b#c"`) | No false sentinel match, full output returned |
| Output containing fake sentinel text | UUID prevents spoofing |
| ANSI escape codes (`ls --color=always`) | Escapes stripped from output |
| Empty output (`true`) | Exit code 0, empty stdout |
| Large output (`yes \| head -n 5000`) | All 5000 lines returned, no truncation under cap |

### 4. `concurrent-sessions.test.ts` — Concurrent sessions on one connection

| Test | What it verifies |
|------|------------------|
| Open 3 interactive sessions on same connection | All 3 `active`, independent state |
| Parallel commands in 3 sessions | Each session's CWD stays independent |
| 4th session exceeds `sessionMaxPerConnection` | Throws session limit error |
| Close 1 of 3 sessions | Other 2 remain active and functional |

### 5. `policy-e2e.test.ts` — Policy engine through real SSH

Uses the `createRegistry()` + `createPolicyEngine()` fixtures. Tests `policy.evaluate()` against real `Profile` objects mapped to the 3 containers.

| Test | Profile | Command | Expected Decision | Rationale |
|------|---------|---------|-------------------|-----------|
| Viewer can read | viewer | `ls -la` | allow | read-only in viewer's allowed classes |
| Viewer cannot run safe | viewer | `npm install` | deny | safe not in viewer's allowed classes |
| Viewer cannot sudo | viewer | `sudo whoami` | deny | privileged not in viewer's allowed classes |
| Operator can run safe | operator | `npm install` | allow | safe in operator's allowed classes on dev |
| Operator destructive needs approval | operator | `rm -rf /tmp/x` | require-approval | destructive + ask-destructive |
| Admin destructive needs approval | admin | `rm -rf /tmp/x` | require-approval | destructive + ask-destructive |
| Admin privileged needs approval | admin | `sudo whoami` | require-approval | privileged + ask-destructive |
| Denylist always wins | admin | `rm -rf /` | deny | denylist match overrides everything |
| Auto mode skips approval | admin (auto) | `rm -rf /tmp/x` | allow | approvalPolicy: auto |
| Denylist with actual exec | admin | `curl ... \| sh` | deny | never reaches SSH |

### 6. `session-ttl.test.ts` — Session TTL and idle reaper

| Test | What it verifies |
|------|------------------|
| Session with 1s TTL expires after 1.5s | `isExpired()` returns true |
| `reapExpiredSessions()` removes expired session | Session deleted from connection |
| Idle connection reaped after timeout | `reapIdleConnections()` closes connection with 0 sessions |
| Active session prevents connection reap | Connection with active session stays alive |

### 7. `sudo-stdin.test.ts` — Privileged-command sudo password piping

| Test | What it verifies |
|------|------------------|
| `sudo -S whoami` returns root | Password piped via stdin, exit code 0 |
| Wrong sudo password fails | Auth failure error, no password in error message |
| `sudo -S cat /etc/shadow` works | Root-only file accessible |
| Password not in remote process list | `ps aux` output doesn't contain the password |

### 8. `cancellation.test.ts` — In-band signal cancellation

| Test | What it verifies |
|------|------------------|
| `sleep 30` with 2s timeout | Timeout error, remote process killed |
| Background session `close()` sends TERM | Process exits after close |
| Output cap truncates large output | `yes \| head -n 100000` output capped at 1MB |

### 9. `audit-e2e.test.ts` — Audit log integration

| Test | What it verifies |
|------|------------------|
| Successful command produces audit record | Correct profile, command, exitCode, durationMs |
| Policy-denied command logged with deny decision | `decision: 'deny'` in audit record |
| Secrets redacted in audit command field | AWS key pattern masked |
| Error path still writes audit record | Failed command has audit entry with error field |

## NPM Scripts

```json
{
  "test": "cross-env SSH_MCP_DISABLE_MAIN=1 vitest --run",
  "test:unit": "cross-env SSH_MCP_DISABLE_MAIN=1 vitest --run test/unit/ test/property/",
  "test:integration": "cross-env SSH_MCP_DISABLE_MAIN=1 vitest --run test/integration/"
}
```

## CI Updates

The `.github/workflows/ci.yml` test job updates to start all 3 containers and set all 3 passwords:

```yaml
services:
  ssh-admin:
    image: lscr.io/linuxserver/openssh-server:latest
    env:
      USER_NAME: admin
      PASSWORD_ACCESS: "true"
      USER_PASSWORD: secret
      SUDO_ACCESS: "true"
    ports: [2222:2222]
  ssh-viewer:
    image: lscr.io/linuxserver/openssh-server:latest
    env:
      USER_NAME: viewer
      PASSWORD_ACCESS: "true"
      USER_PASSWORD: viewpass
    ports: [2223:2222]
  ssh-operator:
    image: lscr.io/linuxserver/openssh-server:latest
    env:
      USER_NAME: operator
      PASSWORD_ACCESS: "true"
      USER_PASSWORD: oppass
      SUDO_ACCESS: "true"
    ports: [2224:2222]
```

Environment variables for credential resolution:
```yaml
env:
  SSH_MCP_ADMIN_PASSWORD: secret
  SSH_MCP_OPERATOR_PASSWORD: oppass
  SSH_MCP_VIEWER_PASSWORD: viewpass
  SSH_MCP_ADMIN_SUDO_PASSWORD: secret
  SSH_MCP_OPERATOR_SUDO_PASSWORD: oppass
```

## Existing Test Migration

The existing 3 integration test files (`ssh-exec.test.ts`, `ssh-session.test.ts`, `ssh-sftp.test.ts`) remain unchanged. They already use the admin container (port 2222) and import from `helpers.ts`. The `helpers.ts` file stays as-is. A new `fixtures.ts` builds on top of `helpers.ts` (imports `SSH_HOST` etc.) and adds the new profile/registry/policy/connection fixtures. New test files import from `fixtures.ts`. No changes to existing test files needed.

The policy E2E tests (`policy-e2e.test.ts`) verify `policy.evaluate()` decisions against real `Profile` objects — they do NOT execute commands via SSH (actual execution with policy gating is covered by the other test files that call `conn.exec()`).

## Expected Outcome

- **Before:** 21 integration tests, 1 container, basic exec/session/sftp only
- **After:** ~60 integration tests, 3 containers, full multi-host + session + policy + security coverage
- **Total test count:** ~170 (109 unit/property + ~60 integration)
- **CI time impact:** ~+5s (3 container health checks + parallel test execution)
