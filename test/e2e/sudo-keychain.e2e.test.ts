import { randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SSH_HOST } from '../integration/helpers.js';
import { PORTS } from '../integration/fixtures.js';
import { describe, it, expect } from 'vitest';
import { startE2E, e2eAvailable, textOf } from './harness.js';

// Opt in: this test writes a disposable secret to the developer's actual OS
// keychain. CI and ordinary test runs must not assume a desktop keychain.
const enabled = process.env.SSH_MCP_TEST_KEYCHAIN === '1';
const run = promisify(execFile);

describe.skipIf(!enabled)('E2E — sudo credentials from the native keychain', () => {
  it('uses the current keychain entry only for approved privileged calls', async () => {
    if (!await e2eAvailable()) throw new Error('Start the disposable SSH fixtures and build the server first.');
    // @ts-ignore — optional dependency, deliberately required by this opt-in test
    const { Entry } = await import('@napi-rs/keyring');
    const service = 'ssh-mcp-test';
    const account = randomUUID();
    const entry = new Entry(service, account);
    const wrong = 'fictional-wrong-keychain-password';
    const envCanary = 'fictional-wrong-env-password';
    // This is the public, disposable admin fixture password in docker-compose.yml.
    const correct = 'secret';
    const e2e = await startE2E({
      defaults: 'approvalMode = "ask-all"\napprovalGrantTtlMs = 0',
      adminProfile: `sudoKeychainEntry = "${service}/${account}"\ntty = true`,
      env: { SSH_MCP_ADMIN_SUDO_PASSWORD: envCanary },
    });
    const elevate = () => e2e.callTool('privileged-command', { command: 'id -u' });
    const checkNoSecrets = (result: unknown) => {
      const serialized = JSON.stringify(result);
      expect(serialized.includes(wrong)).toBe(false);
      expect(serialized.includes(envCanary)).toBe(false);
      expect(serialized.includes(correct)).toBe(false);
    };
    let stored = false;
    try {
      const ordinary = await e2e.callTool('read-command', { command: 'whoami' });
      expect(ordinary.isError).toBeFalsy();
      expect(textOf(ordinary).trim()).toBe('admin');

      e2e.setApproval(false);
      const denied = await elevate();
      expect(denied.isError).toBe(true);
      expect(textOf(denied)).toContain('APPROVAL_DENIED');
      e2e.setApproval(true);

      // The entry does not exist: approval must not turn into an env fallback.
      const missing = await elevate();
      expect(missing.isError).toBe(true);
      expect(textOf(missing)).toMatch(/sudo keychain/i);
      checkNoSecrets(missing);

      // A wrong credential must fail before successful sudo.
      await entry.setPassword(wrong);
      stored = true;
      const invalid = await elevate();
      expect(invalid.isError).toBe(true);
      expect(textOf(invalid)).toMatch(/\[exit [1-9]\d*\]/);
      checkNoSecrets(invalid);

      // Replace the secret without restarting the same MCP child or connection.
      await entry.setPassword(correct);
      const success = await elevate();
      expect(success.isError).toBeFalsy();
      expect(textOf(success)).toMatch(/(^|\n)0(?:\r?\n|$)/);
      checkNoSecrets(success);

      // Even immediately after successful sudo, the next call must authenticate
      // with the current credential rather than reuse a sudo timestamp.
      await entry.setPassword(wrong);
      const invalidAfterSuccess = await elevate();
      expect(invalidAfterSuccess.isError).toBe(true);
      expect(textOf(invalidAfterSuccess)).toMatch(/\[exit [1-9]\d*\]/);
      checkNoSecrets(invalidAfterSuccess);

      // The command must stop working as soon as its keychain entry is removed.
      await entry.deletePassword();
      stored = false;
      const removed = await elevate();
      expect(removed.isError).toBe(true);
      expect(textOf(removed)).toMatch(/sudo keychain/i);
      checkNoSecrets(removed);
      expect(e2e.prompts).toHaveLength(7);
    } finally {
      try {
        await e2e.cleanup();
      } finally {
        if (stored) await entry.deletePassword();
      }
    }
  }, 120000);

  it('uses an SSH private key independently of the sudo keychain entry', async () => {
    if (!await e2eAvailable()) throw new Error('Start the disposable SSH fixtures and build the server first.');
    // This test installs a temporary public key into the local Docker fixture,
    // never into an externally supplied SSH host.
    if (!['127.0.0.1', 'localhost'].includes(SSH_HOST)) {
      throw new Error('Private-key keychain test requires local Docker SSH fixtures.');
    }
    const { stdout } = await run('docker', ['compose', 'ps', '-q', 'ssh-admin']);
    const container = stdout.trim().split('\n')[0];
    if (!container) throw new Error('ssh-admin fixture not found; set COMPOSE_PROJECT_NAME and COMPOSE_FILE.');
    // @ts-ignore — optional dependency, deliberately required by this opt-in test
    const { Entry } = await import('@napi-rs/keyring');
    const account = randomUUID();
    const entry = new Entry('ssh-mcp-test', account);
    const label = `ssh-mcp-keychain-test-${account}`;
    const dir = await mkdtemp(join(tmpdir(), 'ssh-mcp-keychain-key-'));
    let e2e: Awaited<ReturnType<typeof startE2E>> | undefined;
    let authorized = false;
    let stored = false;
    try {
      const keyPath = join(dir, 'id_ed25519');
      await run('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', label, '-f', keyPath]);
      const pub = (await readFile(`${keyPath}.pub`, 'utf8')).trim();
      // ssh-keygen emits a base64 public key and our alphanumeric comment.
      // Use a positional argument, never interpolate the public key in a shell.
      authorized = true;
      await run('docker', ['exec', container, 'sh', '-c',
        'mkdir -p /config/.ssh && printf "\\n%s\\n" "$1" >> /config/.ssh/authorized_keys ' +
        '&& chown -R admin /config/.ssh && chmod 700 /config/.ssh && chmod 600 /config/.ssh/authorized_keys',
        'sh', pub]);
      e2e = await startE2E({
        defaults: 'approvalMode = "ask-all"\napprovalGrantTtlMs = 0',
        extra: `
[[profiles]]
name = "keychain-key"
host = "${SSH_HOST}"
port = ${PORTS.admin}
user = "admin"
auth = "key"
keyRef = ${JSON.stringify(keyPath)}
role = "admin"
group = "dev"
sudoKeychainEntry = "ssh-mcp-test/${account}"
`,
        // The resolver accepts env fallbacks even for auth=key. Disable them
        // for this profile to prove it cannot authenticate with a password.
        env: { SSH_MCP_KEYCHAIN_KEY_PASSWORD: '', SSH_MCP_PASSWORD: '',
          SSH_MCP_KEYCHAIN_KEY_PASSPHRASE: '', SSH_MCP_PASSPHRASE: '' },
      });
      const ordinary = await e2e.callTool('read-command', { command: 'whoami', profile: 'keychain-key' });
      expect(ordinary.isError).toBeFalsy();
      expect(textOf(ordinary).trim()).toBe('admin');
      const missing = await e2e.callTool('privileged-command', { command: 'id -u', profile: 'keychain-key' });
      expect(missing.isError).toBe(true);
      expect(textOf(missing)).toMatch(/sudo keychain/i);
      stored = true;
      await entry.setPassword('secret');
      const success = await e2e.callTool('privileged-command', { command: 'id -u', profile: 'keychain-key' });
      expect(success.isError).toBeFalsy();
      expect(textOf(success)).toMatch(/(^|\n)0(?:\r?\n|$)/);
      expect(JSON.stringify(success)).not.toContain('secret');
      expect(e2e.prompts).toHaveLength(3);
    } finally {
      try {
        await e2e?.cleanup();
      } finally {
        try {
          if (stored) await entry.deletePassword();
        } finally {
          try {
            if (authorized) await run('docker', ['exec', container, 'sh', '-c',
              'if [ -f /config/.ssh/authorized_keys ]; then sed -i "/ $1$/d" /config/.ssh/authorized_keys; fi',
              'sh', label]);
          } finally {
            await rm(dir, { recursive: true, force: true });
          }
        }
      }
    }
  }, 120000);
});
