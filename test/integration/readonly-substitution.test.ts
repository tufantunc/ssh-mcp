import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { SSHConnection } from '../../src/ssh/connection.js';
import { resolveCredentials } from '../../src/config/credential-resolver.js';
import { classifyCommand } from '../../src/policy/classifier.js';
import { isSshServerUp, assertAvailable, SSH_HOST } from './helpers.js';
import { PORTS, profiles } from './fixtures.js';

/**
 * Reported privately as GHSA-r8hm-vpm8-cfh6.
 *
 * `read-command` refuses anything the classifier does not call `read-only`, and
 * the classifier rejected shell metacharacters with /[>;|]/ — a set that leaves
 * out `$(...)` and backticks. So `ls $(touch /tmp/x)` classified as read-only
 * while the remote shell still expanded and ran the inner command.
 *
 * Two halves have to hold for the report to be real, and both are asserted
 * here: the classifier must refuse the payload, and the remote shell must
 * actually execute a substitution when one reaches it.
 */
const up = await isSshServerUp(SSH_HOST, PORTS.viewer);
assertAvailable(up, `viewer (${SSH_HOST}:${PORTS.viewer})`);

describe('command substitution is not read-only', () => {
  const payloads = [
    'ls $(touch /tmp/proof)',
    'ls `touch /tmp/proof`',
    'cat /etc/hostname $(id)',
    'ls ${IFS}$(whoami)',
    'echo $(cat /etc/shadow)',
  ];

  it.each(payloads)('refuses %s', (command) => {
    expect(classifyCommand(command).class).not.toBe('read-only');
  });

  // The allowlisted commands themselves must keep working, or the fix has just
  // broken the tool it was protecting.
  it.each([
    'ls -la',
    'cat /etc/hostname',
    'df -h',
    'grep error /var/log/syslog',
    'systemctl status nginx',
  ])('still allows %s', (command) => {
    expect(classifyCommand(command).class).toBe('read-only');
  });
});

describe.skipIf(!up)('the remote shell does expand substitutions', () => {
  let conn: SSHConnection;
  let saved: NodeJS.ProcessEnv;

  beforeAll(async () => {
    saved = { ...process.env };
    process.env.SSH_MCP_VIEWER_PASSWORD = 'viewpass';
    conn = new SSHConnection(profiles.viewer, await resolveCredentials(profiles.viewer), new Map(), 'insecure');
    await conn.ensureConnected();
  }, 30000);

  afterAll(async () => {
    await conn?.close();
    if (saved) process.env = saved;
  });

  // Establishes the impact rather than assuming it: had such a command reached
  // the channel, the inner half would have run. This is why classification has
  // to stop it before execution — nothing downstream will.
  it('runs the inner command when a substitution reaches the channel', async () => {
    const marker = '/tmp/substitution-proof';
    await conn.exec(`rm -f ${marker}`);

    await conn.exec(`ls $(touch ${marker})`);

    const check = await conn.exec(`test -f ${marker} && echo CREATED || echo ABSENT`);
    expect(check.stdout.trim()).toBe('CREATED');

    await conn.exec(`rm -f ${marker}`);
  }, 30000);
});
