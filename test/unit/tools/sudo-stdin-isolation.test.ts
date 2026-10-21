import { describe, it, expect, afterEach } from 'vitest';
import { createHarness, textOf, type Harness } from './harness.js';

let h: Harness;

afterEach(async () => { await h?.close(); });

async function call(name: string, args: Record<string, unknown> = {}) {
  return h.client.callTool({ name, arguments: args }) as Promise<any>;
}

/**
 * GHSA-9m75-x2ch-j4jr: `sudo -S` only reads stdin when it actually needs a
 * password. Under NOPASSWD (or any policy that skips the prompt) the password
 * line stayed in the pipe and was inherited by the `sh -c` the wrapper runs,
 * so a command like `head -1` handed the password back in the tool result.
 *
 * Two layers pin the fix: the wrapper must point the child shell's stdin at
 * /dev/null so it can never read the password stream, and the output path must
 * scrub the configured sudo password verbatim, because the value is neither
 * token-shaped nor reliably high-entropy, so the pattern/entropy redactors
 * never saw it.
 */
describe('privileged-command stdin isolation (GHSA-9m75-x2ch-j4jr)', () => {
  it('closes the child shell off from the password stream', async () => {
    h = await createHarness();
    const res = await call('privileged-command', { command: 'head -1' });
    expect(res.isError).toBeFalsy();
    const exec = h.execCalls.at(-1)!;
    // sudo still gets the password via stdin for the prompt case…
    expect(exec.stdin).toBe('sudo-secret\n');
    // …but the wrapped script re-points fd 0 before the user command runs,
    // so an unread password line can never reach it.
    expect(exec.command).toBe(`sudo -p "" -S sh -c 'exec 0</dev/null; head -1'`);
  });

  it('scrubs the configured sudo password from the tool output', async () => {
    h = await createHarness();
    // A stdin-reading command under a no-prompt sudo policy echoes the
    // password back. Short and low-entropy on purpose: the entropy scan must
    // not be what catches it.
    h.setExecResult({ stdout: 'sudo-secret\n' });
    const res = await call('privileged-command', { command: 'head -1' });
    const text = textOf(res);
    expect(text).not.toContain('sudo-secret');
    expect(text).toContain('[REDACTED:secret:11]');
  });
});
