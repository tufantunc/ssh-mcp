import { describe, it, expect, afterEach, vi } from 'vitest';
import { startE2E, e2eAvailable, textOf, type StartOptions } from './harness.js';
import { PORTS } from '../integration/fixtures.js';
import { SSH_HOST } from '../integration/helpers.js';

/**
 * `reload-config` and SIGHUP through the built server over stdio: real argv parsing, the
 * real config file the process was started with, and the one reloader main() shares.
 */
let e2e: Awaited<ReturnType<typeof startE2E>>;
const available = await e2eAvailable();

afterEach(async () => { await e2e?.cleanup(); });

/** The harness's config plus an `operator` profile. */
const WITH_OPERATOR: StartOptions = {
  extra: `
[[profiles]]
name = "operator"
host = "${SSH_HOST}"
port = ${PORTS.operator}
user = "operator"
auth = "password"
role = "operator"
group = "dev"
`,
};

const SHA = /sha256: ([0-9a-f]{64})/;

describe.skipIf(!available)('E2E — reload-config over stdio', () => {
  it('reports status, then applies an edited file on reload', async () => {
    e2e = await startE2E();

    const before = await e2e.callTool('reload-config');
    const status = textOf(before);
    expect(before.isError).toBeFalsy();
    expect(status).toContain(`Config file: ${e2e.configPath}`);
    expect(status).toContain('Source: file');
    expect(status).toMatch(SHA);
    expect(status).toContain('Last reload: none.');
    // Status, never contents.
    expect(status).not.toContain('[[profiles]]');
    expect(status).not.toContain(`port = ${PORTS.admin}`);
    expect(textOf(await e2e.callTool('list-connections'))).not.toContain('operator');

    await e2e.rewriteConfig(WITH_OPERATOR);
    const res = await e2e.callTool('reload-config', { action: 'reload' });

    expect(res.isError).toBeFalsy();
    expect(textOf(res)).toContain('Profiles: added operator.');
    expect(textOf(await e2e.callTool('list-connections'))).toContain('operator');

    const after = textOf(await e2e.callTool('reload-config', { action: 'status' }));
    expect(after).toMatch(/Last reload: .* \(tool\), applied\./);
    expect(after.match(SHA)![1]).not.toBe(status.match(SHA)![1]);
  }, 30000);

  it('a refused reload is an error and changes nothing', async () => {
    e2e = await startE2E();
    const before = textOf(await e2e.callTool('reload-config'));

    await e2e.rewriteConfig('[[profiles]\nname = "broken"\n');
    const res = await e2e.callTool('reload-config', { action: 'reload' });

    expect(res.isError).toBe(true);
    expect(textOf(res)).toMatch(/refused: ConfigParseError/);
    expect(textOf(res)).toContain('Nothing was changed.');
    expect(textOf(res)).not.toContain('broken');
    const after = textOf(await e2e.callTool('reload-config'));
    expect(after.match(SHA)![1]).toBe(before.match(SHA)![1]);
    expect(textOf(await e2e.callTool('list-connections'))).toContain('admin');
  }, 30000);
});

describe.skipIf(!available || process.platform === 'win32')('E2E — SIGHUP reloads the config', () => {
  it('applies an edited file on SIGHUP, and the server keeps serving', async () => {
    e2e = await startE2E();
    await e2e.rewriteConfig(WITH_OPERATOR);

    process.kill(e2e.pid, 'SIGHUP');

    await vi.waitFor(
      async () => expect(textOf(await e2e.callTool('list-connections'))).toContain('operator'),
      { timeout: 10000, interval: 100 },
    );
    expect(textOf(await e2e.callTool('reload-config'))).toMatch(/Last reload: .* \(sighup\), applied\./);
  }, 30000);
});
