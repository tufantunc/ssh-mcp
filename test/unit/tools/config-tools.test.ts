import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtemp, readFile, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { createHarness, textOf, type Harness } from './harness.js';
import { ConfigReloader, type ReloadOutcome } from '../../../src/config/reload.js';
import { defaultsFromArgv } from '../../../src/cli.js';
import { loadConfigWithDigest } from '../../../src/config/loader.js';
import type { ConnectionRegistry } from '../../../src/ssh/connection-registry.js';
import { TOOL_DESCRIPTIONS, getToolHashes } from '../../../src/tools/registry.js';
import { makeConfigDir, type ConfigDir } from '../config/helpers.js';
import { buildReloader } from '../config/reload-rig.js';

/** A value that lives only in the config file. No tool result may contain it. */
const CANARY = 'canary-host-41c7';

const TOML = `
[[profiles]]
name = "dev"
host = "${CANARY}"
user = "test"
group = "dev"
`;

let h: Harness;
let dir: ConfigDir;
let auditDir: string;
let auditPath: string;

beforeEach(async () => {
  dir = await makeConfigDir('ssh-mcp-config-tool-');
  auditDir = await mkdtemp(join(tmpdir(), 'ssh-mcp-config-tool-audit-'));
  auditPath = join(auditDir, 'audit.log');
  // The reloader prints its outcome to stderr; keep the test output quiet.
  vi.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(async () => {
  vi.restoreAllMocks();
  await h?.close();
  await dir.cleanup();
  await rm(auditDir, { recursive: true, force: true });
});

/** A real reloader over a real file, behind the stubbed tool harness. */
async function startWithReloader(): Promise<{ path: string; reloader: ConfigReloader; registry: ConnectionRegistry }> {
  const path = await dir.write(TOML);
  const { config, sha256 } = await loadConfigWithDigest(path, {});
  const { registry, reloader } = buildReloader({ config, path, auditPath, sha256 });
  h = await createHarness({}, { reloader });
  return { path, reloader, registry };
}

const call = (args: Record<string, unknown> = {}) =>
  h.client.callTool({ name: 'reload-config', arguments: args }) as Promise<any>;

describe('reload-config', () => {
  it('is registered, with an optional action of status or reload', async () => {
    await startWithReloader();
    const { tools } = await h.client.listTools();
    const tool = tools.find((t) => t.name === 'reload-config');

    expect(tool).toBeDefined();
    expect(tool!.description).toBe(TOOL_DESCRIPTIONS['reload-config']);
    expect(Object.keys(tool!.inputSchema.properties ?? {})).toEqual(['action']);
    expect(tool!.inputSchema.required ?? []).toEqual([]);
    expect((tool!.inputSchema.properties as any).action.enum).toEqual(['status', 'reload']);
    // It changes the server's state, so it must not invite auto-approval as read-only.
    expect(tool!.annotations?.readOnlyHint).not.toBe(true);
  });

  it('has its description hash in getToolHashes()', () => {
    expect(getToolHashes()['reload-config']).toMatch(/^[0-9a-f]{16}$/);
  });

  it('reports status by default: path, source, loadedAt and sha256, and no file contents', async () => {
    const { path, reloader } = await startWithReloader();
    const status = reloader.status();

    const res = await call();
    const text = textOf(res);

    expect(res.isError).toBeFalsy();
    expect(text).toContain(path);
    expect(text).toContain('Source: file');
    expect(text).toContain(status.loadedAt);
    expect(text).toContain(status.sha256!);
    expect(text).toMatch(/Last reload: none/);
    expect(text).not.toContain(CANARY);
    expect(text).not.toContain('[[profiles]]');
    // Reading status reloads nothing.
    expect(reloader.status().last).toBeNull();
  });

  it('status includes a summary of the last reload', async () => {
    await startWithReloader();
    await dir.write(TOML.replace('user = "test"', 'user = "test2"'));
    await call({ action: 'reload' });

    const text = textOf(await call({ action: 'status' }));

    expect(text).toMatch(/Last reload: .*\(tool\), applied/);
    expect(text).toContain('Profiles: changed dev (user).');
    expect(text).not.toContain(CANARY);
  });

  it('status after a refused reload says refused, and that nothing changed', async () => {
    await startWithReloader();
    await dir.write('[[profiles]\n');
    await call({ action: 'reload' });

    const text = textOf(await call({ action: 'status' }));

    expect(text).toMatch(/Last reload: .*\(tool\), refused\./);
    expect(text).toContain('Nothing was changed.');
  });

  it('status after a failure past the swap says so, and not that nothing changed', async () => {
    const { registry } = await startWithReloader();
    vi.spyOn(registry, 'applyConfig').mockImplementationOnce(() => {
      throw new TypeError('boom');
    });
    await dir.write(TOML.replace('user = "test"', 'user = "test2"'));
    await call({ action: 'reload' });

    const text = textOf(await call({ action: 'status' }));

    expect(text).toMatch(/Last reload: .*\(tool\), failed after the swap began\./);
    expect(text).not.toContain('Nothing was changed.');
  });

  it('reload applies a valid file and returns formatOutcome', async () => {
    const { reloader } = await startWithReloader();
    await dir.write(`${TOML}\n[[profiles]]\nname = "extra"\nhost = "h"\nuser = "u"\ngroup = "dev"\n`);

    const res = await call({ action: 'reload' });

    expect(res.isError).toBeFalsy();
    const outcome = reloader.status().last as ReloadOutcome;
    expect(outcome.ok).toBe(true);
    expect(textOf(res)).toBe(reloader.formatOutcome(outcome));
    expect(textOf(res)).toContain('added extra');
  });

  it('reload of a refused config returns isError and the refusal, quoting nothing from the file', async () => {
    const { reloader } = await startWithReloader();
    await dir.write(`[[profiles]\nname = "${CANARY}"\n`);

    const res = await call({ action: 'reload' });
    const text = textOf(res);

    expect(res.isError).toBe(true);
    expect(text).toMatch(/refused: ConfigParseError/);
    expect(text).toContain('Nothing was changed.');
    expect(text).toBe(reloader.formatOutcome(reloader.status().last!));
    expect(text).not.toContain(CANARY);
  });

  it('is not approval-gated, and the reloader audits the attempt', async () => {
    await startWithReloader();
    await dir.write(TOML.replace('user = "test"', 'user = "test2"'));
    h.setApproval(false);

    const res = await call({ action: 'reload' });

    expect(res.isError).toBeFalsy();
    expect(h.approvalPrompts()).toBe(0);
    expect(h.execCalls).toHaveLength(0);
    const records = (await readFile(auditPath, 'utf8')).split('\n').filter(Boolean).map((l) => JSON.parse(l));
    expect(records.map((r) => r.binary)).toEqual(['config:reload']);
    expect(records[0].mcpRequestId).not.toBeUndefined();
  });

  it('returns isError with a safe message when reload rejects', async () => {
    const { reloader } = await startWithReloader();
    vi.spyOn(reloader, 'reload').mockRejectedValueOnce(new TypeError(`defect ${CANARY}`));

    const res = await call({ action: 'reload' });

    expect(res.isError).toBe(true);
    expect(textOf(res)).toMatch(/TypeError/);
    expect(textOf(res)).not.toContain(CANARY);
  });

  it('on an unconfigured server, answers status and reloads a file written since startup', async () => {
    // The one tool that does not refuse while unconfigured: writing the file and reloading
    // is how such a server becomes configured (spec: unconfigured -> configured).
    const path = join(dir.dir, 'config.toml');
    const config = { defaults: defaultsFromArgv({}), profiles: [] };
    const { registry, reloader } = buildReloader({ config, path, auditPath, source: 'unconfigured' });
    h = await createHarness({}, { reloader });

    const status = textOf(await call());
    expect(status).toContain(`Config file: ${path}`);
    expect(status).toContain('Source: unconfigured');
    expect(status).toContain('sha256: none');

    await dir.write(TOML);
    const res = await call({ action: 'reload' });
    expect(res.isError).toBeFalsy();
    expect(textOf(res)).toContain('Profiles: added dev.');
    expect(registry.listAllProfiles().map((p) => p.name)).toEqual(['dev']);
    expect(textOf(await call())).toContain('Source: file');
  });

  it('refuses without a reloader rather than disappearing from the tool list', async () => {
    h = await createHarness();
    const { tools } = await h.client.listTools();
    expect(tools.map((t) => t.name)).toContain('reload-config');

    const res = await call();
    expect(res.isError).toBe(true);
    expect(textOf(res)).toMatch(/not available/);
  });
});
