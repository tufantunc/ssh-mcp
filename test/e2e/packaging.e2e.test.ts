import { describe, it, expect } from 'vitest';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { mkdtemp, rm, writeFile } from 'fs/promises';
import { existsSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import { serverBuilt, SERVER_ENTRY } from './harness.js';
import { assertAvailable } from '../integration/helpers.js';

const run = promisify(execFile);
const REPO_ROOT = resolve(import.meta.dirname, '../..');

/**
 * Packaging checks that need no SSH server.
 *
 * The OTEL integration imported @opentelemetry/resources and
 * semantic-conventions without declaring them; they resolved only because npm
 * hoists transitive dependencies to the top level. Under a strict resolver —
 * pnpm's default, or yarn PnP — tracing would fail at runtime for anyone who
 * installed the published package. This proves the declarations are real.
 */
async function havePnpm(): Promise<boolean> {
  try {
    await run('pnpm', ['--version']);
    return true;
  } catch {
    return false;
  }
}

// The pnpm case is the only real verification that the OTEL imports are
// declared rather than resolved by npm's hoisting, so a CI run without pnpm
// would be quietly missing the check it exists for.
const pnpmAvailable = assertAvailable(await havePnpm(), 'pnpm (run `corepack enable`)');

describe.skipIf(!serverBuilt)('E2E — packaging', () => {
  it('starts and reports a version consistent with package.json', async () => {
    const pkg = JSON.parse(
      await import('fs/promises').then((fs) => fs.readFile(join(REPO_ROOT, 'package.json'), 'utf8')),
    );
    const { SERVER_VERSION } = await import('../../src/version.js');
    expect(SERVER_VERSION).toBe(pkg.version);
  });

  it('refuses removed v1 flags with a migration hint instead of failing later', async () => {
    const { SSH_MCP_DISABLE_MAIN: _omit, ...env } = process.env;
    await expect(
      run('node', [SERVER_ENTRY, '--host=x', '--user=y', '--password=secret'], { env: env as NodeJS.ProcessEnv }),
    ).rejects.toMatchObject({ stderr: expect.stringContaining('removed in v2') });
  }, 20000);

  it('requires a bearer token for the HTTP transport', async () => {
    const { SSH_MCP_DISABLE_MAIN: _omit, ...env } = process.env;
    await expect(
      run('node', [SERVER_ENTRY, '--host=x', '--user=y', '--transport=http'], { env: env as NodeJS.ProcessEnv }),
    ).rejects.toMatchObject({ stderr: expect.stringContaining('bearerToken') });
  }, 20000);
});

describe.skipIf(!serverBuilt || !pnpmAvailable)('E2E — strict dependency resolution', () => {
  // pnpm does not hoist, so an undeclared import fails to resolve here even
  // though it works under npm.
  it('resolves every runtime import under pnpm, including the OTEL chain', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ssh-mcp-pnpm-'));
    try {
      const pkg = JSON.parse(
        await import('fs/promises').then((fs) => fs.readFile(join(REPO_ROOT, 'package.json'), 'utf8')),
      );
      await writeFile(join(dir, 'package.json'), JSON.stringify({
        name: 'ssh-mcp-resolution-probe',
        private: true,
        type: 'module',
        dependencies: pkg.dependencies,
      }, null, 2));

      await run('pnpm', ['install', '--ignore-scripts', '--no-frozen-lockfile'], { cwd: dir, timeout: 180_000 });

      // Import exactly what tracer.ts pulls in at runtime.
      const probe = join(dir, 'probe.mjs');
      await writeFile(probe, `
        const mods = [
          '@opentelemetry/api',
          '@opentelemetry/sdk-node',
          '@opentelemetry/exporter-trace-otlp-http',
          '@opentelemetry/resources',
          '@opentelemetry/semantic-conventions',
          '@modelcontextprotocol/sdk/server/mcp.js',
          'ssh2',
          'smol-toml',
          'zod',
        ];
        for (const m of mods) await import(m);
        const { resourceFromAttributes } = await import('@opentelemetry/resources');
        const { ATTR_SERVICE_NAME } = await import('@opentelemetry/semantic-conventions');
        if (typeof resourceFromAttributes !== 'function') throw new Error('resourceFromAttributes missing');
        if (typeof ATTR_SERVICE_NAME !== 'string') throw new Error('ATTR_SERVICE_NAME missing');
        console.log('resolved');
      `);

      const { stdout } = await run('node', [probe], { cwd: dir, timeout: 60_000 });
      expect(stdout).toContain('resolved');
      expect(existsSync(join(dir, 'node_modules'))).toBe(true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }, 300000);
});
