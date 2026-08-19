import { describe, it, expect } from 'vitest';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { mkdtemp, rm, writeFile, readFile } from 'fs/promises';
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

  /**
   * Spawns the server with the home directory pointed at an empty temp dir.
   *
   * Every one of these tests asserts on a message the server prints *before* it
   * connects, and the config file is read first — so without this they read the
   * developer's real config, and since a present-but-unusable config now refuses
   * to start rather than being silently ignored, they fail on any machine that has
   * one. That is the intended behaviour change catching its own test suite.
   */
  async function runIsolated(args: string[]) {
    const { SSH_MCP_DISABLE_MAIN: _omit, ...env } = process.env;
    const home = await mkdtemp(join(tmpdir(), 'ssh-mcp-e2e-home-'));
    try {
      return await run('node', args, {
        env: {
          ...(env as NodeJS.ProcessEnv),
          HOME: home,
          USERPROFILE: home,
          XDG_CONFIG_HOME: join(home, '.config'),
          APPDATA: home,
        },
      });
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  }

  it('refuses removed v1 flags with a migration hint instead of failing later', async () => {
    await expect(
      runIsolated([SERVER_ENTRY, '--host=x', '--user=y', '--password=secret']),
    ).rejects.toMatchObject({ stderr: expect.stringContaining('removed in v2') });
  }, 20000);

  // #91: the CLI profile had no way to declare a host group, so it fell to the
  // strictest tier and `sudo` could never run without writing a config file.
  // A mistyped group must not quietly land back on those prod bindings — the
  // operator would read the refusal as policy rather than as their own typo.
  it('rejects an unknown --group instead of falling back to the strictest tier', async () => {
    await expect(
      runIsolated([SERVER_ENTRY, '--host=x', '--user=y', '--group=production']),
    ).rejects.toMatchObject({ stderr: expect.stringContaining('Invalid --group=production') });
  }, 20000);

  /**
   * How the error is *presented*, which only a spawned process can show.
   *
   * Every failure used to go through `console.error('Fatal error:', error)`,
   * which prints the Error object: name, message, and a stack through
   * buildAppConfig and main. A mistyped flag therefore reached the operator
   * looking like a crash in our code, with the explanation we wrote for them
   * wrapped in frames that only matter to someone debugging this repo. It is
   * the first thing the reporter of #138 pasted, and it told them nothing.
   *
   * The complementary half — a real defect keeps its stack — is asserted in
   * test/unit/cli-fatal-reporting.test.ts, which can construct one.
   */
  it('reports an invocation mistake as a message, with exit status 2', async () => {
    // --group is only validated on the no-config-file path — `resolveHostGroup` is called
    // from the CLI-args branch of `buildAppConfig` — so the run cannot be pinned with
    // --config; `runIsolated` points the home directory at an empty temp dir instead.
    const err = await runIsolated([SERVER_ENTRY, '--host=x', '--user=y', '--group=production'])
      .then(
        () => { throw new Error('expected a non-zero exit for --group=production'); },
        (e: { stderr: string; code: number }) => e,
      );

    // Asserted on the report rather than the whole stream: an unrelated Node
    // ExperimentalWarning can carry indented `at ` frames of its own.
    const report = err.stderr.slice(err.stderr.indexOf('Invalid --group=production'));
    expect(report).not.toBe('');
    expect(report.trimEnd()).toBe(
      'Invalid --group=production. Expected one of: prod, staging, dev.',
    );
    expect(err.stderr).not.toContain('Fatal error:');
    // The distinction reportFatal draws is only machine-readable through this.
    expect(err.code).toBe(2);
  }, 20000);

  /**
   * The image has to satisfy the server's own permission check.
   *
   * `mkdir -p` under Docker's default umask produces 0755, and checkPermissions
   * refuses a config whose directory is group- or world-readable — so a container
   * with a config bind-mounted at the default path met that refusal on every
   * start, and the remedy it printed was a chmod on a directory baked into the
   * image. Asserted against the Dockerfile text rather than a built image as the
   * cheap proxy — the `test` job does have a Docker daemon (it brings up the sshd
   * containers), so a real `docker build` here is possible and would be stronger;
   * the mode is what drifts, and this catches that much.
   */
  it('builds a config directory the loader will accept', async () => {
    // Comment lines stripped: this repo comments heavily, so `# RUN chmod 700 …` in a
    // commented-out line would satisfy the positive assertion while the image builds 0755,
    // and a comment mentioning the old `--from=builder … config.default.toml` would fail
    // the negative one on a Dockerfile that is correct.
    const dockerfile = (await readFile(join(REPO_ROOT, 'Dockerfile'), 'utf8'))
      .split('\n')
      .filter((l) => !l.trimStart().startsWith('#'))
      .join('\n');
    expect(dockerfile).toMatch(/chmod 700 [^\n]*\.config/);
    // And the sources the runtime stage needs must come from somewhere that has
    // them: config.default.toml was copied --from=builder, which never had it.
    expect(dockerfile).not.toMatch(/--from=builder [^\n]*config\.default\.toml/);
  });

  it('requires a bearer token for the HTTP transport', async () => {
    await expect(
      runIsolated([SERVER_ENTRY, '--host=x', '--user=y', '--transport=http']),
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
