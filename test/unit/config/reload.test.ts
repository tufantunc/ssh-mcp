import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createHash } from 'crypto';
import { mkdtemp, readFile, rm } from 'fs/promises';
import { platform, tmpdir } from 'os';
import { join } from 'path';
import { ConfigReloader, installSighupReload, type ReloadOutcome } from '../../../src/config/reload.js';
import { aclOptionsFromArgv, defaultsFromArgv } from '../../../src/cli.js';
import { loadConfigWithDigest } from '../../../src/config/loader.js';
import type { ConfigSource } from '../../../src/config/loaded.js';
import { ConnectionRegistry } from '../../../src/ssh/connection-registry.js';
import { PolicyEngine, resolvePolicyRules } from '../../../src/policy/engine.js';
import { AuditStore } from '../../../src/audit/store.js';
import { CommandQuota } from '../../../src/policy/quota.js';
import type { AppConfig, AuditRecord, Profile } from '../../../src/types.js';
import { makeConfigDir, type ConfigDir } from './helpers.js';
import { buildReloader, STARTED_AT } from './reload-rig.js';

/** A value that lives only in the config file. Nothing the reloader prints may contain it. */
const CANARY = 'canary-host-9f3a';
const onWindows = platform() === 'win32';

const BASE = `
[[profiles]]
name = "dev"
host = "${CANARY}"
user = "test"
group = "dev"
`;

const profileToml = (name: string, extra = '') => `
[[profiles]]
name = "${name}"
host = "${name}.example.test"
user = "u"
group = "dev"
${extra}
`;

let dir: ConfigDir;
let auditDir: string;
let stderr: string[];

beforeEach(async () => {
  dir = await makeConfigDir('ssh-mcp-reload-');
  auditDir = await mkdtemp(join(tmpdir(), 'ssh-mcp-reload-audit-'));
  stderr = [];
  vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => {
    stderr.push(a.map(String).join(' '));
  });
});

afterEach(async () => {
  vi.restoreAllMocks();
  await dir.cleanup();
  await rm(auditDir, { recursive: true, force: true });
});

interface Harness {
  path: string;
  registry: ConnectionRegistry;
  policy: PolicyEngine;
  audit: AuditStore;
  localPath: { transferRoot?: string };
  reloader: ConfigReloader;
}

function build(
  config: AppConfig,
  path: string,
  source: ConfigSource = 'file',
  sha256: string | null = null,
): Harness {
  const localPath = { transferRoot: config.defaults.transferRoot };
  const auditPath = join(auditDir, 'audit.log');
  return { path, ...buildReloader({ config, path, auditPath, source, sha256, localPath }) };
}

const sha256Of = async (path: string) => createHash('sha256').update(await readFile(path)).digest('hex');

/** A server started from `toml`, loaded through the same loader the reload uses. */
async function startFrom(toml: string, source: ConfigSource = 'file'): Promise<Harness> {
  const path = await dir.write(toml);
  const { config, sha256 } = await loadConfigWithDigest(path, {});
  return build(config, path, source, source === 'file' ? sha256 : null);
}

async function auditRecords(h: Harness): Promise<AuditRecord[]> {
  await h.audit.close();
  const text = await readFile(join(auditDir, 'audit.log'), 'utf8').catch(() => '');
  return text.split('\n').filter(Boolean).map((l) => JSON.parse(l) as AuditRecord);
}

/** Everything a refused reload must leave alone. */
function snapshot(h: Harness) {
  return {
    config: (h.registry as any).config,
    compiled: (h.policy as any).compiled,
    localPath: h.localPath,
    transferRoot: h.localPath.transferRoot,
    generation: h.registry.generation,
    sha256: h.reloader.status().sha256,
    loadedAt: h.reloader.status().loadedAt,
  };
}

/**
 * The one check every refusal makes: the same objects by reference, and the same
 * generation, so a failed reload does not invalidate grants either.
 */
function expectUnchanged(h: Harness, before: ReturnType<typeof snapshot>) {
  const now = snapshot(h);
  expect(now.config).toBe(before.config);
  expect(now.compiled).toBe(before.compiled);
  expect(now.localPath).toBe(before.localPath);
  expect(now.transferRoot).toBe(before.transferRoot);
  expect(now.generation).toBe(before.generation);
  expect(now.sha256).toBe(before.sha256);
  expect(now.loadedAt).toBe(before.loadedAt);
}

function expectNoCanary(h: Harness, outcome: ReloadOutcome) {
  expect(JSON.stringify(outcome)).not.toContain(CANARY);
  expect(h.reloader.formatOutcome(outcome)).not.toContain(CANARY);
  expect(stderr.join('\n')).not.toContain(CANARY);
}

/**
 * A planted connection whose close order and sessions the test controls. applyConfig
 * reads `profile`, calls `replaceProfile` on a kept one and `retire` on one it closes,
 * and hands those back; the reloader reads `listSessions` and calls `close`.
 */
function plant(
  h: Harness,
  name: string,
  sessions: string[],
  log: string[],
  close: () => Promise<void> = async () => {},
) {
  let profile = h.registry.listAllProfiles().find((p) => p.name === name) as Profile;
  const conn = {
    get profile() {
      return profile;
    },
    replaceProfile(p: Profile) {
      profile = p;
    },
    retired: false,
    retire() {
      this.retired = true;
    },
    listSessions: () =>
      sessions.map((s) => ({ name: s, toInfo: () => ({ type: 'background' }) })),
    close: async () => {
      log.push(name);
      await close();
    },
  };
  (h.registry as any).connections.set(name, conn);
  return conn;
}

describe('ConfigReloader: a refused reload changes nothing', () => {
  // Each case also proves its canary would have leaked: the raw error from the layer
  // that refuses does quote it, so the absence below is the reloader's doing.
  const cases: { name: string; toml: string; raw: (path: string) => Promise<unknown> }[] = [
    {
      name: 'malformed TOML',
      toml: `[[profiles]\nname = "${CANARY}"\n`,
      raw: (path) => loadConfigWithDigest(path, {}),
    },
    {
      name: 'a schema violation',
      toml: `${BASE}auth = "${CANARY}"\n"${CANARY}" = 1\n`,
      raw: (path) => loadConfigWithDigest(path, {}),
    },
    {
      name: 'a bad denylist regex',
      toml: `${BASE}\n[policy]\ndenylist = ["(${CANARY}"]\n`,
      raw: async (path) => {
        const { config: c } = await loadConfigWithDigest(path, {});
        return new PolicyEngine(resolvePolicyRules(c.profiles, c.policy));
      },
    },
    {
      name: 'a cross-check failure',
      toml: BASE.replace('user = "test"', `user = "test"\nrole = "${CANARY}"`),
      raw: async (path) => {
        const { config: c } = await loadConfigWithDigest(path, {});
        return resolvePolicyRules(c.profiles, c.policy);
      },
    },
    {
      // Role and group names are keys, so they land in the schema issue path.
      name: 'a schema violation under a role and group named in the file',
      toml: `${BASE}\n[policy.roleBindings.${CANARY}-role]\n${CANARY}-group = ["not-a-class"]\n`,
      raw: (path) => loadConfigWithDigest(path, {}),
    },
  ];

  it.each(cases)('$name', async ({ toml, raw }) => {
    const h = await startFrom(BASE);
    const before = snapshot(h);
    await dir.write(toml);
    await expect(raw(h.path)).rejects.toThrow(CANARY);

    const outcome = await h.reloader.reload('tool', 1);

    expect(outcome.ok).toBe(false);
    expect(outcome.error?.name).toBeTruthy();
    expect(outcome.error?.message).toBeTruthy();
    expectUnchanged(h, before);
    expect(outcome.grantsInvalidated).toBeUndefined();
    expect(h.reloader.status().last).toBe(outcome);
    expectNoCanary(h, outcome);
  });

  it('names the TOML position and the path, not the source text', async () => {
    const h = await startFrom(BASE);
    await dir.write(`[[profiles]\nname = "${CANARY}"\n`);
    const { error } = await h.reloader.reload('tool', 1);
    expect(error?.name).toBe('ConfigParseError');
    expect(error?.message).toContain(h.path);
    expect(error?.message).toMatch(/line 1, column \d+/);
  });

  it('names the schema issue paths and codes, not the received values', async () => {
    const h = await startFrom(BASE);
    await dir.write(`${BASE}auth = "${CANARY}"\n"${CANARY}" = 1\n`);
    const { error } = await h.reloader.reload('tool', 1);
    expect(error?.name).toBe('ConfigSchemaError');
    expect(error?.message).toContain(h.path);
    expect(error?.message).toContain('profiles.0.auth (invalid_value)');
    expect(error?.message).toContain('profiles.0 (unrecognized_keys)');
  });

  it('masks role and group names in a schema issue path', async () => {
    const h = await startFrom(BASE);
    await dir.write(`${BASE}\n[policy.roleBindings.${CANARY}-role]\n${CANARY}-group = ["not-a-class"]\n`);
    const { error } = await h.reloader.reload('tool', 1);
    expect(error?.name).toBe('ConfigSchemaError');
    expect(error?.message).toContain('policy.roleBindings.*.*.0 (invalid_value)');
  });

  it('names the denylist without quoting the pattern', async () => {
    const h = await startFrom(BASE);
    await dir.write(`${BASE}\n[policy]\ndenylist = ["(${CANARY}"]\n`);
    const { error } = await h.reloader.reload('tool', 1);
    expect(error?.message).toContain('policy.denylist');
  });

  it.skipIf(onWindows)('a world-readable file', async () => {
    const h = await startFrom(BASE);
    const before = snapshot(h);
    await dir.write(BASE, 0o644);

    const outcome = await h.reloader.reload('tool', 1);

    expect(outcome.ok).toBe(false);
    expect(outcome.error?.message).toMatch(/group\/world accessible/);
    expectUnchanged(h, before);
    expectNoCanary(h, outcome);
  });

  it.each([
    ['some -> other', '/srv/transfer-a', '/srv/transfer-b'],
    ['some -> none', '/srv/transfer-a', undefined],
  ])('a transferRoot change (%s)', async (_label, from, to) => {
    const withRoot = (root?: string) =>
      root === undefined ? BASE : `[defaults]\ntransferRoot = "${root}"\n${BASE}`;
    const h = await startFrom(withRoot(from));
    const before = snapshot(h);
    await dir.write(withRoot(to));

    const outcome = await h.reloader.reload('tool', 1);

    expect(outcome.ok).toBe(false);
    expect(outcome.error?.message).toMatch(/transferRoot/);
    expect(outcome.error?.message).toMatch(/restart/);
    expect(outcome.error?.message).not.toContain('/srv/');
    expect(h.localPath.transferRoot).toBe(from);
    expectUnchanged(h, before);
  });

  it('duplicate profile names', async () => {
    const h = await startFrom(BASE);
    const before = snapshot(h);
    // The duplicated name is the canary: the refusal names indices, never the value.
    await dir.write(`${BASE}${BASE.replace('name = "dev"', `name = "${CANARY}"`)}${BASE.replace('name = "dev"', `name = "${CANARY}"`)}`);

    const outcome = await h.reloader.reload('tool', 1);

    expect(outcome.ok).toBe(false);
    expect(outcome.error?.message).toContain('profiles[2].name');
    expect(outcome.error?.message).toContain('profiles[1].name');
    expectUnchanged(h, before);
    expectNoCanary(h, outcome);
  });

  it('zero profiles', async () => {
    const h = await startFrom(BASE);
    const before = snapshot(h);
    await dir.write('profiles = []\n');

    const outcome = await h.reloader.reload('tool', 1);

    expect(outcome.ok).toBe(false);
    expect(outcome.error?.message).toContain('profiles (too_small)');
    expectUnchanged(h, before);
  });

  it("source: 'flags'", async () => {
    const h = await startFrom(BASE, 'flags');
    const before = snapshot(h);

    const outcome = await h.reloader.reload('sighup', 1);

    expect(outcome.ok).toBe(false);
    expect(outcome.error?.message).toBe('started from command-line flags; restart to use a config file');
    expectUnchanged(h, before);
  });

  it('audits a refusal as one config:reload deny with the error', async () => {
    const h = await startFrom(BASE);
    await dir.write(`[[profiles]\nname = "${CANARY}"\n`);
    await h.reloader.reload('tool', 'req-9');

    const records = await auditRecords(h);
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      mcpRequestId: 'req-9',
      command: 'config:reload',
      binary: 'config:reload',
      commandClass: 'safe',
      profile: '-',
      decision: 'deny',
      ruleId: 'config-reload',
    });
    expect(records[0].error).toMatch(/ConfigParseError/);
    expect(records[0].error).not.toContain(CANARY);
  });
});

describe('ConfigReloader: an applied reload', () => {
  const START =
    profileToml('jump') +
    profileToml('app', 'via = "jump"').replace('app.example.test', CANARY) +
    profileToml('keep') +
    profileToml('idle') +
    profileToml('gone');
  const NEXT =
    profileToml('jump').replace('jump.example.test', 'jump2.example.test') +
    profileToml('app', 'via = "jump"').replace('app.example.test', CANARY) +
    profileToml('keep', 'workdir = "/w"\nreadOnly = true') +
    profileToml('idle', 'workdir = "/w"') +
    profileToml('new') +
    '\n[policy]\ndenylist = ["^terraform"]\n';

  async function applied() {
    const h = await startFrom(START);
    const closes: string[] = [];
    const conns = {
      jump: plant(h, 'jump', ['s-jump'], closes),
      app: plant(h, 'app', ['s-app'], closes),
      keep: plant(h, 'keep', ['s-keep'], closes),
      gone: plant(h, 'gone', ['s-g1', 's-g2'], closes),
    };
    const generation = h.registry.generation;
    await dir.write(NEXT);
    const outcome = await h.reloader.reload('tool', 'req-1');
    return { h, closes, conns, generation, outcome };
  }

  const sortChanges = (cs: { name: string; fields: string[] }[] = []) =>
    cs.map((c) => ({ name: c.name, fields: [...c.fields].sort() })).sort((a, b) => a.name.localeCompare(b.name));

  it('reports the diff, policy change, closures and session-fixed fields', async () => {
    const { h, outcome, generation } = await applied();

    expect(outcome.ok).toBe(true);
    expect(outcome.error).toBeUndefined();
    expect(outcome.trigger).toBe('tool');
    expect(outcome.diff?.added).toEqual(['new']);
    expect(outcome.diff?.removed).toEqual(['gone']);
    expect(sortChanges(outcome.diff?.changed)).toEqual([
      { name: 'idle', fields: ['workdir'] },
      { name: 'jump', fields: ['host'] },
      { name: 'keep', fields: ['readOnly', 'workdir'] },
    ]);
    expect(outcome.policyChanged).toBe(true);
    expect([...(outcome.closed ?? [])].sort((a, b) => a.profile.localeCompare(b.profile))).toEqual([
      { profile: 'app', reason: 'bastion-closed', sessions: ['s-app'] },
      { profile: 'gone', reason: 'removed', sessions: ['s-g1', 's-g2'] },
      { profile: 'jump', reason: 'connection-field', sessions: ['s-jump'] },
    ]);
    // Only `keep` has an open connection; `idle` changed the same field with none.
    expect(outcome.sessionFieldsChanged).toEqual([{ name: 'keep', fields: ['workdir'] }]);
    expect(outcome.grantsInvalidated).toBe(true);
    expect(h.registry.generation).toBe(generation + 1);
  });

  it('swaps the policy rules and the kept connection profile', async () => {
    const { h, conns } = await applied();
    const keep = h.registry.getProfile('keep');
    expect(conns.keep.profile).toBe(keep);
    expect(keep.readOnly).toBe(true);
    expect(h.policy.evaluate('terraform plan', keep).ruleId).toBe('denylist');
    expect(h.registry.liveConnections()).toEqual([conns.keep]);
    // Every connection the reload closes is retired first; the kept one is not.
    expect([conns.jump, conns.app, conns.gone].map((c) => c.retired)).toEqual([true, true, true]);
    expect(conns.keep.retired).toBe(false);
  });

  it('closes a dependent before the bastion it runs through', async () => {
    const { closes } = await applied();
    expect(closes).toHaveLength(3);
    expect(closes.indexOf('app')).toBeLessThan(closes.indexOf('jump'));
  });

  it('does not start closing the bastion until its dependent has finished closing', async () => {
    const h = await startFrom(profileToml('jump') + profileToml('app', 'via = "jump"'));
    const closes: string[] = [];
    let release!: () => void;
    const held = new Promise<void>((resolve) => { release = resolve; });
    plant(h, 'jump', [], closes);
    plant(h, 'app', [], closes, () => held);
    await dir.write(
      profileToml('jump').replace('jump.example.test', 'jump2.example.test') + profileToml('app', 'via = "jump"'),
    );

    const reloading = h.reloader.reload('tool', 1);
    await vi.waitFor(() => expect(closes).toEqual(['app']));
    // Let everything already queued run: the bastion's close must still not have begun.
    await new Promise((r) => setImmediate(r));
    expect(closes).toEqual(['app']);

    release();
    await reloading;
    expect(closes).toEqual(['app', 'jump']);
  });

  it('hashes the bytes and records the outcome in status', async () => {
    const { h, outcome } = await applied();
    const expected = createHash('sha256').update(await readFile(h.path)).digest('hex');
    expect(outcome.sha256).toBe(expected);
    const status = h.reloader.status();
    expect(status.last).toBe(outcome);
    expect(status.sha256).toBe(expected);
    expect(status.source).toBe('file');
    expect(status.path).toBe(h.path);
    expect(status.loadedAt).toBe(outcome.loadedAt);
    expect(status.loadedAt).not.toBe(STARTED_AT);
    expect(h.reloader.formatOutcome(outcome)).toContain(`loaded at ${outcome.loadedAt}`);
    expect(h.reloader.formatOutcome(outcome)).toContain(`sha256 ${expected}`);
  });

  it('reports the startup hash and load time of a file-started server', async () => {
    const h = await startFrom(BASE);
    expect(h.reloader.status()).toMatchObject({
      sha256: await sha256Of(h.path),
      loadedAt: STARTED_AT,
      source: 'file',
      last: null,
    });
  });

  it('never prints a value from the file', async () => {
    const { h, outcome } = await applied();
    // The canary is the host of a profile the report names, so this bites.
    expect(h.reloader.formatOutcome(outcome)).toContain('app');
    expectNoCanary(h, outcome);
    expect(stderr.join('\n')).toContain(h.reloader.formatOutcome(outcome));
  });

  it('audits one config:reload allow and one session:close per closed session', async () => {
    const { h } = await applied();
    const records = await auditRecords(h);

    const reloads = records.filter((r) => r.binary === 'config:reload');
    expect(reloads).toHaveLength(1);
    expect(reloads[0]).toMatchObject({
      mcpRequestId: 'req-1',
      command: 'config:reload',
      commandClass: 'safe',
      profile: '-',
      decision: 'allow',
      ruleId: 'config-reload',
    });
    expect(reloads[0].error).toBeUndefined();

    const closes = records.filter((r) => r.binary === 'session:close');
    expect(closes.map((r) => r.command).sort()).toEqual([
      'session:close background s-app (reload)',
      'session:close background s-g1 (reload)',
      'session:close background s-g2 (reload)',
      'session:close background s-jump (reload)',
    ]);
    for (const r of closes) {
      expect(r).toMatchObject({ decision: 'allow', commandClass: 'safe', ruleId: 'session-release' });
    }
    expect(closes.find((r) => r.command.includes('s-app'))?.profile).toBe('app');
    // The config:reload record comes last: it is written once the closes are done.
    expect(records[records.length - 1].binary).toBe('config:reload');
  });

  it('reports a failed close and still closes the others', async () => {
    const h = await startFrom(profileToml('a') + profileToml('b'));
    const closes: string[] = [];
    plant(h, 'a', ['s-a'], closes, async () => {
      throw Object.assign(new Error(`cannot close ${CANARY}`), { code: 'EPIPE' });
    });
    plant(h, 'b', [], closes);
    await dir.write(profileToml('c'));

    const outcome = await h.reloader.reload('tool', 1);

    expect(outcome.ok).toBe(true);
    expect(closes.sort()).toEqual(['a', 'b']);
    expect(outcome.closed).toEqual([
      { profile: 'a', reason: 'removed', sessions: ['s-a'], error: 'Error (EPIPE)' },
      { profile: 'b', reason: 'removed', sessions: [] },
    ]);
    expect(h.reloader.formatOutcome(outcome)).toMatch(/close failed/);
    expectNoCanary(h, outcome);
  });

  it('closes a chain of bastions from the far end inwards', async () => {
    const h = await startFrom(profileToml('a') + profileToml('b', 'via = "a"') + profileToml('c', 'via = "b"'));
    const closes: string[] = [];
    for (const name of ['a', 'b', 'c']) plant(h, name, [], closes);
    await dir.write(
      profileToml('a').replace('a.example.test', 'a2.example.test') +
      profileToml('b', 'via = "a"') +
      profileToml('c', 'via = "b"'),
    );

    await h.reloader.reload('tool', 1);

    expect(closes).toEqual(['c', 'b', 'a']);
  });
});

describe('ConfigReloader: transferRoot none -> some', () => {
  it('is allowed and sets localPath.transferRoot', async () => {
    const h = await startFrom(BASE);
    expect(h.localPath.transferRoot).toBeUndefined();
    await dir.write(`[defaults]\ntransferRoot = "/srv/transfer"\n${BASE}`);

    const outcome = await h.reloader.reload('tool', 1);

    expect(outcome.ok).toBe(true);
    expect(h.localPath.transferRoot).toBe('/srv/transfer');
  });
});

describe('ConfigReloader: unconfigured startup', () => {
  it('reloads into a configured server once the file is written', async () => {
    const path = join(dir.dir, 'config.toml');
    const h = build({ defaults: defaultsFromArgv({}), profiles: [] }, path, 'unconfigured');
    expect(h.reloader.status()).toMatchObject({ path, source: 'unconfigured', sha256: null, last: null });

    const missing = await h.reloader.reload('tool', 1);
    expect(missing.ok).toBe(false);
    expect(missing.error?.name).toBe('ConfigNotFoundError');

    await dir.write(BASE);
    const outcome = await h.reloader.reload('tool', 2);

    expect(outcome.ok).toBe(true);
    expect(outcome.diff?.added).toEqual(['dev']);
    expect(h.registry.getProfile('dev').name).toBe('dev');
    expect(h.reloader.status().source).toBe('file');
  });
});

describe('ConfigReloader: concurrency (Review Focus 3)', () => {
  /** A reload held in its close of `gone` until the returned release is called. */
  async function heldReload() {
    const h = await startFrom(BASE + profileToml('gone'));
    let release!: () => void;
    const held = new Promise<void>((resolve) => { release = resolve; });
    plant(h, 'gone', [], [], () => held);
    const apply = vi.spyOn(h.registry, 'applyConfig');
    await dir.write(BASE);
    const first = h.reloader.reload('tool', 1);
    // Running: it has swapped and is stuck closing `gone`.
    await vi.waitFor(() => expect(apply).toHaveBeenCalledTimes(1));
    return { h, apply, first, release };
  }

  it('runs a reload asked for while one is running only after it, on the file as it is then', async () => {
    const { h, apply, first, release } = await heldReload();

    const second = h.reloader.reload('sighup', 2);
    // Written while the first is still running. A second reload that ran alongside the
    // first, or that had read the file already, would not see `late`.
    await dir.write(BASE + profileToml('late'));
    expect(apply).toHaveBeenCalledTimes(1);

    release();
    const [a, b] = await Promise.all([first, second]);
    expect(apply).toHaveBeenCalledTimes(2);
    expect(a.ok).toBe(true);
    expect(a.diff?.removed).toEqual(['gone']);
    expect(b.ok).toBe(true);
    expect(b.trigger).toBe('sighup');
    expect(b.diff?.added).toEqual(['late']);
    expect(h.reloader.status().last).toBe(b);
  });

  it('coalesces reloads asked for while one is running into one more run', async () => {
    const { h, apply, first, release } = await heldReload();

    const queued = [2, 3, 4, 5, 6].map((id) => h.reloader.reload('sighup', id));

    release();
    const outcomes = await Promise.all([first, ...queued]);
    expect(apply).toHaveBeenCalledTimes(2);
    // Every caller that joined the queued run gets its outcome.
    for (const o of outcomes.slice(2)) expect(o).toBe(outcomes[1]);
    expect(outcomes[1]).not.toBe(outcomes[0]);
    const reloads = (await auditRecords(h)).filter((r) => r.binary === 'config:reload');
    expect(reloads.map((r) => r.mcpRequestId)).toEqual([1, 2]);
  });

});

describe('ConfigReloader: a defect after the swap began', () => {
  it('is audited, reported in status, and resolves rather than rejects', async () => {
    const h = await startFrom(BASE);
    vi.spyOn(h.registry, 'applyConfig').mockImplementationOnce(() => {
      throw new TypeError(`boom ${CANARY}`);
    });
    await dir.write(BASE.replace('user = "test"', 'user = "test"\nworkdir = "/w"'));

    const outcome = await h.reloader.reload('sighup', 'req-d');

    expect(outcome.ok).toBe(false);
    expect(outcome.error?.name).toBe('TypeError');
    expect(outcome.error?.message).toMatch(/partially applied/);
    expect(h.reloader.status().last).toBe(outcome);
    expectNoCanary(h, outcome);

    // The queue survives it.
    expect((await h.reloader.reload('tool', 2)).ok).toBe(true);

    const reloads = (await auditRecords(h)).filter((r) => r.binary === 'config:reload');
    expect(reloads.map((r) => r.decision)).toEqual(['deny', 'allow']);
    expect(reloads[0].mcpRequestId).toBe('req-d');
    // Told apart from a refusal, which changed nothing, by its rule id.
    expect(reloads.map((r) => r.ruleId)).toEqual(['config-reload-partial', 'config-reload']);
    expect(reloads[0].error).toMatch(/TypeError: .*partially applied/);
    expect(reloads[0].error).not.toContain(CANARY);
  });

  it('closes every connection when one cannot list or describe its sessions', async () => {
    const h = await startFrom(profileToml('a') + profileToml('b') + profileToml('c'));
    const closes: string[] = [];
    plant(h, 'a', [], closes).listSessions = () => {
      throw new Error('cannot list');
    };
    const b = plant(h, 'b', [], closes);
    b.listSessions = () => [{ name: 's-b', toInfo: () => { throw new Error('cannot describe'); } }] as never;
    plant(h, 'c', ['s-c'], closes);
    await dir.write(profileToml('d'));

    const outcome = await h.reloader.reload('tool', 1);

    expect(outcome.ok).toBe(true);
    expect(closes.sort()).toEqual(['a', 'b', 'c']);
    expect(outcome.closed).toEqual([
      { profile: 'a', reason: 'removed', sessions: [] },
      { profile: 'b', reason: 'removed', sessions: ['s-b'] },
      { profile: 'c', reason: 'removed', sessions: ['s-c'] },
    ]);
    const commands = (await auditRecords(h)).filter((r) => r.binary === 'session:close').map((r) => r.command);
    expect(commands.sort()).toEqual([
      'session:close background s-c (reload)',
      'session:close unknown s-b (reload)',
    ]);
  });
});

describe('ConfigReloader: policyChanged is measured against the live rules', () => {
  const DENY = '\n[policy]\ndenylist = ["^terraform"]\n';

  it('is false when only a profile changed', async () => {
    const h = await startFrom(BASE);
    await dir.write(BASE.replace('user = "test"', 'user = "test"\nworkdir = "/w"'));
    const outcome = await h.reloader.reload('tool', 1);
    expect(outcome.ok).toBe(true);
    expect(outcome.policyChanged).toBe(false);
  });

  it('is true when the denylist changed', async () => {
    const h = await startFrom(BASE);
    await dir.write(BASE + DENY);
    expect((await h.reloader.reload('tool', 1)).policyChanged).toBe(true);
  });

  // The rules are swapped before the registry. A failure after that leaves the new rules
  // live, so the next reload of the same file has no policy change to report; a baseline
  // kept beside the engine said it had.
  it('compares with the rules the engine runs on, even after a partial failure', async () => {
    const h = await startFrom(BASE);
    vi.spyOn(h.registry, 'applyConfig').mockImplementationOnce(() => {
      throw new TypeError('boom');
    });
    await dir.write(BASE + DENY);
    expect((await h.reloader.reload('tool', 1)).partial).toBe(true);
    expect(h.policy.evaluate('terraform plan', h.registry.getProfile('dev')).ruleId).toBe('denylist');

    const outcome = await h.reloader.reload('tool', 2);

    expect(outcome.ok).toBe(true);
    expect(outcome.policyChanged).toBe(false);
  });

  it('compiles the rules once per reload and installs that compilation', async () => {
    const h = await startFrom(BASE);
    const compile = vi.spyOn(PolicyEngine, 'compile');
    const replace = vi.spyOn(h.policy, 'replaceRules');
    await dir.write(BASE + DENY);

    expect((await h.reloader.reload('tool', 1)).ok).toBe(true);

    expect(compile).toHaveBeenCalledTimes(1);
    expect(replace).toHaveBeenCalledTimes(1);
    expect(replace.mock.calls[0]![0]).toBe(compile.mock.results[0]!.value);
  });
});

describe('ConfigReloader: formatOutcome says what a failure left behind', () => {
  it('a refusal says nothing was changed', async () => {
    const h = await startFrom(BASE);
    await dir.write('[[profiles]\n');

    const text = h.reloader.formatOutcome(await h.reloader.reload('tool', 1));

    expect(text).toMatch(/^Config reload \(tool\) refused: ConfigParseError: /);
    expect(text).toContain('Nothing was changed.');
    expect(text).not.toMatch(/partially applied/);
  });

  it('a failure after the swap began says it may be partially applied, not that nothing changed', async () => {
    const h = await startFrom(BASE);
    vi.spyOn(h.registry, 'applyConfig').mockImplementationOnce(() => {
      throw new TypeError('boom');
    });
    await dir.write(BASE.replace('user = "test"', 'user = "test"\nworkdir = "/w"'));

    const outcome = await h.reloader.reload('sighup', 'sighup');
    const text = h.reloader.formatOutcome(outcome);

    expect(outcome.ok).toBe(false);
    expect(text).not.toContain('Nothing was changed');
    expect(text).not.toContain('refused');
    expect(text).toMatch(/^Config reload \(sighup\) failed after the swap began: TypeError: /);
    expect(text).toMatch(/may be partially applied/);
    expect(text).toMatch(/reload-config status/);
    expect(text).toMatch(/restart the server if/);
  });
});

describe('installSighupReload', () => {
  function fakeProcess(platform: NodeJS.Platform) {
    const handlers = new Map<string, () => void>();
    return {
      platform,
      on: vi.fn((event: string, fn: () => void) => {
        handlers.set(event, fn);
      }),
      handlers,
    };
  }

  it('is not wired on Windows, where SIGHUP means the console is closing', () => {
    const proc = fakeProcess('win32');
    const reload = vi.fn();

    expect(installSighupReload({ reload }, proc as never)).toBe(false);
    expect(proc.on).not.toHaveBeenCalled();
  });

  it('reloads with trigger and request id "sighup" elsewhere', async () => {
    const proc = fakeProcess('linux');
    const reload = vi.fn(async () => ({ ok: true }) as ReloadOutcome);

    expect(installSighupReload({ reload }, proc as never)).toBe(true);
    proc.handlers.get('SIGHUP')!();

    expect(reload).toHaveBeenCalledWith('sighup', 'sighup');
  });

  it('catches a rejected reload, logs a message that quotes nothing, and keeps running', async () => {
    const proc = fakeProcess('darwin');
    const reload = vi.fn(async () => {
      throw new TypeError(`defect ${CANARY}`);
    });
    installSighupReload({ reload }, proc as never);

    proc.handlers.get('SIGHUP')!();
    await vi.waitFor(() => expect(stderr.join('\n')).toMatch(/SIGHUP.*TypeError/));

    expect(stderr.join('\n')).not.toContain(CANARY);
  });
});

describe('ConfigReloader: the hash is of the bytes that were parsed', () => {
  /**
   * The read is stubbed to hand back different bytes from what is on disk. A reloader
   * that hashed a read of its own would report the disk's hash while applying the stub's
   * config, which is exactly the mismatch a write between two reads produces.
   */
  afterEach(() => {
    vi.doUnmock('fs/promises');
    vi.resetModules();
  });

  it('reads the file once and hashes that buffer', async () => {
    const path = await dir.write(BASE);
    const served = Buffer.from(BASE + profileToml('extra'), 'utf8');
    const reads: string[] = [];

    vi.resetModules();
    vi.doMock('fs/promises', async () => {
      const actual = await vi.importActual<typeof import('fs/promises')>('fs/promises');
      const readFileStub = (async (p: unknown, ...rest: unknown[]) => {
        if (p === path) {
          reads.push(String(p));
          return rest[0] === 'utf8' ? served.toString('utf8') : served;
        }
        return (actual.readFile as (...a: unknown[]) => unknown)(p, ...rest);
      }) as typeof actual.readFile;
      return { ...actual, default: { ...actual, readFile: readFileStub }, readFile: readFileStub };
    });
    // Imported after the mock, so the reloader it builds reads through the stub.
    const { buildReloader: buildMocked } = await import('./reload-rig.js');

    const config: AppConfig = { defaults: defaultsFromArgv({}), profiles: [] };
    const { reloader } = buildMocked({
      config,
      path,
      auditPath: join(auditDir, 'audit.log'),
      source: 'unconfigured',
    });

    const outcome = await reloader.reload('tool', 1);

    expect(outcome.ok).toBe(true);
    expect(reads).toEqual([path]);
    expect(outcome.diff?.added).toEqual(['dev', 'extra']);
    expect(outcome.sha256).toBe(createHash('sha256').update(served).digest('hex'));
    expect(outcome.sha256).not.toBe(await sha256Of(path));
  });
});

describe('ConfigReloader: quota counters survive a reload', () => {
  const withQuota = (n: number, extra = '') =>
    BASE.replace('user = "test"', `user = "test"\ncommandQuotaPerDay = ${n}${extra}`);

  it('keeps the spend and reads the new limit live', async () => {
    const h = await startFrom(withQuota(3));
    const quota = new CommandQuota();
    // The pipeline's call: the profile name, and the limit read from the live profile.
    const spend = () => quota.consume('dev', h.registry.getProfile('dev').commandQuotaPerDay).allowed;

    expect(spend()).toBe(true);
    expect(spend()).toBe(true);

    await dir.write(withQuota(3, '\nworkdir = "/w"'));
    expect((await h.reloader.reload('tool', 1)).ok).toBe(true);
    expect(spend()).toBe(true);
    expect(spend()).toBe(false);

    await dir.write(withQuota(5));
    expect((await h.reloader.reload('tool', 2)).ok).toBe(true);
    expect(spend()).toBe(true);
    expect(spend()).toBe(true);
    expect(spend()).toBe(false);
  });
});

describe('ConfigReloader: the ACL options from argv reach the loader (Review Focus 4)', () => {
  /**
   * The Windows ACL check, stubbed to come back with a finding the default posture
   * refuses (an ACL that could not be read). `--allowUncheckedConfigAcl` waives it; its
   * absence refuses. main() computes the options from argv once, with
   * `aclOptionsFromArgv`, and hands the same object to the reloader; pinned here because
   * a reload that built its own options (or none) would pass every other test.
   */
  afterEach(() => {
    vi.doUnmock('os');
    vi.doUnmock('../../../src/config/windows-acl.js');
    vi.resetModules();
  });

  async function reloadUnderAclFinding(argv: Record<string, string | null>) {
    vi.resetModules();
    vi.doMock('os', async () => {
      const actual = await vi.importActual<typeof import('os')>('os');
      return { ...actual, platform: () => 'win32' };
    });
    vi.doMock('../../../src/config/windows-acl.js', async () => {
      const actual = await vi.importActual<typeof import('../../../src/config/windows-acl.js')>(
        '../../../src/config/windows-acl.js',
      );
      return {
        ...actual,
        assertPrivateOnWindows: (path: string, opts: Parameters<typeof actual.assertPrivateOnWindows>[1]) =>
          actual.assertPrivateOnWindows(path, opts, async () => ({
            status: 'unknown',
            reason: 'read-refused',
            detail: 'stubbed',
          })),
      };
    });
    // Imported after the mocks, so the reloader it builds runs the stubbed ACL check.
    const { buildReloader: buildMocked } = await import('./reload-rig.js');

    const path = await dir.write(BASE);
    const config: AppConfig = { defaults: defaultsFromArgv({}), profiles: [] };
    const h: Harness = {
      path,
      ...buildMocked({
        config,
        path,
        auditPath: join(auditDir, 'audit.log'),
        source: 'unconfigured',
        aclOptions: aclOptionsFromArgv(argv),
      }),
    };
    const before = snapshot(h);
    return { h, before, outcome: await h.reloader.reload('tool', 1) };
  }

  it('passes with --allowUncheckedConfigAcl, and reports the finding', async () => {
    const { outcome } = await reloadUnderAclFinding({ allowUncheckedConfigAcl: null });
    expect(outcome.error).toBeUndefined();
    expect(outcome.ok).toBe(true);
    // Waived, not silent: the sink aclOptionsFromArgv installs printed the finding.
    expect(stderr.some((line) => line.startsWith('Warning: '))).toBe(true);
  });

  it('refuses without it, naming the flag, and changes nothing', async () => {
    const { h, before, outcome } = await reloadUnderAclFinding({});
    expect(outcome.ok).toBe(false);
    expect(outcome.error?.name).toBe('OperatorError');
    expect(outcome.error?.message).toContain('--allowUncheckedConfigAcl');
    expectUnchanged(h, before);
  });
});
