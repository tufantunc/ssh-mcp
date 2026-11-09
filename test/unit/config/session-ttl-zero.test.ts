import { describe, it, expect } from 'vitest';
import { EventEmitter } from 'node:events';
import type { ClientChannel } from 'ssh2';
import { useConfigDir } from './helpers.js';
import { loadConfigWithDigest, getProfile } from '../../../src/config/loader.js';
import { parseTtlMs, defaultsFromArgv } from '../../../src/cli.js';
import { BackgroundSession } from '../../../src/ssh/session.js';
import type { Profile } from '../../../src/types.js';

/**
 * `sessionIdleTimeoutMs` / `sessionBackgroundMaxMs` = 0 means "no cap".
 *
 * Same trap the commandMaxChars fix (#123) documents: widening the schema to
 * `nonnegative()` is only half the fix, because a literal 0 reaching
 * `isExpired()` used to read as "expire immediately" — the exact opposite of the
 * request. A schema-level "0 parses" assertion passes against that bug, so these
 * go config file → loader → a real Session and assert the behaviour.
 */

const cfg = useConfigDir('ssh-mcp-sessionttl-');

const PROFILE = `
[[profiles]]
name = "web"
host = "10.0.0.5"
user = "deploy"
role = "admin"
group = "dev"
`;

async function profileFor(toml: string): Promise<Profile> {
  const { config } = await loadConfigWithDigest(await cfg.write(toml));
  return getProfile(config, 'web');
}

function sessionFrom(profile: Profile): BackgroundSession {
  const channel = new EventEmitter() as unknown as ClientChannel;
  return new BackgroundSession('id', 'job', profile.name, channel, profile.sessionIdleTimeoutMs, profile.sessionBackgroundMaxMs);
}

describe('session TTLs in the config file', () => {
  it('accepts 0 for the idle timeout and keeps it as 0', async () => {
    const profile = await profileFor(`
[defaults]
sessionIdleTimeoutMs = 0
${PROFILE}`);

    expect(profile.sessionIdleTimeoutMs).toBe(0);
  });

  it('a 0 idle timeout produces a session that never idle-expires', async () => {
    const profile = await profileFor(`
[defaults]
sessionIdleTimeoutMs = 0
${PROFILE}`);

    const session = sessionFrom(profile);
    session.lastActivity = new Date(Date.now() - 365 * 24 * 60 * 60 * 1_000);

    expect(session.isExpired()).toBe(false);
  });

  it('accepts 0 for the absolute cap as well', async () => {
    const profile = await profileFor(`
[defaults]
sessionIdleTimeoutMs = 0
sessionBackgroundMaxMs = 0
${PROFILE}`);

    const session = sessionFrom(profile);
    session.createdAt.setFullYear(session.createdAt.getFullYear() - 1);

    expect(session.isExpired()).toBe(false);
  });

  it('works as a per-profile override, and does not leak to a sibling', async () => {
    const { config } = await loadConfigWithDigest(await cfg.write(`
[defaults]
sessionIdleTimeoutMs = 600000

[[profiles]]
name = "web"
host = "10.0.0.5"
user = "deploy"
sessionIdleTimeoutMs = 0

[[profiles]]
name = "db"
host = "10.0.0.6"
user = "deploy"
`));

    expect(getProfile(config, 'web').sessionIdleTimeoutMs).toBe(0);
    expect(getProfile(config, 'db').sessionIdleTimeoutMs).toBe(600_000);
  });

  it('takes a per-profile 0 for the absolute cap too, without leaking it', async () => {
    // `??`, not `||`, in the loader's merge: with `||` this profile's "no cap" became
    // the 1-hour default in silence.
    const { config } = await loadConfigWithDigest(await cfg.write(`
[defaults]
sessionBackgroundMaxMs = 3600000

[[profiles]]
name = "web"
host = "10.0.0.5"
user = "deploy"
sessionBackgroundMaxMs = 0

[[profiles]]
name = "db"
host = "10.0.0.6"
user = "deploy"
`));

    const web = getProfile(config, 'web');
    expect(web.sessionBackgroundMaxMs).toBe(0);
    expect(getProfile(config, 'db').sessionBackgroundMaxMs).toBe(3_600_000);

    const session = sessionFrom({ ...web, sessionIdleTimeoutMs: 0 });
    session.createdAt.setFullYear(session.createdAt.getFullYear() - 1);
    expect(session.isExpired()).toBe(false);
  });

  it('still honours a finite value', async () => {
    const profile = await profileFor(`
[defaults]
sessionIdleTimeoutMs = 1234
${PROFILE}`);

    expect(profile.sessionIdleTimeoutMs).toBe(1_234);

    const session = sessionFrom(profile);
    session.lastActivity = new Date(Date.now() - 2_000);
    expect(session.isExpired()).toBe(true);
  });

  it('rejects a negative value', async () => {
    await expect(profileFor(`
[defaults]
sessionIdleTimeoutMs = -1
${PROFILE}`)).rejects.toThrow();
  });
});

describe('--sessionTtl parsing', () => {
  it('reaches the defaults: --sessionTtl=0 is 0, not the 10-minute default', () => {
    // Through defaultsFromArgv, the call site, not only the helper: reverting that line
    // to `parseInt(x) || 600_000` left every helper test green.
    expect(defaultsFromArgv({ sessionTtl: '0' }).sessionIdleTimeoutMs).toBe(0);
    expect(defaultsFromArgv({ sessionTtl: 'soon' }).sessionIdleTimeoutMs).toBe(600_000);
  });

  it('keeps 0 instead of falling back to the default', () => {
    // `parseInt(x) || 600_000` turned the one spelling of "unlimited" into the
    // 10-minute default — falsy, not invalid.
    expect(parseTtlMs('0', 600_000)).toBe(0);
  });

  it('passes a real value through', () => {
    expect(parseTtlMs('7200000', 600_000)).toBe(7_200_000);
  });

  it('falls back on missing or malformed input', () => {
    expect(parseTtlMs(undefined, 600_000)).toBe(600_000);
    expect(parseTtlMs('', 600_000)).toBe(600_000);
    expect(parseTtlMs('soon', 600_000)).toBe(600_000);
    expect(parseTtlMs('-5', 600_000)).toBe(600_000);
  });
});
