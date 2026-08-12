import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, chmod, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { loadConfig, getProfile } from '../../../src/config/loader.js';
import { sanitizeCommand } from '../../../src/guard/sanitizer.js';

/**
 * These go config file → loadConfig → sanitizeCommand, because the bug in the
 * middle of #123 is invisible one step earlier.
 *
 * `--maxChars=none` disabled the cap; the TOML schema was `positive()`, so the
 * config file could not say the same thing. Widening it to `nonnegative()` is
 * only half a fix: `sanitizeCommand` tests `cleaned.length > maxChars`, so a
 * literal `0` reaching it rejects every non-empty command with "Command is too
 * long (max 0 characters)". A schema-level assertion that `0` parses would pass
 * against exactly that.
 */

let tempDir: string;

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), 'ssh-mcp-maxchars-'));
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

async function writeConfig(content: string): Promise<string> {
  const path = join(tempDir, 'config.toml');
  await writeFile(path, content, 'utf8');
  await chmod(path, 0o600);
  return path;
}

const PROFILE = `
[[profiles]]
name = "web"
host = "10.0.0.5"
user = "deploy"
role = "admin"
group = "dev"
`;

/** Longer than the 5000-char default, so the default would reject it. */
const LONG_COMMAND = `echo ${'x'.repeat(6000)}`;

async function maxCharsFor(toml: string): Promise<number> {
  const config = await loadConfig(await writeConfig(toml));
  return getProfile(config, 'web').maxChars;
}

describe('commandMaxChars = 0 means unlimited', () => {
  it('accepts a command longer than the default cap', async () => {
    const maxChars = await maxCharsFor(`
[defaults]
commandMaxChars = 0
${PROFILE}`);

    expect(sanitizeCommand(LONG_COMMAND, maxChars)).toBe(LONG_COMMAND);
  });

  it('resolves to the same value --maxChars=none produces', async () => {
    const maxChars = await maxCharsFor(`
[defaults]
commandMaxChars = 0
${PROFILE}`);

    // parseMaxChars() maps `none`, `0` and negatives to this. The two surfaces
    // are one setting, so they must produce one Profile.
    expect(maxChars).toBe(Number.MAX_SAFE_INTEGER);
  });

  it('works as a per-profile override too', async () => {
    const maxChars = await maxCharsFor(`
[defaults]
commandMaxChars = 100
${PROFILE}
maxChars = 0
`);

    expect(maxChars).toBe(Number.MAX_SAFE_INTEGER);
    expect(sanitizeCommand(LONG_COMMAND, maxChars)).toBe(LONG_COMMAND);
  });

  it('a profile inherits an unlimited default', async () => {
    const maxChars = await maxCharsFor(`
[defaults]
commandMaxChars = 0
${PROFILE}`);

    expect(sanitizeCommand('uptime', maxChars)).toBe('uptime');
  });
});

describe('a real cap still caps', () => {
  it('rejects a command over an explicit limit', async () => {
    const maxChars = await maxCharsFor(`
[defaults]
commandMaxChars = 10
${PROFILE}`);

    expect(maxChars).toBe(10);
    expect(() => sanitizeCommand(LONG_COMMAND, maxChars)).toThrow(/too long \(max 10 characters\)/);
  });

  it('a per-profile cap overrides an unlimited default', async () => {
    const maxChars = await maxCharsFor(`
[defaults]
commandMaxChars = 0
${PROFILE}
maxChars = 10
`);

    expect(maxChars).toBe(10);
    expect(() => sanitizeCommand(LONG_COMMAND, maxChars)).toThrow(/too long/);
  });

  it('the default cap is unchanged when nothing is set', async () => {
    const maxChars = await maxCharsFor(PROFILE);

    expect(maxChars).toBe(5000);
    expect(() => sanitizeCommand(LONG_COMMAND, maxChars)).toThrow(/too long \(max 5000 characters\)/);
  });
});

describe('negatives are still rejected', () => {
  /**
   * `--maxChars=-1` means unlimited only as a wart of parseInt handling, and is
   * far likelier to be a typo than an intent. Parity is worth having between
   * the documented behaviours, not between the accidents.
   */
  it('fails at load rather than parsing into a grant of nothing', async () => {
    await expect(maxCharsFor(`
[defaults]
commandMaxChars = -1
${PROFILE}`)).rejects.toThrow(/commandMaxChars/);
  });

  it('rejects a negative per-profile override', async () => {
    await expect(maxCharsFor(`
[defaults]
commandMaxChars = 100
${PROFILE}
maxChars = -1
`)).rejects.toThrow(/maxChars/);
  });
});
