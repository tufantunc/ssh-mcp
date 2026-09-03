import { describe, it, expect, afterEach } from 'vitest';
import { loadConfig } from '../../../src/config/loader.js';
import { makeConfigDir, enforceAcl, type ConfigDir } from './helpers.js';

/**
 * `trustedHostKey` is the only host-key control that survives a restart, so a
 * profile that carries the line and verifies nothing is the worst outcome the
 * field has.
 *
 * This goes config file → loadConfig rather than testing the zod schema in
 * isolation, for the reason max-chars.test.ts gives: the interesting failure is a
 * value that passes validation and then means something different downstream, and
 * that is invisible one step earlier.
 */
describe('trustedHostKey in the config schema', () => {
  let cfg: ConfigDir;
  afterEach(async () => { await cfg?.cleanup(); });

  const profile = (line: string) => `
[[profiles]]
name = "dev"
host = "localhost"
user = "test"
${line}
`;

  const load = async (line: string) => {
    cfg = await makeConfigDir('ssh-mcp-pin-');
    const path = await cfg.write(profile(line));
    return loadConfig(path, enforceAcl());
  };

  it('accepts a fingerprint', async () => {
    const config = await load('trustedHostKey = "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"');
    expect(config.profiles[0].trustedHostKey).toBe(
      'SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG',
    );
  });

  it('refuses an empty pin instead of silently ignoring it', async () => {
    // `z.string().optional()` accepted this, and the gate that read it tested
    // truthiness — so the line was inert and the operator who wrote it believed
    // the profile was pinned. Loud at startup is the only safe reading of a blank
    // pin, because the alternative is a profile that verifies nothing and says so
    // nowhere.
    await expect(load('trustedHostKey = ""')).rejects.toThrow(/trustedHostKey cannot be empty/);
  });

  it('refuses a whitespace-only pin for the same reason', async () => {
    await expect(load('trustedHostKey = "   "')).rejects.toThrow(/trustedHostKey cannot be empty/);
  });

  it('trims surrounding whitespace rather than refusing every key', async () => {
    // The comparison against the presented fingerprint is exact, so an untrimmed
    // value refused every connection with nothing in the message pointing at the
    // stray character. A trailing newline is a typo, not an intent.
    const config = await load('trustedHostKey = "  SHA256:abc123  "');
    expect(config.profiles[0].trustedHostKey).toBe('SHA256:abc123');
  });
});
