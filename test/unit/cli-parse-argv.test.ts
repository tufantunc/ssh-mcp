import { describe, it, expect } from 'vitest';
import { parseArgv } from '../../src/cli.js';

/**
 * The contract every other argv helper is built on, finally asserted.
 *
 * `parseArgv` had no test at all. On main it *looked* covered, but only because
 * `npm run test:unit` was actually booting `main()` — the coverage was an artifact of the
 * import-time side effect this split removed, not of a test. Measured: two mutations left
 * the whole 498-test in-process suite green — storing `''` instead of `null` for a bare
 * flag (which stops a bare `--hostKeyMode` defaulting to `tofu` and makes it throw), and
 * dropping the value from every `--key=value`.
 *
 * The null-for-a-bare-flag rule is the root of #91 and of the bare-`--config` bug, and
 * `flagEnabled`, `resolveHostKeyMode` and `buildAppConfig` all presuppose it. It was
 * documented in three prose comments and executed by nothing.
 */
describe('parseArgv', () => {
  it('stores null for a flag written without a value', () => {
    // #91: the spelling every documented boolean flag uses. `flagEnabled` reads null as
    // "present, therefore on", so anything else here silently changes what the flag means.
    expect(parseArgv(['--strictConfigAcl'])).toEqual({ strictConfigAcl: null });
  });

  it('stores the value for --key=value', () => {
    expect(parseArgv(['--host=example.com'])).toEqual({ host: 'example.com' });
  });

  it('distinguishes an empty value from an absent one', () => {
    // `--flag=` is the operator explicitly passing nothing, which is not the same as a
    // bare `--flag`; `parseMaxChars` and `resolveHostKeyMode` treat the two differently.
    expect(parseArgv(['--group='])).toEqual({ group: '' });
  });

  it('splits on the first = only', () => {
    // indexOf, not split: a value may legitimately contain '=' — a base64 key path, or a
    // command fragment.
    expect(parseArgv(['--key=a=b=c'])).toEqual({ key: 'a=b=c' });
  });

  it('ignores arguments that are not flags', () => {
    expect(parseArgv(['positional', '--host=h', 'another'])).toEqual({ host: 'h' });
  });

  it('lets the last spelling of a repeated flag win', () => {
    expect(parseArgv(['--host=first', '--host=second'])).toEqual({ host: 'second' });
  });

  it('reads process.argv when given nothing', () => {
    // The default argument is what production uses; a test that only ever passed an array
    // would not notice it being removed.
    const original = process.argv;
    try {
      process.argv = ['node', 'ssh-mcp', '--host=from-argv', '--strictConfigAcl'];
      expect(parseArgv()).toEqual({ host: 'from-argv', strictConfigAcl: null });
    } finally {
      process.argv = original;
    }
  });
});
