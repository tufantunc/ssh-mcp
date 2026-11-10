import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { checkUnknownFlags, KNOWN_FLAGS, parseArgv } from '../../src/cli.js';
import { OperatorError } from '../../src/errors.js';

/**
 * A flag the server does not read is refused, not dropped.
 *
 * `parseArgv` accepts any `--anything`, and nothing looked at the keys afterwards. That
 * matters most for `--allowUncheckedConfigAcl`, the way out of a startup the server is
 * already refusing: misspelled, it produced the same refusal again with no sign that
 * anything had been passed. Same class as #91, where `--flag` and `--flag=1` differed.
 */
function refusalFor(args: string[]): OperatorError {
  try {
    checkUnknownFlags(parseArgv(args));
  } catch (e) {
    if (e instanceof OperatorError) return e;
    throw e;
  }
  throw new Error(`expected ${args.join(' ')} to be refused`);
}

describe('checkUnknownFlags', () => {
  it('accepts every flag the server reads', () => {
    expect(() => checkUnknownFlags(parseArgv(KNOWN_FLAGS.map((f) => `--${f}`)))).not.toThrow();
  });

  it('refuses a flag it does not read, naming it', () => {
    expect(refusalFor(['--verbose']).message).toMatch(/^Unknown flag: --verbose\b/);
  });

  it('suggests the flag a misspelling was probably meant to be', () => {
    // The case this exists for: one letter off the only exit from an ACL refusal.
    expect(refusalFor(['--allowUncheckedConfigAc']).message)
      .toContain('--allowUncheckedConfigAc (did you mean --allowUncheckedConfigAcl?)');
  });

  it('suggests across a difference in case alone', () => {
    // Every flag is camelCase, and an all-lowercase spelling is the commonest slip.
    expect(refusalFor(['--hostkeymode=strict']).message).toContain('did you mean --hostKeyMode?');
  });

  it('does not suggest a flag that is not close', () => {
    expect(refusalFor(['--verbose']).message).not.toContain('did you mean');
  });

  it('names every unknown flag at once rather than one per restart', () => {
    const { message } = refusalFor(['--hots=x', '--usr=y']);
    expect(message).toMatch(/^Unknown flags: /);
    expect(message).toContain('--hots (did you mean --host?)');
    expect(message).toContain('--usr (did you mean --user?)');
  });

  it('leaves removed v1 flags to the refusal that explains the migration', () => {
    // checkRemovedFlags runs first and says what replaced them; "unknown" would be the
    // worse message for a flag that used to work.
    expect(() => checkUnknownFlags(parseArgv(['--password=x', '--disableSudo']))).not.toThrow();
  });
});

describe('KNOWN_FLAGS', () => {
  it('is exactly the README flag table', () => {
    // The list is the contract: a flag added to the code but not here is refused at
    // startup (and fails the typecheck, since `Argv` is keyed by it), and one documented
    // but missing here is a documented flag the server rejects.
    const readme = readFileSync(resolve(import.meta.dirname, '../../README.md'), 'utf8');
    const section = readme.slice(readme.indexOf('## CLI Flags'), readme.indexOf('## Migrating from v1'));
    const documented = [...section.matchAll(/^\| `--([a-zA-Z]+)`/gm)].map((m) => m[1]);
    expect(documented.length).toBeGreaterThan(0);
    expect([...KNOWN_FLAGS].sort()).toEqual([...documented].sort());
  });
});
