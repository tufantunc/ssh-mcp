import { describe, it, expect } from 'vitest';
import { classifyCommand } from '../../../src/policy/classifier.js';
import { PolicyEngine, DEFAULT_RULES } from '../../../src/policy/engine.js';
import type { Profile } from '../../../src/types.js';

/**
 * #224: a reader drops from `read-only` to `safe` when its command carries a shell
 * metacharacter. The drop is right; the refusal used to say only "clear readOnly on
 * the profile", naming neither the character nor — for the SFTP verbs — the path.
 */
const readOnlyProfile = {
  name: 'ro-box', host: 'h', port: 22, user: 'viewer', auth: 'agent', tty: false,
  timeout: 60_000, maxChars: 5000, maxOutputBytes: 1_048_576, group: 'dev',
  role: 'viewer', readOnly: true, approvalPolicy: 'ask-destructive', cert: false,
  announceAgent: true, sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 600_000,
  sessionBackgroundMaxMs: 3_600_000, commandQuotaPerDay: 0,
  transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
} as unknown as Profile;

describe('the metacharacter downgrade says what decided it', () => {
  it.each(['sftp:list', 'sftp:download'])('records the character and the cause for %s', (verb) => {
    const parsed = classifyCommand(`${verb} /srv/backup(old)`);
    expect(parsed.class).toBe('safe');
    expect(parsed.readOnlyRejection).toEqual({
      binary: verb, word: '(', cause: 'shell-metacharacter',
    });
  });

  it('records the first metacharacter for a typed reader, not a later one', () => {
    expect(classifyCommand('cat /x;y|z').readOnlyRejection).toEqual({
      binary: 'cat', word: ';', cause: 'shell-metacharacter',
    });
  });

  it('names a two-word reader by its two words', () => {
    expect(classifyCommand('git log a;b').readOnlyRejection).toEqual({
      binary: 'git log', word: ';', cause: 'shell-metacharacter',
    });
  });

  it('keeps the grammar cause for a grammar rejection', () => {
    expect(classifyCommand('journalctl --foo').readOnlyRejection).toEqual({
      binary: 'journalctl', word: '--foo', cause: 'grammar',
    });
  });

  it('says nothing when a nested command, not the metacharacter, decided the class', () => {
    const parsed = classifyCommand('cat /x; sudo id');
    expect(parsed.class).toBe('privileged');
    expect(parsed.readOnlyRejection).toBeUndefined();
  });
});

describe('a readOnly refusal names the metacharacter', () => {
  const engine = new PolicyEngine(DEFAULT_RULES);

  it('for an SFTP verb, names the path as the reason', () => {
    const path = '/srv/backup(old)';
    const evaluation = engine.evaluate(`sftp:list ${path}`, readOnlyProfile, { remotePath: path });
    expect(evaluation.decision).toBe('deny');
    expect(evaluation.reason).toContain(
      'The remote path contains `(`, which counts as a shell metacharacter here, ' +
      'so `sftp:list` is read-only only for a path without one.',
    );
  });

  it('for a typed reader, names the binary and the character', () => {
    const evaluation = engine.evaluate('cat /x;y', readOnlyProfile);
    expect(evaluation.decision).toBe('deny');
    expect(evaluation.reason).toContain(
      '`cat` is read-only only when the command contains no shell metacharacter; `;` is one.',
    );
  });

  it.each([['\r', '\\r'], ['\n', '\\n']])('shows an invisible metacharacter escaped', (char, shown) => {
    const evaluation = engine.evaluate(`cat /x${char}y`, readOnlyProfile);
    expect(evaluation.reason).toContain(`\`${shown}\` is one.`);
  });

  it('quotes a backtick so it stays readable', () => {
    // Wrapped in single backticks it would print as three in a row, the one
    // character the sentence exists to name lost in its own quoting.
    const evaluation = engine.evaluate('cat `which foo`', readOnlyProfile);
    expect(evaluation.reason).toContain('`` ` `` is one.');
  });
});
