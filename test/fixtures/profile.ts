import type { Profile } from '../../src/types.js';

/**
 * A complete Profile: every required field set, nothing optional, so a test names only
 * the fields it is about. One literal for the suites that each carried their own copy;
 * a new required field breaks here, once.
 */
export function makeProfile(overrides: Partial<Profile> = {}): Profile {
  return {
    name: 'dev',
    group: 'dev',
    host: 'stub',
    port: 22,
    user: 'tester',
    auth: 'password',
    tty: false,
    timeout: 5000,
    maxChars: 5000,
    maxOutputBytes: 1_048_576,
    role: 'admin',
    readOnly: false,
    announceAgent: true,
    approvalPolicy: 'ask-destructive',
    cert: false,
    sessionMaxPerConnection: 5,
    sessionIdleTimeoutMs: 60_000,
    sessionBackgroundMaxMs: 3_600_000,
    commandQuotaPerDay: 0,
    transferMaxBytes: 268_435_456,
    transferTimeoutMs: 300_000,
    ...overrides,
  };
}
