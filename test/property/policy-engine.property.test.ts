import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { PolicyEngine, DEFAULT_RULES } from '../../src/policy/engine.js';
import { findForbiddenMatch } from '../../src/policy/classifier.js';
import type { PolicyDecision, Profile } from '../../src/types.js';
import { CLASS_RANK, fcParams } from './fc-seed.js';
import { closedCommand } from './command-arbitraries.js';

// What the engine promises on top of the classifier, under the shipped default rules:
// a readOnly profile never runs more than read-only, the never-allowed list is not
// negotiable by role, each approval policy has a fixed shape, and a higher class is never
// treated more permissively than a lower one. Built once: the engine is stateless per call.

const engine = new PolicyEngine(DEFAULT_RULES);

function makeProfile(overrides: Partial<Profile> = {}): Profile {
  return {
    name: 'p',
    group: 'dev',
    host: 'localhost',
    port: 22,
    user: 'test',
    auth: 'agent',
    tty: false,
    timeout: 60000,
    maxChars: 5000,
    maxOutputBytes: 1048576,
    role: 'operator',
    readOnly: false,
    announceAgent: true,
    approvalPolicy: 'ask-destructive',
    cert: false,
    sessionMaxPerConnection: 5,
    sessionIdleTimeoutMs: 600000,
    sessionBackgroundMaxMs: 3600000,
    commandQuotaPerDay: 0,
    transferMaxBytes: 268_435_456,
    transferTimeoutMs: 300_000,
    ...overrides,
  };
}

const profile = fc
  .record({
    role: fc.constantFrom('admin', 'operator', 'viewer'),
    group: fc.constantFrom('prod', 'staging', 'dev'),
    approvalPolicy: fc.constantFrom('auto' as const, 'ask-destructive' as const, 'ask-all' as const, 'deny' as const),
    readOnly: fc.boolean(),
  })
  .map((fields) => makeProfile(fields));

/** How much a decision lets through: allow > require-approval > deny. */
const PERMISSIVENESS: Record<PolicyDecision, number> = { allow: 2, 'require-approval': 1, deny: 0 };

/**
 * Counts `allow` decisions across a property's run, so a property cannot pass only because
 * every sampled profile was denied everything.
 */
function allowCounter() {
  let allows = 0;
  return {
    see(decision: PolicyDecision) { if (decision === 'allow') allows++; },
    assertSome() { expect(allows).toBeGreaterThan(0); },
  };
}

describe('PolicyEngine invariants (default rules)', () => {
  it('lets a readOnly profile run nothing above read-only', () => {
    const allows = allowCounter();
    fc.assert(
      fc.property(profile.map((p) => ({ ...p, readOnly: true })), closedCommand, (p, command) => {
        const result = engine.evaluate(command, p);
        allows.see(result.decision);
        if (result.decision === 'deny') return;
        expect(result.commandClass, command).toBe('read-only');
      }),
      fcParams(200),
    );
    allows.assertSome();
  });

  it('denies anything on the never-allowed list, whatever the role, tier or approval policy', () => {
    let hits = 0;
    fc.assert(
      fc.property(profile, closedCommand, (p, command) => {
        if (findForbiddenMatch(command) === null) return;
        hits++;
        expect(engine.evaluate(command, p).decision, command).toBe('deny');
      }),
      fcParams(200),
    );
    expect(hits).toBeGreaterThan(0);
  });

  it('denies an SFTP write to a never-allowed path, whatever the role, tier or approval policy', () => {
    // The README's never-allowed write paths, in the spellings the path readings resolve.
    const path = fc.tuple(
      fc.constantFrom('/etc/cron.d/job', '/etc/systemd/system/x.service', '/home/u/.ssh/authorized_keys', '/root/.ssh/authorized_keys'),
      fc.constantFrom('', '//', '/./'),
    ).map(([p, sep]) => (sep ? p.replace('/', sep) : p));
    fc.assert(
      fc.property(profile, path, (p, remotePath) => {
        const result = engine.evaluate(`sftp:upload ${remotePath}`, p, { remotePath, remoteWrite: true });
        expect(result.decision, remotePath).toBe('deny');
      }),
      fcParams(200),
    );
  });

  it('gives each approval policy its fixed shape', () => {
    const allows = allowCounter();
    fc.assert(
      fc.property(profile, closedCommand, (p, command) => {
        const { decision } = engine.evaluate(command, p);
        allows.see(decision);
        if (p.approvalPolicy === 'auto' || p.approvalPolicy === 'deny') expect(decision, command).not.toBe('require-approval');
        if (p.approvalPolicy === 'ask-all') expect(decision, command).not.toBe('allow');
      }),
      fcParams(200),
    );
    allows.assertSome();
  });

  it('never treats a higher class more permissively than a lower one', () => {
    // The never-allowed check runs before class is considered, so a forbidden command is
    // denied whatever its class; those are covered above and left out here.
    const allows = allowCounter();
    const notForbidden = closedCommand.filter((c) => findForbiddenMatch(c) === null);
    fc.assert(
      fc.property(profile, notForbidden, notForbidden, (p, a, b) => {
        const ra = engine.evaluate(a, p);
        const rb = engine.evaluate(b, p);
        allows.see(ra.decision);
        if (CLASS_RANK[ra.commandClass] > CLASS_RANK[rb.commandClass]) {
          expect(PERMISSIVENESS[ra.decision], `${a} vs ${b}`).toBeLessThanOrEqual(PERMISSIVENESS[rb.decision]);
        }
      }),
      fcParams(200),
    );
    allows.assertSome();
  });
});
