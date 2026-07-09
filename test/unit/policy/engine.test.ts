import { describe, it, expect } from 'vitest';
import { PolicyEngine, DEFAULT_RULES } from '../../../src/policy/engine.js';
import type { Profile } from '../../../src/types.js';

function makeProfile(overrides: Partial<Profile> = {}): Profile {
  return {
    name: 'dev',
    host: 'localhost',
    port: 22,
    user: 'test',
    auth: 'agent',
    tty: false,
    timeout: 60000,
    maxChars: 5000,
    role: 'operator',
    readOnly: false,
    approvalPolicy: 'ask-destructive',
    cert: false,
    sessionMaxPerConnection: 5,
    sessionIdleTimeoutMs: 600000,
    ...overrides,
  };
}

describe('PolicyEngine', () => {
  const engine = new PolicyEngine(DEFAULT_RULES);

  it('allows read-only commands for operator on dev', () => {
    const profile = makeProfile({ role: 'operator', name: 'dev' });
    const result = engine.evaluate('ls -la', profile, 'read-command');
    expect(result.decision).toBe('allow');
    expect(result.commandClass).toBe('read-only');
  });

  it('requires approval for destructive commands with ask-destructive', () => {
    const profile = makeProfile({ role: 'admin', name: 'dev', approvalPolicy: 'ask-destructive' });
    const result = engine.evaluate('rm -rf /tmp/test', profile, 'run-command');
    expect(result.decision).toBe('require-approval');
  });

  it('allows destructive commands with auto approval', () => {
    const profile = makeProfile({ role: 'admin', name: 'dev', approvalPolicy: 'auto' });
    const result = engine.evaluate('rm -rf /tmp/test', profile, 'run-command');
    expect(result.decision).toBe('allow');
  });

  it('denies privileged commands for viewer role', () => {
    const profile = makeProfile({ role: 'viewer', name: 'dev' });
    const result = engine.evaluate('sudo whoami', profile, 'run-command');
    expect(result.decision).toBe('deny');
    expect(result.reason).toContain('viewer');
  });

  it('denylist always wins', () => {
    const engineWithDeny = new PolicyEngine({
      ...DEFAULT_RULES,
      denylist: ['rm\\s+-rf'],
    });
    const profile = makeProfile({ role: 'admin', name: 'dev', approvalPolicy: 'auto' });
    const result = engineWithDeny.evaluate('rm -rf /tmp/test', profile, 'run-command');
    expect(result.decision).toBe('deny');
    expect(result.ruleId).toBe('denylist');
  });

  it('readOnly profile only allows read-only', () => {
    const profile = makeProfile({ readOnly: true, name: 'prod-db' });
    expect(engine.evaluate('ls', profile, 'read-command').decision).toBe('allow');
    expect(engine.evaluate('npm install', profile, 'run-command').decision).toBe('deny');
  });

  it('prod host group is stricter than dev', () => {
    const operatorProd = makeProfile({ role: 'operator', name: 'prod-web-1' });
    const adminProd = makeProfile({ role: 'admin', name: 'prod-web-1' });
    const adminDev = makeProfile({ role: 'admin', name: 'dev-local' });

    // Operator cannot run destructive on prod (denied by role binding)
    expect(engine.evaluate('rm -rf /tmp/test', operatorProd, 'run-command').decision).toBe('deny');

    // Admin can run destructive on prod but needs approval
    expect(engine.evaluate('rm -rf /tmp/test', adminProd, 'run-command').decision).toBe('require-approval');

    // Admin on dev also needs approval (ask-destructive default)
    expect(engine.evaluate('rm -rf /tmp/test', adminDev, 'run-command').decision).toBe('require-approval');
  });

  it('ask-all mode requires approval even for read-only', () => {
    const profile = makeProfile({ role: 'admin', name: 'dev', approvalPolicy: 'ask-all' });
    expect(engine.evaluate('ls -la', profile, 'read-command').decision).toBe('require-approval');
  });

  it('deny mode requires approval for destructive', () => {
    const profile = makeProfile({ role: 'admin', name: 'dev', approvalPolicy: 'deny' });
    expect(engine.evaluate('rm -rf /tmp/x', profile, 'run-command').decision).toBe('require-approval');
  });

  it('denylist with invalid regex falls back to substring match', () => {
    const engineWithBadRegex = new PolicyEngine({
      ...DEFAULT_RULES,
      denylist: ['[invalid'],
    });
    const profile = makeProfile({ role: 'admin', name: 'dev', approvalPolicy: 'auto' });
    // Should not throw, should fall back to includes()
    const result = engineWithBadRegex.evaluate('echo [invalid pattern', profile, 'run-command');
    expect(result.decision).toBe('deny');
  });
});
