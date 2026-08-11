import { describe, it, expect } from 'vitest';
import { PolicyEngine, DEFAULT_RULES } from '../../../src/policy/engine.js';
import type { Profile } from '../../../src/types.js';

function makeProfile(overrides: Partial<Profile> = {}): Profile {
  return {
    name: 'dev',
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
    approvalPolicy: 'ask-destructive',
    cert: false,
    sessionMaxPerConnection: 5,
    sessionIdleTimeoutMs: 600000,
    sessionBackgroundMaxMs: 3600000,
    commandQuotaPerDay: 0,
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
    const operatorProd = makeProfile({ role: 'operator', name: 'prod-web-1', group: 'prod' });
    const adminProd = makeProfile({ role: 'admin', name: 'prod-web-1', group: 'prod' });
    const adminDev = makeProfile({ role: 'admin', name: 'dev-local', group: 'dev' });

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

  it('deny mode denies destructive commands outright (no approval prompt)', () => {
    const profile = makeProfile({ role: 'admin', name: 'dev', approvalPolicy: 'deny' });
    const result = engine.evaluate('rm -rf /tmp/x', profile, 'run-command');
    expect(result.decision).toBe('deny');
    expect(result.ruleId).toBe('approval-policy');
  });

  it('deny mode denies privileged commands outright', () => {
    const profile = makeProfile({ role: 'admin', name: 'dev', approvalPolicy: 'deny' });
    expect(engine.evaluate('sudo systemctl restart nginx', profile, 'privileged-command').decision).toBe('deny');
  });

  it('deny mode still allows non-destructive commands', () => {
    const profile = makeProfile({ role: 'admin', name: 'dev', approvalPolicy: 'deny' });
    expect(engine.evaluate('ls -la', profile, 'read-command').decision).toBe('allow');
  });

  it('rejects an invalid denylist pattern at construction', () => {
    // Previously this fell back to `command.includes(pattern)` — matching the
    // command against regex *source text*. A deny rule that silently degrades
    // is worse than a startup failure, because nothing surfaces the degradation.
    expect(() => new PolicyEngine({ ...DEFAULT_RULES, denylist: ['[invalid'] }))
      .toThrow(/Invalid denylist pattern/);
  });

  it('applies operator-supplied denylist patterns on top of the canonical list', () => {
    const engineWithExtra = new PolicyEngine({ ...DEFAULT_RULES, denylist: ['\\bnpm\\s+publish\\b'] });
    const profile = makeProfile({ role: 'admin', group: 'dev', approvalPolicy: 'auto' });
    expect(engineWithExtra.evaluate('npm publish', profile, 'run-command').decision).toBe('deny');
    // ...and the canonical entries still apply.
    expect(engineWithExtra.evaluate('rm -rf /', profile, 'run-command').ruleId).toBe('denylist');
  });

  it('separates never-allowed commands from destructive-but-approvable ones', () => {
    const profile = makeProfile({ role: 'admin', group: 'dev', approvalPolicy: 'ask-destructive' });
    // `rm -rf /` can never run; `rm -rf /tmp/x` is destructive but approvable.
    expect(engine.evaluate('rm -rf /', profile, 'run-command').ruleId).toBe('denylist');
    expect(engine.evaluate('rm -rf /tmp/x', profile, 'run-command').decision).toBe('require-approval');
  });

  /*
   * These two can only be reached by constructing the engine directly.
   * resolvePolicyRules refuses to start on either shape, so a config file
   * cannot produce them, which is the point: the engine is a public class, and
   * the fallback below is what a library consumer gets when the startup check
   * is not in the path.
   */
  describe('unresolved bindings fail closed', () => {
    it('does not hand an unresolved tier the prod cell', () => {
      const scoped = new PolicyEngine({
        roleBindings: {
          deployer: { prod: ['read-only', 'safe', 'destructive', 'privileged'] },
        },
      });
      // Falling back to HOST_GROUPS[0] was safe while the prod cell was always
      // a role's strictest. A [policy] block can now write it, so the hop would
      // hand every unresolved tier whatever prod was granted.
      const staging = makeProfile({ role: 'deployer', name: 'staging-web', group: undefined, approvalPolicy: 'auto' });
      expect(scoped.evaluate('sudo id', staging, 'privileged-command').decision).toBe('deny');
      expect(scoped.evaluate('ls -la', staging, 'read-command').decision).toBe('allow');
    });

    it('demotes an unknown role to read-only', () => {
      const unknown = makeProfile({ role: 'deployer', name: 'dev', approvalPolicy: 'auto' });
      expect(engine.evaluate('npm install', unknown, 'run-command').decision).toBe('deny');
      expect(engine.evaluate('ls -la', unknown, 'read-command').decision).toBe('allow');
    });
  });

  it('resolves an unrecognised profile name to the strictest tier', () => {
    // Previously any unrecognised name fell through to `dev`, so a production
    // host merely named "web-01" silently got the loosest permissions.
    const unknown = makeProfile({ role: 'admin', name: 'web-01', group: undefined });
    expect(engine.evaluate('sudo whoami', unknown, 'privileged-command').decision).toBe('deny');
    // An explicit group is authoritative.
    const tagged = makeProfile({ role: 'admin', name: 'web-01', group: 'dev' });
    expect(engine.evaluate('sudo whoami', tagged, 'privileged-command').decision).toBe('require-approval');
  });

  /*
   * Reported as #91: the refusal read `Role "admin" cannot run "privileged"
   * commands`, so the reporter concluded the admin role simply cannot sudo and
   * went looking for a larger role that does not exist. The host group is what
   * actually decided — admin has `privileged` on staging and dev, not on prod —
   * and the message never mentioned it.
   */
  describe('refusal explains which of the three things decided', () => {
    function denial(overrides: Parameters<typeof makeProfile>[0]): string {
      return engine.evaluate('sudo whoami', makeProfile(overrides), 'privileged-command').reason ?? '';
    }

    it('names the group, not just the role and class', () => {
      const reason = denial({ role: 'admin', name: 'web-01', group: undefined });
      expect(reason).toContain('admin');
      expect(reason).toContain('privileged');
      expect(reason).toContain('prod');
    });

    it('lists what the role can run, so the boundary is visible', () => {
      expect(denial({ role: 'admin', name: 'web-01', group: 'prod' }))
        .toMatch(/allowed: .*read-only.*safe.*destructive/);
    });

    // The inferred case is the one worth calling out: nobody wrote "prod"
    // anywhere, so without saying so the operator cannot see why it applied.
    it('says the group was inferred when none was set, and how to set one', () => {
      const reason = denial({ role: 'admin', name: 'web-01', group: undefined });
      expect(reason).toMatch(/No group is set/);
      expect(reason).toMatch(/--group/);
    });

    it('points at the real levers when the group was explicit', () => {
      const reason = denial({ role: 'admin', name: 'web-01', group: 'prod' });
      expect(reason).not.toMatch(/No group is set/);
      expect(reason).toMatch(/roleBindings/);
    });

    it('explains a read-only profile as read-only rather than as a role problem', () => {
      const reason = denial({ role: 'admin', name: 'web-01', group: 'dev', readOnly: true });
      expect(reason).toMatch(/read-only/);
      expect(reason).toMatch(/readOnly/);
    });
  });
});
