import { describe, it, expect } from 'vitest';
import { PolicyEngine, DEFAULT_RULES } from '../../../src/policy/engine.js';
import type { Profile } from '../../../src/types.js';

const profile: Profile = {
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
  role: 'admin',
  readOnly: false,
  announceAgent: true,
  approvalPolicy: 'auto',
  cert: false,
  sessionMaxPerConnection: 5,
  sessionIdleTimeoutMs: 600000,
  sessionBackgroundMaxMs: 3600000,
  commandQuotaPerDay: 0,
  transferMaxBytes: 268_435_456,
  transferTimeoutMs: 300_000,
};

/**
 * Reload compiles the rules once, in validation, and the swap installs the compiled
 * result: so the swap step itself cannot throw, and an invalid denylist is caught
 * before anything moved.
 */
describe('PolicyEngine.compile and replaceRules', () => {
  it('compile throws on an invalid denylist pattern, before any engine is touched', () => {
    const engine = new PolicyEngine({ ...DEFAULT_RULES, denylist: ['\\bnpm\\s+publish\\b'] });
    expect(engine.evaluate('npm publish', profile).ruleId).toBe('denylist');

    expect(() => PolicyEngine.compile({ ...DEFAULT_RULES, denylist: ['^terraform', '[invalid'] }))
      .toThrow(/Invalid denylist pattern/);

    expect(engine.evaluate('npm publish', profile).ruleId).toBe('denylist');
    expect(engine.evaluate('terraform plan', profile).ruleId).not.toBe('denylist');
  });

  it('exposes the live rules, as given, for comparison', () => {
    const before = { ...DEFAULT_RULES, denylist: ['^a'] };
    const after = { ...DEFAULT_RULES, denylist: ['^b'] };
    const engine = new PolicyEngine(before);
    expect(engine.rules).toBe(before);

    engine.replaceRules(PolicyEngine.compile(after));
    expect(engine.rules).toBe(after);
  });

  it('applies a newly denylisted command and leaves the OPA settings alone', () => {
    const engine = new PolicyEngine(DEFAULT_RULES);
    engine.setOpaUrl('http://127.0.0.1:8181/v1/data/ssh/allow', true, 1234);
    expect(engine.evaluate('terraform destroy', profile).ruleId).not.toBe('denylist');

    engine.replaceRules(PolicyEngine.compile({ ...DEFAULT_RULES, denylist: ['^terraform\\s+destroy'] }));

    const result = engine.evaluate('terraform destroy', profile);
    expect(result.decision).toBe('deny');
    expect(result.ruleId).toBe('denylist');
    expect((engine as any).opaUrl).toBe('http://127.0.0.1:8181/v1/data/ssh/allow');
    expect((engine as any).opaFailClosed).toBe(true);
    expect((engine as any).opaTimeoutMs).toBe(1234);
  });
});
