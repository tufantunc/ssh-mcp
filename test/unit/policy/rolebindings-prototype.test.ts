import { describe, it, expect } from 'vitest';
import { mergePolicyRules, resolvePolicyRules, DEFAULT_RULES } from '../../../src/policy/engine.js';

/**
 * `roleBindings` is indexed by a name the operator chose (issue #172).
 *
 * `role` is a free string — `role: z.string().default('operator')` — and
 * `mergePolicyRules` assigns `roleBindings[role]`. On a plain object that assignment
 * is not always a key: for `__proto__` it invokes the prototype setter instead.
 *
 * Measured before the fix, the effect was not global — `Object.prototype` stayed
 * clean — but this object's own prototype became the operator's tier map, after which
 * `roleBindings.prod` resolved through the chain as though `prod` were a role. The
 * config schema rejects that name before the engine sees it, and that guard is what
 * zod 4 silently disabled once already, which is why the engine does not rely on it.
 */
describe('roleBindings cannot be reached through the prototype chain', () => {
  const evilRole = () => JSON.parse('{"__proto__":{"prod":["privileged"]}}');

  it('treats __proto__ as a key rather than a prototype assignment', () => {
    const merged = mergePolicyRules(DEFAULT_RULES, { roleBindings: evilRole() });

    expect(Object.getPrototypeOf(merged.roleBindings)).toBeNull();
    expect(Object.keys(merged.roleBindings)).toContain('__proto__');
    // The load-bearing assertion: before the fix this was ['privileged'], inherited
    // from the tier map the setter installed as the prototype.
    expect(merged.roleBindings.prod).toBeUndefined();
    expect(Object.prototype).not.toHaveProperty('prod');
  });

  it('does not answer for Object.prototype members, with no config involved', () => {
    // `mergePolicyRules` returns DEFAULT_RULES unchanged when there is no override,
    // which is the commonest path, so fixing only the merged copy would have left it.
    for (const rules of [DEFAULT_RULES, mergePolicyRules(DEFAULT_RULES, undefined)]) {
      for (const inherited of ['toString', 'constructor', 'valueOf', 'hasOwnProperty']) {
        expect(rules.roleBindings[inherited]).toBeUndefined();
      }
    }
  });

  it('still merges an ordinary override, and still copies rather than aliasing', () => {
    const merged = mergePolicyRules(DEFAULT_RULES, {
      roleBindings: { operator: { prod: ['read-only', 'safe', 'destructive'] } },
    });

    expect(merged.roleBindings.operator.prod).toEqual(['read-only', 'safe', 'destructive']);
    expect(merged.roleBindings.admin).toEqual(DEFAULT_RULES.roleBindings.admin);
    // The reason the copying loop exists: DEFAULT_RULES is a module-level singleton.
    // Checked on a role the override does *not* touch — `operator` gets a fresh object
    // from the override loop's spread either way, so asserting identity there passed
    // even with the copying loop's spread removed. `admin` is the one that would alias.
    expect(merged.roleBindings.admin).not.toBe(DEFAULT_RULES.roleBindings.admin);
    expect(DEFAULT_RULES.roleBindings.operator.prod).toEqual(['read-only', 'safe']);
  });

  it('leaves every real policy decision where it was', () => {
    const profile = (role: string) => ({
      name: 'p', group: 'prod', host: 'h', port: 22, user: 'u', auth: 'key' as const, role,
      readOnly: false, approvalPolicy: 'ask-destructive' as const, tty: false, timeout: 5000,
      maxChars: 5000, maxOutputBytes: 1_048_576, maxTransferBytes: 1_073_741_824,
      cert: false, sessionMaxPerConnection: 5,
      sessionIdleTimeoutMs: 60_000, sessionBackgroundMaxMs: 3_600_000, commandQuotaPerDay: 0,
    });
    const rules = resolvePolicyRules([profile('admin'), profile('operator'), profile('viewer')]);
    expect(rules.roleBindings.admin.prod).toEqual(['read-only', 'safe', 'destructive']);
    expect(rules.roleBindings.operator.prod).toEqual(['read-only', 'safe']);
    expect(rules.roleBindings.viewer.prod).toEqual(['read-only']);
  });
});
