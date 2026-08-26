import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, chmod, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { loadConfig, getProfile } from '../../../src/config/loader.js';
import {
  PolicyEngine,
  DEFAULT_RULES,
  mergePolicyRules,
  resolvePolicyRules,
} from '../../../src/policy/engine.js';
import type { AppConfig } from '../../../src/types.js';

/**
 * The point of these tests is that a `[policy]` block changes a *decision*.
 *
 * PolicyEngine's constructor has always accepted rules, so the capability
 * existed in the type long before anything fed it from configuration — which is
 * precisely what made the README document a table that was parsed and dropped
 * (#95). A test asserting only that the config parses would have passed then
 * too. So every case here goes config file → loadConfig → mergePolicyRules →
 * evaluate(), and asserts on the verdict at the end of that chain.
 */

let tempDir: string;

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), 'ssh-mcp-policy-'));
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

async function writeConfig(content: string): Promise<string> {
  const path = join(tempDir, 'config.toml');
  await writeFile(path, content, 'utf8');
  await chmod(path, 0o600);
  return path;
}

/**
 * config file → the engine an operator would actually be running.
 *
 * `resolvePolicyRules`, not `mergePolicyRules`, because that is the call main()
 * makes: the startup coherence check runs here or these tests assert on an
 * engine nobody can boot.
 */
function engineFor(config: AppConfig): PolicyEngine {
  return new PolicyEngine(resolvePolicyRules(config.profiles, config.policy));
}

const ADMIN_PROD_PROFILE = `
[[profiles]]
name = "prod-web"
host = "10.0.0.5"
user = "deploy"
role = "admin"
group = "prod"
`;

describe('[policy] roleBindings', () => {
  it('grants privileged to admin on prod, which the defaults refuse', async () => {
    const before = await loadConfig(await writeConfig(ADMIN_PROD_PROFILE));
    const denied = engineFor(before).evaluate(
      'sudo systemctl restart nginx',
      getProfile(before, 'prod-web'),
      'privileged-command',
    );
    expect(denied.decision).toBe('deny');
    expect(denied.ruleId).toBe('role-binding');

    const after = await loadConfig(await writeConfig(`
${ADMIN_PROD_PROFILE}

[policy.roleBindings.admin]
prod = ["read-only", "safe", "destructive", "privileged"]
`));
    const granted = engineFor(after).evaluate(
      'sudo systemctl restart nginx',
      getProfile(after, 'prod-web'),
      'privileged-command',
    );
    // Not "allow": the profile still defaults to ask-destructive, so the command
    // now reaches the approval gate instead of being refused outright. That is
    // the flip that matters — the role binding no longer decides.
    expect(granted.decision).toBe('require-approval');
    expect(granted.ruleId).toBe('approval-policy');
  });

  it('leaves the tiers and roles the override never mentions on their defaults', async () => {
    const config = await loadConfig(await writeConfig(`
[[profiles]]
name = "prod-web"
host = "10.0.0.5"
user = "deploy"
role = "admin"
group = "prod"

[[profiles]]
name = "staging-web"
host = "10.0.0.6"
user = "deploy"
role = "admin"
group = "staging"

[[profiles]]
name = "prod-readonly"
host = "10.0.0.7"
user = "audit"
role = "viewer"
group = "prod"

[policy.roleBindings.admin]
prod = ["read-only"]
`));
    const policy = engineFor(config);

    // The one cell the operator wrote: admin/prod narrowed to read-only.
    expect(policy.evaluate('npm install', getProfile(config, 'prod-web'), 'run-command').decision)
      .toBe('deny');

    // admin/staging is untouched — a role-depth merge would have wiped it.
    expect(policy.evaluate('npm install', getProfile(config, 'staging-web'), 'run-command').decision)
      .toBe('allow');

    // And another role entirely is untouched.
    expect(policy.evaluate('ls -la', getProfile(config, 'prod-readonly'), 'read-command').decision)
      .toBe('allow');
  });

  it('makes a custom tier real, and refuses to start when nothing defines it', async () => {
    const profile = `
[[profiles]]
name = "build-box"
host = "10.0.0.8"
user = "ci"
role = "admin"
group = "tier-1"
approvalPolicy = "auto"
`;
    // An undefined tier used to resolve to the strictest one, which was safe
    // only while roleBindings were compiled in, because the prod cell was that
    // role's strictest. Now that a [policy] block can widen prod, an unresolved
    // tier is a startup error rather than a fallback to whatever prod became.
    const before = await loadConfig(await writeConfig(profile));
    expect(() => engineFor(before)).toThrow(/no bindings for group "tier-1"/);

    const after = await loadConfig(await writeConfig(`
${profile}

[policy.roleBindings.admin]
"tier-1" = ["read-only", "safe", "destructive", "privileged"]
`));
    expect(
      engineFor(after).evaluate('sudo make install', getProfile(after, 'build-box'), 'privileged-command').decision,
    ).toBe('allow');
  });

  it('makes a custom role real, and refuses to start when nothing defines it', async () => {
    const profile = `
[[profiles]]
name = "deploy-box"
host = "10.0.0.10"
user = "ci"
role = "deployer"
group = "dev"
approvalPolicy = "auto"
`;
    // An unknown role is demoted to read-only, and at the point of use that is
    // indistinguishable from a policy decision someone made on purpose. It is the
    // exact shape of #95, from the profile side rather than the [policy] side.
    const before = await loadConfig(await writeConfig(profile));
    expect(() => engineFor(before)).toThrow(/role "deployer" has no role bindings/);

    const after = await loadConfig(await writeConfig(`
${profile}

[policy.roleBindings.deployer]
dev = ["read-only", "safe"]
`));
    expect(
      engineFor(after).evaluate('npm install', getProfile(after, 'deploy-box'), 'run-command').decision,
    ).toBe('allow');
  });

  it('treats an empty class list as a real lockdown, not as unset', async () => {
    const config = await loadConfig(await writeConfig(`
${ADMIN_PROD_PROFILE}

[policy.roleBindings.admin]
prod = []
`));
    // Asserting that the merge copied `[]` through would pass whether or not the
    // lockdown works: the deny depends on `[]` surviving as a value one layer
    // down, so drive it to the verdict.
    const denied = engineFor(config).evaluate(
      'ls -la',
      getProfile(config, 'prod-web'),
      'read-command',
    );
    expect(denied.decision).toBe('deny');
    expect(denied.ruleId).toBe('role-binding');

    // And the lockdown is confined to the cell the operator wrote.
    expect(mergePolicyRules(DEFAULT_RULES, config.policy).roleBindings.admin.staging)
      .toEqual(DEFAULT_RULES.roleBindings.admin.staging);
  });

  it('applies a denylist from config', async () => {
    const config = await loadConfig(await writeConfig(`
[[profiles]]
name = "dev-box"
host = "10.0.0.9"
user = "dev"
role = "admin"
group = "dev"
approvalPolicy = "auto"

[policy]
denylist = ["^terraform\\\\s+destroy"]
`));
    const policy = engineFor(config);
    const denied = policy.evaluate('terraform destroy -auto-approve', getProfile(config, 'dev-box'), 'run-command');
    expect(denied.decision).toBe('deny');
    expect(denied.ruleId).toBe('denylist');
    // Neighbouring commands are unaffected: the pattern is a regex, not a ban
    // on the binary.
    expect(policy.evaluate('terraform plan', getProfile(config, 'dev-box'), 'run-command').decision)
      .toBe('allow');
  });

  it('behaves exactly like the compiled defaults when no [policy] section exists', async () => {
    const config = await loadConfig(await writeConfig(ADMIN_PROD_PROFILE));
    expect(config.policy).toBeUndefined();
    expect(mergePolicyRules(DEFAULT_RULES, config.policy)).toBe(DEFAULT_RULES);
  });
});

describe('[policy] validation', () => {
  it('rejects a misspelled command class at load', async () => {
    const path = await writeConfig(`
${ADMIN_PROD_PROFILE}

[policy.roleBindings.admin]
prod = ["read-only", "priviledged"]
`);
    // The whole point: a typo that parses to a grant of nothing is
    // indistinguishable at runtime from a deliberate policy decision.
    await expect(loadConfig(path)).rejects.toThrow(/policy\.roleBindings\.admin\.prod/);
  });

  it('rejects an unknown key inside [policy] rather than dropping it', async () => {
    const path = await writeConfig(`
${ADMIN_PROD_PROFILE}

[policy]
allowlist = ["ls"]
`);
    await expect(loadConfig(path)).rejects.toThrow(/Config validation error/);
  });

  it('rejects a role or tier named __proto__ rather than accepting one that cannot exist', async () => {
    // Merging assigns into a plain object, so this key would land on the
    // prototype and the role would parse, validate, and then not be there.
    const path = await writeConfig(`
${ADMIN_PROD_PROFILE}

[policy.roleBindings."__proto__"]
prod = ["privileged"]
`);
    await expect(loadConfig(path)).rejects.toThrow(/Reserved name/);

    const tier = await writeConfig(`
${ADMIN_PROD_PROFILE}

[policy.roleBindings.admin]
"constructor" = ["privileged"]
`);
    await expect(loadConfig(tier)).rejects.toThrow(/Reserved name/);
  });

  it('names the role a reserved tier sits under, not just the tier', async () => {
    // The path is the actionable half of the refusal. Reporting only the leaf key
    // pointed the operator at `policy.roleBindings.__proto__` — a top-level role that
    // is not in their file — while the role they have to edit went unnamed. Asserting
    // the message alone let that regress unnoticed.
    const path = await writeConfig(`
${ADMIN_PROD_PROFILE}

[policy.roleBindings.admin]
"__proto__" = ["privileged"]
`);
    await expect(loadConfig(path)).rejects.toThrow(/policy\.roleBindings\.admin\.__proto__/);
  });

  it('rejects a role named prototype', async () => {
    // `prototype` was in the reserved list with nothing pinning it: removing it from
    // the list failed no test. It is also the name a future narrowing would drop
    // first, since unlike `__proto__` it reaches the key schema on its own.
    const path = await writeConfig(`
${ADMIN_PROD_PROFILE}

[policy.roleBindings."prototype"]
prod = ["privileged"]
`);
    await expect(loadConfig(path)).rejects.toThrow(/Reserved name/);
  });

  it('reports every reserved name rather than stopping at the first', async () => {
    // The walk uses `continue`, not `return`, matching the engine's coherence check.
    // With only a `/Reserved name/` assertion, swapping one for the other was
    // invisible.
    const path = await writeConfig(`
${ADMIN_PROD_PROFILE}

[policy.roleBindings."constructor"]
prod = ["privileged"]

[policy.roleBindings.admin]
"prototype" = ["privileged"]
`);
    const error = await loadConfig(path).then(() => null, (e: Error) => e);
    expect(error?.message).toMatch(/roleBindings\.constructor/);
    expect(error?.message).toMatch(/roleBindings\.admin\.prototype/);
  });

  it('explains an empty role or tier name instead of saying only that the key is invalid', async () => {
    // zod 4's record replaces the key schema's own message with `Invalid key in
    // record`, so `min(1)`'s text stopped reaching the operator.
    const path = await writeConfig(`
${ADMIN_PROD_PROFILE}

[policy.roleBindings.""]
prod = ["privileged"]
`);
    await expect(loadConfig(path)).rejects.toThrow(/cannot be empty/);
  });

  it('refuses roleBindings that is not a table', async () => {
    const path = await writeConfig(`
${ADMIN_PROD_PROFILE}

[policy]
roleBindings = "nope"
`);
    await expect(loadConfig(path)).rejects.toThrow(/policy\.roleBindings/);
  });

  it('names the root in a top-level validation error instead of an empty path', async () => {
    const path = await writeConfig(`
${ADMIN_PROD_PROFILE}

[policies]
roleBindings = {}
`);
    await expect(loadConfig(path)).rejects.toThrow(/\(root\): Unrecognized key/);
  });

  it('names the unrecognised section rather than failing generically', async () => {
    const path = await writeConfig(`
${ADMIN_PROD_PROFILE}

[telemetry]
enabled = true
`);
    // Before the root schema was strict, this parsed cleanly and vanished: a
    // clean startup, no warning, and none of the configured behaviour. Asserting
    // on the section name rather than the wrapper, so the test still means
    // something if the message ever stops saying which key was rejected.
    await expect(loadConfig(path)).rejects.toThrow(/telemetry/);
  });
});

describe('mergePolicyRules', () => {
  it('does not mutate the compiled defaults', () => {
    const snapshot = JSON.stringify(DEFAULT_RULES);
    mergePolicyRules(DEFAULT_RULES, {
      roleBindings: { admin: { prod: ['read-only', 'safe', 'destructive', 'privileged'] } },
    });
    mergePolicyRules(DEFAULT_RULES, { roleBindings: { viewer: { dev: [] } } });
    expect(JSON.stringify(DEFAULT_RULES)).toBe(snapshot);
  });

  it('adds roles the defaults have never heard of', () => {
    const merged = mergePolicyRules(DEFAULT_RULES, {
      roleBindings: { auditor: { prod: ['read-only'] } },
    });
    expect(merged.roleBindings.auditor).toEqual({ prod: ['read-only'] });
    expect(merged.roleBindings.admin).toEqual(DEFAULT_RULES.roleBindings.admin);
  });

});

/**
 * The merge is additive by design: an unknown role or tier is added rather than
 * rejected, which is what makes a custom `group` resolve to real bindings. The
 * cost is that nothing distinguishes "new custom role" from "typo of an existing
 * one", so a restriction written under a misspelt name merges into a role
 * nobody holds and the operator reads their config as a lockdown that was never
 * applied.
 *
 * These cases are the cross-check that closes that, in both directions.
 */
describe('startup coherence', () => {
  it('rejects a profile whose group nothing defines', async () => {
    const config = await loadConfig(await writeConfig(`
[[profiles]]
name = "build-box"
host = "10.0.0.8"
user = "ci"
role = "admin"
group = "teir-1"

[policy.roleBindings.admin]
prod = ["read-only", "safe", "destructive", "privileged"]
"tier-1" = ["read-only", "safe", "destructive"]
`));
    // Both README examples in one config, and one typo away from the tier the
    // operator meant. Before the check, "teir-1" fell through to the prod cell
    // this very config had just widened to privileged.
    expect(() => engineFor(config)).toThrow(/profile "build-box".*no bindings for group "teir-1"/s);
  });

  it('rejects a profile whose inferred tier nothing defines', async () => {
    const config = await loadConfig(await writeConfig(`
[[profiles]]
name = "staging-web"
host = "10.0.0.11"
user = "deploy"
role = "deployer"

[[profiles]]
name = "prod-web"
host = "10.0.0.12"
user = "deploy"
role = "deployer"

[policy.roleBindings.deployer]
prod = ["read-only", "safe", "destructive", "privileged"]
`));
    // No group is set anywhere here, so a check on the explicit field would pass
    // this config. "staging-web" infers `staging`, the role defines only `prod`,
    // and the old fallback handed it the privileged prod grant.
    expect(() => engineFor(config)).toThrow(/profile "staging-web".*inferred from the name as "staging"/s);
  });

  it('rejects a roleBindings block no profile can reach', async () => {
    const config = await loadConfig(await writeConfig(`
[[profiles]]
name = "prod-web"
host = "10.0.0.5"
user = "deploy"
role = "operator"
group = "prod"

[policy.roleBindings.operater]
prod = ["read-only"]
`));
    // The typo merges as a fourth role, `operator.prod` keeps its default, and
    // the profile still runs on defaults the operator believed they had narrowed.
    expect(() => engineFor(config)).toThrow(/no profile uses role "operater"/);
  });

  it('rejects a tier key no profile can reach', async () => {
    const config = await loadConfig(await writeConfig(`
${ADMIN_PROD_PROFILE}

[policy.roleBindings.admin]
stagign = ["read-only"]
`));
    expect(() => engineFor(config)).toThrow(/key "stagign" matches no profile's group/);
  });

  it('reports every problem at once rather than the first', async () => {
    const config = await loadConfig(await writeConfig(`
[[profiles]]
name = "build-box"
host = "10.0.0.8"
user = "ci"
role = "admin"
group = "teir-1"

[policy.roleBindings.operater]
prod = ["read-only"]
`));
    // An operator fixing a config file wants the list, not one round trip per
    // typo. Same shape as the config validation error in loader.ts.
    expect(() => engineFor(config)).toThrow(/teir-1[\s\S]*operater/);
  });

  it('accepts a custom role and tier that a profile actually uses', async () => {
    const config = await loadConfig(await writeConfig(`
[[profiles]]
name = "build-box"
host = "10.0.0.8"
user = "ci"
role = "deployer"
group = "tier-1"
approvalPolicy = "auto"

[policy.roleBindings.deployer]
"tier-1" = ["read-only", "safe", "destructive"]
`));
    // The negative control: the check must not make custom names unusable,
    // which is the feature #95 asked for.
    expect(() => engineFor(config)).not.toThrow();
    expect(
      engineFor(config).evaluate('rm -rf /tmp/build', getProfile(config, 'build-box'), 'run-command').decision,
    ).toBe('allow');
  });

  it('accepts a config with no [policy] section at all', async () => {
    const config = await loadConfig(await writeConfig(ADMIN_PROD_PROFILE));
    expect(() => engineFor(config)).not.toThrow();
    expect(resolvePolicyRules(config.profiles, config.policy)).toBe(DEFAULT_RULES);
  });
});
