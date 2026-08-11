import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, chmod, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { loadConfig, getProfile } from '../../../src/config/loader.js';
import { PolicyEngine, DEFAULT_RULES, mergePolicyRules } from '../../../src/policy/engine.js';
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

/** config file → the engine an operator would actually be running. */
function engineFor(config: AppConfig): PolicyEngine {
  return new PolicyEngine(mergePolicyRules(DEFAULT_RULES, config.policy));
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

  it('makes a custom tier real instead of falling back to prod', async () => {
    const profile = `
[[profiles]]
name = "build-box"
host = "10.0.0.8"
user = "ci"
role = "admin"
group = "tier-1"
approvalPolicy = "auto"
`;
    // Without a definition, an unrecognised tier resolves to the strictest one.
    const before = await loadConfig(await writeConfig(profile));
    expect(
      engineFor(before).evaluate('sudo make install', getProfile(before, 'build-box'), 'privileged-command').decision,
    ).toBe('deny');

    const after = await loadConfig(await writeConfig(`
${profile}

[policy.roleBindings.admin]
"tier-1" = ["read-only", "safe", "destructive", "privileged"]
`));
    expect(
      engineFor(after).evaluate('sudo make install', getProfile(after, 'build-box'), 'privileged-command').decision,
    ).toBe('allow');
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

  it('names the root in a top-level validation error instead of an empty path', async () => {
    const path = await writeConfig(`
${ADMIN_PROD_PROFILE}

[policies]
roleBindings = {}
`);
    await expect(loadConfig(path)).rejects.toThrow(/\(root\): Unrecognized key/);
  });

  it('rejects an unknown top-level section rather than dropping it', async () => {
    const path = await writeConfig(`
${ADMIN_PROD_PROFILE}

[policies]
roleBindings = {}
`);
    // Before the root schema was strict, this parsed cleanly and vanished: a
    // clean startup, no warning, and none of the configured behaviour.
    await expect(loadConfig(path)).rejects.toThrow(/Config validation error/);
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

  it('treats an empty class list as a real lockdown, not as unset', () => {
    const merged = mergePolicyRules(DEFAULT_RULES, {
      roleBindings: { admin: { prod: [] } },
    });
    expect(merged.roleBindings.admin.prod).toEqual([]);
    expect(merged.roleBindings.admin.staging).toEqual(DEFAULT_RULES.roleBindings.admin.staging);
  });
});
