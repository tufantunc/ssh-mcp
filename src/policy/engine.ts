import type {
  CommandClass,
  PolicyConfig,
  PolicyEvaluation,
  Profile,
  ApprovalMode,
} from '../types.js';
import { classifyCommand, FORBIDDEN_PATTERNS } from './classifier.js';

export interface PolicyRules {
  roleBindings: Record<string, Record<string, CommandClass[]>>;
  /**
   * Extra deny patterns supplied by the operator, as regex source strings.
   * The canonical never-allowed list (FORBIDDEN_PATTERNS) lives in
   * classifier.ts and is always applied on top of these — not repeated here.
   */
  denylist?: string[];
  allowlist?: string[];
}

/** Tiers, most restrictive first. Unknown/unset tiers resolve to the first. */
export const HOST_GROUPS = ['prod', 'staging', 'dev'] as const;

export const DEFAULT_RULES: PolicyRules = {
  roleBindings: {
    viewer: {
      prod: ['read-only'],
      staging: ['read-only'],
      dev: ['read-only', 'safe'],
    },
    operator: {
      prod: ['read-only', 'safe'],
      staging: ['read-only', 'safe', 'destructive'],
      dev: ['read-only', 'safe', 'destructive'],
    },
    admin: {
      prod: ['read-only', 'safe', 'destructive'],
      staging: ['read-only', 'safe', 'destructive', 'privileged'],
      dev: ['read-only', 'safe', 'destructive', 'privileged'],
    },
  },
};

/**
 * Layer an operator's `[policy]` section over the compiled-in defaults.
 *
 * The merge is at role → group depth, not role depth. Replacing a whole role's
 * bindings from a partial table is the trap here: a config naming only
 * `admin.prod` would otherwise wipe `admin.staging` and `admin.dev` back to
 * nothing, widening or narrowing two tiers the operator never mentioned.
 *
 * Roles and groups absent from the override keep their defaults, and a role or
 * tier the defaults have never heard of is added rather than rejected. That is
 * what makes a custom `group = "tier-1"` resolve to real bindings.
 *
 * `denylist` replaces rather than appends, because the defaults carry none and
 * FORBIDDEN_PATTERNS is applied on top by the engine regardless.
 */
export function mergePolicyRules(
  base: PolicyRules,
  override?: PolicyConfig,
): PolicyRules {
  if (!override?.roleBindings && !override?.denylist) return base;

  // Copy every tier map: assigning base's objects straight through would let a
  // later merge mutate DEFAULT_RULES, which is a module-level singleton.
  const roleBindings: Record<string, Record<string, CommandClass[]>> = {};
  for (const [role, groups] of Object.entries(base.roleBindings)) {
    roleBindings[role] = { ...groups };
  }
  for (const [role, groups] of Object.entries(override.roleBindings ?? {})) {
    roleBindings[role] = { ...(roleBindings[role] ?? {}), ...groups };
  }

  return {
    roleBindings,
    denylist: override.denylist ?? base.denylist,
    allowlist: base.allowlist,
  };
}

/**
 * Which tier's role binding applies to this profile.
 *
 * `profile.group` is authoritative. Without it we still infer from the name
 * for convenience, but an unrecognised name resolves to the most restrictive
 * tier: the previous default sent every unrecognised profile to `dev`, so a
 * production host merely named "web-01" silently received the loosest
 * permissions in the matrix.
 *
 * Exported rather than kept private because startup validation has to reach the
 * same answer the engine will reach, inference included. Checking only the
 * explicit `group` would pass every profile that never set one, which is where
 * the widening below actually happens.
 */
export function resolveProfileGroup(profile: Profile): string {
  if (profile.group) return profile.group;

  const name = profile.name.toLowerCase();
  if (name.includes('prod')) return 'prod';
  if (name.includes('staging')) return 'staging';
  if (/\b(dev|local|test|sandbox)\b/.test(name) || /(^|[-_])(dev|local|test|sandbox)([-_]|$)/.test(name)) {
    return 'dev';
  }
  return HOST_GROUPS[0];
}

/**
 * Every way a config's policy can mean something other than what it says.
 *
 * Checked in both directions, because a silent no-op is reachable from either:
 * a profile can name a role or tier that nothing defines, and a `[policy]`
 * block can define a role or tier that no profile can reach. #95 was the second
 * kind (written, parsed, dropped), and the first kind lands on `['read-only']`,
 * which at runtime is indistinguishable from a deliberate policy decision.
 *
 * The `[policy]` side is checked against `override`, never the merged table:
 * the merge carries the three compiled-in roles, and no real config references
 * all of them.
 *
 * Returns every problem rather than the first, matching the config validation
 * error in loader.ts. An operator fixing a config file wants the whole list.
 */
export function findPolicyProblems(
  merged: PolicyRules,
  profiles: Profile[],
  override?: PolicyConfig,
): string[] {
  const problems: string[] = [];

  for (const profile of profiles) {
    const roleBinding = merged.roleBindings[profile.role];
    if (!roleBinding) {
      problems.push(
        `profile "${profile.name}": role "${profile.role}" has no role bindings, so it can only ever ` +
        `run read-only commands. Define [policy.roleBindings.${profile.role}], or set role to one of: ` +
        `${Object.keys(merged.roleBindings).join(', ')}.`,
      );
      continue;
    }

    const group = resolveProfileGroup(profile);
    if (roleBinding[group]) continue;

    const tiers = Object.keys(roleBinding).join(', ');
    problems.push(
      profile.group
        ? `profile "${profile.name}": role "${profile.role}" has no bindings for group "${group}". ` +
          `Add a "${group}" key under [policy.roleBindings.${profile.role}], or set group to one of: ${tiers}.`
        : `profile "${profile.name}": no group is set, so the tier is inferred from the name as "${group}", ` +
          `and role "${profile.role}" has no bindings for it. Set group explicitly to one of: ${tiers}, ` +
          `or add a "${group}" key under [policy.roleBindings.${profile.role}].`,
    );
  }

  const rolesInUse = [...new Set(profiles.map((p) => p.role))];
  for (const [role, tiers] of Object.entries(override?.roleBindings ?? {})) {
    if (!rolesInUse.includes(role)) {
      problems.push(
        `[policy.roleBindings.${role}]: no profile uses role "${role}", so this block changes nothing. ` +
        `Roles in use: ${rolesInUse.join(', ')}.`,
      );
    }
    for (const tier of Object.keys(tiers)) {
      if ((HOST_GROUPS as readonly string[]).includes(tier)) continue;
      if (profiles.some((p) => p.group === tier)) continue;
      problems.push(
        `[policy.roleBindings.${role}]: key "${tier}" matches no profile's group and is not a built-in ` +
        `tier (${HOST_GROUPS.join(', ')}), so it changes nothing. Set group = "${tier}" on a profile, ` +
        `or remove the key.`,
      );
    }
  }

  return problems;
}

/**
 * The rules main() runs on: the compiled-in defaults, the operator's overrides
 * layered on top, and a refusal to start when the two do not describe the same
 * world.
 *
 * Refusing rather than warning. A warning here goes to stderr, which for a
 * stdio MCP server means a log file the operator is not reading, and "written,
 * ignored, nothing said" is the whole of #95.
 */
export function resolvePolicyRules(
  profiles: Profile[],
  override?: PolicyConfig,
): PolicyRules {
  const merged = mergePolicyRules(DEFAULT_RULES, override);
  const problems = findPolicyProblems(merged, profiles, override);
  if (problems.length > 0) {
    throw new Error(
      'Policy configuration error:\n' +
      problems.map((p) => `  ${p}`).join('\n') +
      '\nSee the "Configuring the matrix" section of the README.',
    );
  }
  return merged;
}

export class PolicyEngine {
  private opaUrl: string | null = null;
  /** Rate-limits the fail-open warning so one outage can't flood stderr. */
  private lastOpaWarning = 0;
  /** Canonical patterns plus the operator's, compiled once at construction. */
  private readonly denyPatterns: RegExp[];

  constructor(private rules: PolicyRules = DEFAULT_RULES) {
    // Compile eagerly: a deny rule that silently degrades (the old code fell
    // back to substring-matching the command against the regex *source*) is
    // worse than a startup failure, because nothing surfaces the degradation.
    const userPatterns = (rules.denylist ?? []).map((pattern) => {
      try {
        return new RegExp(pattern);
      } catch (err) {
        throw new Error(
          `Invalid denylist pattern ${JSON.stringify(pattern)}: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    });
    this.denyPatterns = [...FORBIDDEN_PATTERNS, ...userPatterns];
  }

  setOpaUrl(url: string | null): void {
    this.opaUrl = url;
  }

  evaluate(
    command: string,
    profile: Profile,
    _toolName: string,
  ): PolicyEvaluation {
    const parsed = classifyCommand(command);
    const allowedClasses = this.getAllowedClasses(profile);
    const classAllowed = allowedClasses.includes(parsed.class);

    if (this.matchesDenylist(command)) {
      return {
        decision: 'deny',
        commandClass: parsed.class,
        binary: parsed.binary,
        ruleId: 'denylist',
        reason: 'Command matches denylist pattern',
      };
    }

    const needsApproval =
      parsed.class === 'destructive' || parsed.class === 'privileged';

    const approvalRequired = this.requiresApproval(profile, needsApproval);

    if (!classAllowed) {
      return {
        decision: 'deny',
        commandClass: parsed.class,
        binary: parsed.binary,
        ruleId: 'role-binding',
        reason: this.explainRoleDenial(profile, parsed.class),
      };
    }

    if (approvalRequired) {
      // approvalPolicy "deny" rejects outright instead of prompting — otherwise
      // it would behave exactly like ask-destructive and never deny anything.
      if (profile.approvalPolicy === 'deny') {
        return {
          decision: 'deny',
          commandClass: parsed.class,
          binary: parsed.binary,
          ruleId: 'approval-policy',
          reason: `Profile "${profile.name}" denies ${parsed.class} commands (approvalPolicy = "deny")`,
        };
      }
      return {
        decision: 'require-approval',
        commandClass: parsed.class,
        binary: parsed.binary,
        ruleId: 'approval-policy',
        reason: `Profile "${profile.name}" requires approval for ${parsed.class} commands`,
      };
    }

    return {
      decision: 'allow',
      commandClass: parsed.class,
      binary: parsed.binary,
      ruleId: 'default',
    };
  }

  async evaluateWithOpa(
    command: string,
    profile: Profile,
    toolName: string,
  ): Promise<PolicyEvaluation> {
    const local = this.evaluate(command, profile, toolName);

    if (local.decision === 'deny') {
      return local;
    }

    if (!this.opaUrl) {
      return local;
    }

    try {
      const parsed = classifyCommand(command);
      const input = {
        subject: { role: profile.role, profile: profile.name },
        action: { tool: toolName, commandClass: parsed.class },
        resource: { command: parsed.fullCommand, binary: parsed.binary, host: profile.host },
        context: { readOnly: profile.readOnly },
      };

      const resp = await fetch(`${this.opaUrl}/v1/data/ssh/mcp/allow`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input }),
      });

      if (!resp.ok) {
        this.warnOpaUnavailable(`HTTP ${resp.status} from ${this.opaUrl}`);
        return local;
      }

      const data = await resp.json() as { result?: boolean };
      if (data.result === false) {
        return {
          decision: 'deny',
          commandClass: parsed.class,
          binary: parsed.binary,
          ruleId: 'opa',
          reason: 'Denied by OPA policy',
        };
      }
    } catch (err) {
      this.warnOpaUnavailable(err instanceof Error ? err.message : String(err));
    }

    return local;
  }

  /**
   * OPA is an *additional* deny layer, so an outage falls back to the local
   * decision rather than blocking all work. That is a deliberate trade-off, but
   * it must be loud: an operator who deployed OPA as a hard authorization gate
   * would otherwise have no signal that the gate is down while commands it
   * would have denied keep running.
   */
  private warnOpaUnavailable(cause: string): void {
    const now = Date.now();
    if (now - this.lastOpaWarning < 60_000) return;
    this.lastOpaWarning = now;
    console.error(
      `POLICY WARNING: OPA evaluation unavailable (${cause}). ` +
      'Falling back to local policy — commands OPA would deny may now be allowed.',
    );
  }

  /**
   * Say which three things produced the refusal, not one of them.
   *
   * The message used to read `Role "admin" cannot run "privileged" commands`,
   * which names the role and the class but not the host group — and the group
   * is usually what decided, because `admin` has `privileged` on staging and
   * dev but not on prod. A reader concludes their role is simply incapable of
   * sudo and goes looking for a bigger role that does not exist (#91).
   *
   * The inferred case matters most: a profile with no group set lands on the
   * strictest tier, so the reason is something the operator never wrote down
   * anywhere and cannot see.
   */
  private explainRoleDenial(profile: Profile, commandClass: CommandClass): string {
    if (profile.readOnly) {
      return `Profile "${profile.name}" is read-only, so "${commandClass}" commands are refused. ` +
        `Clear readOnly on the profile to allow them.`;
    }

    const group = resolveProfileGroup(profile);
    const inferred = !profile.group;
    const allowed = this.getAllowedClasses(profile).join(', ');

    let reason =
      `Role "${profile.role}" on host group "${group}" cannot run "${commandClass}" commands ` +
      `(allowed: ${allowed}).`;

    if (inferred) {
      reason +=
        ` No group is set for profile "${profile.name}", so it defaulted to the most restrictive tier.` +
        ` Set group = "dev" or "staging" on the profile, or pass --group, if this host is not production.`;
    } else {
      reason += ` Change the profile's group, or grant the class to this role in the policy's roleBindings.`;
    }

    return reason;
  }

  private getAllowedClasses(profile: Profile): CommandClass[] {
    if (profile.readOnly) {
      return ['read-only'];
    }
    const roleBinding = this.rules.roleBindings[profile.role];
    if (!roleBinding) {
      return ['read-only'];
    }
    // No hop to another tier when this one has no bindings. While roleBindings
    // were compiled in, falling back to HOST_GROUPS[0] meant falling back to
    // that role's *strictest* cell, so the old comment here was true. Once a
    // [policy] block can write the prod cell, the same hop hands an unresolved
    // tier whatever prod was granted. That is a widening, and a silent one.
    //
    // An unresolved tier is a startup error now (resolvePolicyRules), so
    // reaching this line means the engine was constructed directly rather than
    // from a config file. Fail closed.
    //
    // `??` rather than `||`: an empty class list is a deliberate lockdown, and
    // whether it survives should not rest on `[]` being truthy.
    return roleBinding[resolveProfileGroup(profile)] ?? ['read-only'];
  }

  /**
   * Whether this command trips the profile's approval gate. What happens at the
   * gate — prompt or deny — is decided by evaluate() from the approvalPolicy.
   */
  private requiresApproval(profile: Profile, needsApproval: boolean): boolean {
    const mode: ApprovalMode = profile.approvalPolicy;
    if (mode === 'auto') return false;
    if (mode === 'ask-all') return true;
    // ask-destructive and deny both gate on destructive/privileged commands.
    return needsApproval;
  }

  private matchesDenylist(command: string): boolean {
    return this.denyPatterns.some((pattern) => pattern.test(command));
  }
}
