import type {
  CommandClass,
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
const HOST_GROUPS = ['prod', 'staging', 'dev'] as const;

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
        reason: `Role "${profile.role}" cannot run "${parsed.class}" commands`,
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

  private getAllowedClasses(profile: Profile): CommandClass[] {
    if (profile.readOnly) {
      return ['read-only'];
    }
    const roleBinding = this.rules.roleBindings[profile.role];
    if (!roleBinding) {
      return ['read-only'];
    }
    const hostGroup = this.resolveHostGroup(profile);
    // Falls back to the most restrictive tier, never to the loosest one.
    return roleBinding[hostGroup] || roleBinding[HOST_GROUPS[0]] || ['read-only'];
  }

  /**
   * Which tier's role binding applies to this profile.
   *
   * `profile.group` is authoritative. Without it we still infer from the name
   * for convenience, but an unrecognised name resolves to the most restrictive
   * tier: the previous default sent every unrecognised profile to `dev`, so a
   * production host merely named "web-01" silently received the loosest
   * permissions in the matrix.
   */
  private resolveHostGroup(profile: Profile): string {
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
