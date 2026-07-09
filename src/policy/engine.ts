import type {
  CommandClass,
  PolicyDecision,
  PolicyEvaluation,
  Profile,
  ApprovalMode,
} from '../types.js';
import { classifyCommand } from './classifier.js';

export interface PolicyRules {
  roleBindings: Record<string, Record<string, CommandClass[]>>;
  denylist?: string[];
  allowlist?: string[];
}

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

  constructor(private rules: PolicyRules = DEFAULT_RULES) {}

  setOpaUrl(url: string | null): void {
    this.opaUrl = url;
  }

  evaluate(
    command: string,
    profile: Profile,
    toolName: string,
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

      if (!resp.ok) return local;

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
    } catch {
      // OPA unreachable — fall back to local evaluation
    }

    return local;
  }

  private getAllowedClasses(profile: Profile): CommandClass[] {
    if (profile.readOnly) {
      return ['read-only'];
    }
    const roleBinding = this.rules.roleBindings[profile.role];
    if (!roleBinding) {
      return ['read-only'];
    }
    const hostGroup = this.inferHostGroup(profile);
    return roleBinding[hostGroup] || roleBinding['dev'] || ['read-only'];
  }

  private inferHostGroup(profile: Profile): string {
    const name = profile.name.toLowerCase();
    if (name.includes('prod')) return 'prod';
    if (name.includes('staging')) return 'staging';
    return 'dev';
  }

  private requiresApproval(profile: Profile, needsApproval: boolean): boolean {
    const mode: ApprovalMode = profile.approvalPolicy;
    if (mode === 'auto') return false;
    if (mode === 'ask-all') return true;
    if (mode === 'deny') return needsApproval;
    return needsApproval;
  }

  private matchesDenylist(command: string): boolean {
    if (!this.rules.denylist) return false;
    return this.rules.denylist.some((pattern) => {
      try {
        return new RegExp(pattern).test(command);
      } catch {
        return command.includes(pattern);
      }
    });
  }
}
