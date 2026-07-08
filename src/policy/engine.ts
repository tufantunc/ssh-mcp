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

const CLASS_RANK: Record<CommandClass, number> = {
  'read-only': 0,
  safe: 1,
  destructive: 2,
  privileged: 3,
};

export class PolicyEngine {
  constructor(private rules: PolicyRules = DEFAULT_RULES) {}

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
    if (!needsApproval) return false;
    const mode: ApprovalMode = profile.approvalPolicy;
    if (mode === 'auto') return false;
    if (mode === 'deny') return true;
    if (mode === 'ask-all') return true;
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
