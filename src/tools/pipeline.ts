import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { tracer } from '../observability/tracer.js';
import type { ConnectionRegistry } from '../ssh/connection-registry.js';
import type { PolicyEngine } from '../policy/engine.js';
import type { AuditStore } from '../audit/store.js';
import { sanitizeCommand } from '../guard/sanitizer.js';
import { requestApproval } from '../guard/elicitation.js';
import { commandOutput, type ToolResult } from './results.js';
import { CommandQuota } from '../policy/quota.js';
import type { CommandResult, ToolContext, PolicyEvaluation, CommandClass } from '../types.js';

/**
 * What we know about a request while it is being processed, so a failure can be
 * audited truthfully.
 *
 * The catch block of a tool handler is reached by two very different events: a
 * policy denial, and a failure *after* the command was allowed, approved and
 * executed. Recording both as `decision: 'deny'` told an auditor that commands
 * which actually ran on the host had been blocked.
 */
export interface AuditState {
  /** Best-known command string: raw until sanitized, wrapped once wrapped. */
  command: string;
  /** Set once the policy engine actually produced a decision. */
  evaluation?: PolicyEvaluation;
}

/** Policy never ran — the input was rejected at the boundary. */
function rejectedEvaluation(commandClass: CommandClass): PolicyEvaluation {
  return { decision: 'deny', commandClass, binary: '', ruleId: 'input-rejected' };
}

/**
 * Carries the policy decision that caused a refusal, so the audit record shows
 * the real rule and class instead of a synthetic placeholder.
 */
export class PolicyRefusedError extends Error {
  constructor(message: string, readonly evaluation: PolicyEvaluation) {
    super(message);
    this.name = 'PolicyRefusedError';
  }
}

export interface ToolDeps {
  server: McpServer;
  registry: ConnectionRegistry;
  policy: PolicyEngine;
  audit: AuditStore;
}

/**
 * Builds the audited execution pipeline every tool handler runs through.
 *
 * A factory rather than free functions because the pipeline closes over the
 * server (approval prompts), registry (connections and profiles), policy engine
 * and audit store. Tool groups receive the result and never touch those four
 * directly, so there is exactly one path from caller input to a remote command.
 */
export function createPipeline({ server, registry, policy, audit }: ToolDeps) {
  const quota = new CommandQuota();
  async function resolveConn(profileName?: string) {
    return registry.getOrCreate(profileName);
  }

  async function checkPolicyAndApprove(
    command: string,
    profileName: string,
    toolName: string,
  ) {
    const span = tracer.startSpan('policy.evaluate');
    span.setAttribute('tool.name', toolName);
    span.setAttribute('ssh.profile', profileName);
    try {
      const conn = await resolveConn(profileName);
      const evaluation = await policy.evaluateWithOpa(command, conn.profile, toolName);
      span.setAttribute('policy.decision', evaluation.decision);
      span.setAttribute('command.class', evaluation.commandClass);
      span.setAttribute('command.binary', evaluation.binary);

      if (evaluation.decision === 'deny') {
        throw new PolicyRefusedError(
          `POLICY_DENIED: ${evaluation.reason || 'Command not allowed'}`,
          evaluation,
        );
      }

      if (evaluation.decision === 'require-approval') {
        const approval = await requestApproval(server, command, conn.profile.name, evaluation);
        if (!approval.approved) {
          throw new PolicyRefusedError('APPROVAL_DENIED: User did not approve this command', evaluation);
        }
        return { conn, evaluation, approver: approval.approver };
      }

      return { conn, evaluation, approver: undefined };
    } finally {
      span.end();
    }
  }

  async function auditResult(
    ctx: ToolContext,
    profileName: string,
    command: string,
    evaluation: PolicyEvaluation,
    result: CommandResult | { error: string },
    approver?: string,
  ) {
    await audit.record({
      mcpRequestId: ctx.requestId,
      profile: profileName,
      user: registry.getProfile(profileName).user,
      command,
      commandClass: evaluation.commandClass,
      binary: evaluation.binary,
      decision: evaluation.decision,
      ruleId: evaluation.ruleId,
      exitCode: 'exitCode' in result ? result.exitCode : undefined,
      durationMs: 'durationMs' in result ? result.durationMs : undefined,
      error: 'error' in result ? result.error : undefined,
      approver,
    });
  }

  function makeCtx(extra: any, profile?: string, session?: string): ToolContext {
    return { requestId: extra?.requestId ?? 0, profile, session };
  }

  /**
   * Audit a failed tool call with the real policy decision when there was one.
   *
   * Never throws: an audit write error must not replace the error the caller
   * actually needs to see (and on the success path, must not make an agent
   * think a non-idempotent command failed after it already ran).
   */
  async function auditFailure(
    ctx: ToolContext,
    profileName: string,
    state: AuditState,
    failureClass: CommandClass,
    err: any,
  ): Promise<void> {
    const evaluation = (err instanceof PolicyRefusedError ? err.evaluation : undefined)
      ?? state.evaluation
      ?? rejectedEvaluation(failureClass);
    try {
      await auditResult(ctx, profileName, state.command, evaluation, {
        error: err?.message ?? String(err),
      });
    } catch (auditErr) {
      console.error('Audit write failed while recording a tool failure:', auditErr);
    }
  }

  function defaultProfileName(profile?: string): string {
    return profile || registry.getProfile().name;
  }

  function makeProgressSender(extra: any): ((bytes: number, tail: string) => void) | undefined {
    const token = extra?._meta?.progressToken;
    if (token === undefined) return undefined;
    return (bytes, tail) => {
      extra.sendNotification({
        method: 'notifications/progress',
        params: { progressToken: token, progress: bytes, message: tail },
      }).catch(() => {});
    };
  }

  interface RunContext {
    conn: Awaited<ReturnType<typeof resolveConn>>;
    /** Sanitized (and wrapped, where applicable) command actually being run. */
    command: string;
    profileName: string;
    onProgress?: (bytes: number, tail: string) => void;
    abortSignal?: AbortSignal;
    extra: any;
  }

  interface AuditedOpts {
    toolName: string;
    /** Class recorded when a failure happens before policy produced a decision. */
    failureClass: CommandClass;
    profile?: string;
    session?: string;
    extra: any;
    /** Reject anything the policy engine did not classify as this. */
    enforceClass?: CommandClass;
    /**
     * Synthetic commands (`sftp:upload …`, `kill -TERM …`, `session:open …`)
     * are built by us, not the caller, so they skip caller-input sanitization.
     */
    synthetic?: boolean;
    /** Extra check on the sanitized command before policy evaluation. */
    preCheck?: (cleanCmd: string) => void;
    /** Rewrite what policy evaluates and what runs (the sudo wrapper). */
    wrap?: (cleanCmd: string) => string;
  }

  /**
   * The one place the sanitize → policy → approve → run → audit pipeline lives.
   *
   * Five of the six audited handlers used to inline their own copy of this, and
   * they had already drifted apart: one dropped abort/progress support, one
   * audited a different command string on success than on failure, one carried
   * a dead `?? command` fallback. Every audit-semantics fix had to be made six
   * times, so they were never all correct at once.
   */
  async function runAudited(
    command: string,
    opts: AuditedOpts,
    run: (rt: RunContext) => Promise<{ audited: CommandResult; output: ToolResult }>,
  ): Promise<ToolResult> {
    const ctx = makeCtx(opts.extra, opts.profile, opts.session);
    const profileName = defaultProfileName(opts.profile);
    const profile = registry.getProfile(profileName);
    const onProgress = makeProgressSender(opts.extra);
    const abortSignal = opts.extra?.signal;

    // Sanitization runs inside the try so a rejected (empty, control-char-only,
    // over-length) command still leaves an audit trail — a client probing with
    // malformed payloads used to leave none.
    const state: AuditState = { command };
    try {
      let effective = opts.synthetic ? command : sanitizeCommand(command, profile.maxChars);
      state.command = effective;

      opts.preCheck?.(effective);

      if (opts.wrap) {
        effective = opts.wrap(effective);
        state.command = effective;
      }

      const { conn, evaluation, approver } = await checkPolicyAndApprove(effective, profileName, opts.toolName);
      state.evaluation = evaluation;

      if (opts.enforceClass && evaluation.commandClass !== opts.enforceClass) {
        throw new Error(`${opts.toolName} only accepts ${opts.enforceClass} commands, got: ${evaluation.commandClass}`);
      }

      // Counted after the policy allowed it and before it runs: a denied
      // command should not burn quota, and an allowed one should be counted
      // even if it later fails on the host — the work was still spent.
      const budget = quota.consume(profileName, profile.commandQuotaPerDay);
      if (!budget.allowed) {
        throw new PolicyRefusedError(
          `QUOTA_EXCEEDED: profile "${profileName}" has used its ${profile.commandQuotaPerDay} commands ` +
          `for the last 24h. Next slot frees at ${budget.retryAt?.toISOString()}.`,
          { ...evaluation, decision: 'deny', ruleId: 'command-quota' },
        );
      }

      const { audited, output } = await run({
        conn, command: effective, profileName, onProgress, abortSignal, extra: opts.extra,
      });

      await auditResult(ctx, profileName, effective, evaluation, audited, approver);
      return output;
    } catch (err: any) {
      await auditFailure(ctx, profileName, state, opts.failureClass, err);
      throw err;
    }
  }

  /** Run a command over the connection and report it verbatim to the client. */
  function execAndReport(opts: { stdin?: string } = {}) {
    return async (rt: RunContext) => {
      const audited = await rt.conn.exec(rt.command, {
        stdin: opts.stdin,
        onProgress: rt.onProgress,
        abortSignal: rt.abortSignal,
      });
      return { audited, output: commandOutput(audited) };
    };
  }

  return { runAudited, execAndReport, defaultProfileName, makeCtx, auditResult, auditFailure, resolveConn, quota };
}

export type Pipeline = ReturnType<typeof createPipeline>;
