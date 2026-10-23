import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { tracer } from '../observability/tracer.js';
import type { ConnectionRegistry } from '../ssh/connection-registry.js';
import type { PolicyEngine, PolicyResource } from '../policy/engine.js';
import type { AuditStore } from '../audit/store.js';
import { sanitizeCommand } from '../guard/sanitizer.js';
import { requestApproval } from '../guard/elicitation.js';
import { commandOutput, type ToolResult } from './results.js';
import { CommandQuota } from '../policy/quota.js';
import { formatReadOnlyRejection } from '../policy/classifier.js';
import type { LocalPathContext } from './local-path.js';
import type { ConfigReloader } from '../config/reload.js';
import { ApprovalGrants } from '../guard/approval-grants.js';
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
  /**
   * Where the streaming SFTP file tools may touch local disk, and which
   * directories they must stay clear of.
   *
   * Optional so the tool layer can be built without it — an unconfigured server
   * still has to answer `tools/list`. Absent, those tools register and refuse,
   * which is the same answer a configured server with no `transferRoot` gives.
   */
  localPath?: LocalPathContext;
  /**
   * The one reloader the server shares across every MCP server it builds. main() always
   * passes it, an unconfigured start included; it is optional only for test harnesses
   * that build the tool layer without one. Absent, `reload-config` still registers and
   * refuses.
   */
  reloader?: ConfigReloader;
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
  // Both read live: a reload changes the TTL, and moves the generation that retires
  // every grant given under the rules before it.
  const grants = new ApprovalGrants(
    () => registry.currentDefaults().approvalGrantTtlMs,
    () => registry.generation,
  );
  async function resolveConn(profileName?: string) {
    return registry.getOrCreate(profileName);
  }

  async function checkPolicyAndApprove(
    command: string,
    profileName: string,
    toolName: string,
    resource: PolicyResource = {},
  ) {
    const span = tracer.startSpan('policy.evaluate');
    span.setAttribute('tool.name', toolName);
    span.setAttribute('ssh.profile', profileName);
    try {
      // Captured before resolving the connection: a reload from here on means the
      // decision below may have been made under rules that are no longer the live ones,
      // or against a connection the reload has since closed.
      const genAtEval = registry.generation;
      const conn = await resolveConn(profileName);
      const evaluation = await policy.evaluateWithOpa(command, conn.profile, toolName, resource);
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
        // A live grant from an earlier explicit approval of this exact command.
        if (grants.has(conn.profile.name, command, evaluation.commandClass)) {
          span.setAttribute('policy.grant', 'reused');
          if (registry.generation !== genAtEval) {
            // The grant is current, but the evaluation that led here is not.
            const recheck = await recheckAfterReload(conn, command, toolName, resource, evaluation, 'decision');
            return { conn, evaluation: recheck.evaluation, approver: undefined };
          }
          return { conn, evaluation, approver: 'jit-grant' };
        }

        const approval = await requestApproval(server, command, conn.profile.name, evaluation);
        if (!approval.approved) {
          // Two different failures used to share one message. "User did not
          // approve" is true when the user declined and a lie when the client
          // could not be asked, and the reader cannot tell which they got (#91).
          throw new PolicyRefusedError(
            approval.unavailable
              ? `APPROVAL_UNAVAILABLE: ${approval.unavailable}`
              : 'APPROVAL_DENIED: User did not approve this command',
            evaluation,
          );
        }
        // Each grant is tagged with the generation its decision was checked under, not
        // the one current when it is written: a reload landing in between then leaves a
        // grant that never counts.
        if (registry.generation !== genAtEval) {
          const recheck = await recheckAfterReload(conn, command, toolName, resource, evaluation, 'approval');
          grants.record(conn.profile.name, command, evaluation.commandClass, { generation: recheck.generation });
          return { conn, evaluation: recheck.evaluation, approver: approval.approver };
        }
        grants.record(conn.profile.name, command, evaluation.commandClass, { generation: genAtEval });
        return { conn, evaluation, approver: approval.approver };
      }

      if (registry.generation !== genAtEval) {
        const recheck = await recheckAfterReload(conn, command, toolName, resource, evaluation, 'decision');
        return { conn, evaluation: recheck.evaluation, approver: undefined };
      }
      return { conn, evaluation, approver: undefined };
    } finally {
      span.end();
    }
  }

  /**
   * The config was reloaded after the decision in hand was made: while the connection was
   * resolved or the policy evaluated (`'decision'`), or while a human was deciding
   * (`'approval'`). The decision was made under the old rules, so it stands only if the
   * command still runs on the same connection, and the new evaluation, against the
   * profile as swapped in and the rules as replaced, would lead to the same thing:
   *
   * - after an approval, `allow`, or `require-approval` again, for the class the human
   *   approved: the new rules would still have put this same decision to them;
   * - after an `allow` or a reused grant, `allow` for the same class. A decision nobody
   *   was asked about is not carried over to rules that would now ask, or refuse.
   *
   * Anything else refuses with `config-reloaded` rather than prompting again: a second
   * prompt for a call already in flight is a surprise, and a retry asks under the new
   * rules from the start. Returns the new evaluation, which is what the audit records,
   * and the generation it was checked under, which is what a grant is tagged with.
   */
  async function recheckAfterReload(
    conn: Awaited<ReturnType<typeof resolveConn>>,
    command: string,
    toolName: string,
    resource: PolicyResource,
    decided: PolicyEvaluation,
    after: 'approval' | 'decision',
  ): Promise<{ evaluation: PolicyEvaluation; generation: number }> {
    const refuse = (): never => {
      throw new PolicyRefusedError(
        after === 'approval'
          ? 'CONFIG_RELOADED: The configuration was reloaded while this command awaited approval, ' +
            'and the approval does not carry over to the new rules; retry the call.'
          : 'CONFIG_RELOADED: The configuration was reloaded while this command was being checked, ' +
            'and the decision does not carry over to the new rules; retry the call.',
        {
          ...decided,
          decision: 'deny',
          ruleId: 'config-reloaded',
          // Fixed: the decided evaluation's reason may quote the old config.
          reason: after === 'approval'
            ? 'The configuration was reloaded while waiting for approval; the command was not run.'
            : 'The configuration was reloaded while the command was being checked; the command was not run.',
        },
      );
    };

    // Still stored means applyConfig swapped its profile in place; gone means the reload
    // closed it (profile removed, connection fields changed, bastion closing), and any
    // connection a retry reaches is not the one the decision was made for.
    if (!registry.liveConnections().includes(conn)) refuse();

    const genAtRecheck = registry.generation;
    const current = await policy.evaluateWithOpa(command, conn.profile, toolName, resource);
    // Another reload during the re-evaluation: this one is stale too.
    if (registry.generation !== genAtRecheck) refuse();
    const accepted = after === 'approval'
      ? current.decision === 'allow' || current.decision === 'require-approval'
      : current.decision === 'allow';
    if (!accepted) refuse();
    if (current.commandClass !== decided.commandClass) refuse();
    return { evaluation: current, generation: genAtRecheck };
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
      // Looked up without throwing. This used to be `registry.getProfile(profileName).user`,
      // which throws for exactly the reason the tool call is being audited as a failure —
      // an unconfigured server, or a profile name that does not exist — and `auditFailure`
      // swallows that by design. The record the operator most needs was the one record that
      // could not be written.
      user: profileUser(profileName),
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

  /** The profile's SSH user, or a placeholder — never throws, so an audit write cannot fail. */
  function profileUser(profileName: string): string {
    return registry.listAllProfiles().find((p) => p.name === profileName)?.user ?? '(unresolved)';
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
    /**
     * Append detail that only exists once the operation has started, so the
     * audit record describes what actually happened.
     *
     * The streaming SFTP tools are why this exists (#207). Their local path can
     * only be resolved by touching the filesystem — creating a staged `.part`,
     * and answering "does this exist?" through the error it returns — and doing
     * that before the policy decision hands those effects to a caller who is
     * about to be denied. So the resolved local path is not available when
     * policy runs, and the audit record still has to name it.
     *
     * Append-only, and enforced rather than documented: the refined string must
     * start with the exact string policy evaluated and the approver saw. That
     * keeps this from being a way to audit a different operation than the one
     * that was authorized — the subject can be elaborated, never replaced.
     */
    refineCommand: (command: string) => void;
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
    /**
     * What the call acts on beyond its command string — its remote path, for the SFTP
     * tools. Forwarded whole to the policy engine, so `[policy].denylist` is tested
     * against it as well as against the command string, which for these tools is one we
     * compose, and OPA's `resource` gains it (#230).
     */
    resource?: PolicyResource;
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
    const onProgress = makeProgressSender(opts.extra);
    const abortSignal = opts.extra?.signal;

    // Named before the try because `auditFailure` needs something to file the record
    // under even when resolution itself is what failed. Reassigned to the resolved name as
    // the first statement inside, so the quota key and the audit record are unchanged on
    // every path that gets that far.
    let profileName = opts.profile ?? '(default)';

    // Profile resolution and sanitization both run inside the try, so a rejected call
    // still leaves an audit trail — a client probing with malformed payloads, or probing
    // a server that has no config at all, used to leave none. The unconfigured refusal
    // reaches this the same way a bad command does.
    const state: AuditState = { command };
    try {
      profileName = defaultProfileName(opts.profile);
      const profile = registry.getProfile(profileName);
      let effective = opts.synthetic ? command : sanitizeCommand(command, profile.maxChars);
      state.command = effective;

      opts.preCheck?.(effective);

      if (opts.wrap) {
        effective = opts.wrap(effective);
        state.command = effective;
      }

      const { conn, evaluation, approver } = await checkPolicyAndApprove(
        effective, profileName, opts.toolName, opts.resource,
      );
      state.evaluation = evaluation;

      if (opts.enforceClass && evaluation.commandClass !== opts.enforceClass) {
        // A command that fell to `safe` because a reader was refused read-only —
        // its grammar rejected an argv word, or the command carries a shell
        // metacharacter — is one spelling away from the class this tool demands.
        // Say which word or character, or the caller only learns that the tool
        // refused it, not why the reader that ran the exact same binary would
        // not have.
        const rejectionSuffix = evaluation.readOnlyRejection
          ? ` ${formatReadOnlyRejection(evaluation.readOnlyRejection)}`
          : '';
        throw new Error(
          `${opts.toolName} only accepts ${opts.enforceClass} commands, got: ${evaluation.commandClass}${rejectionSuffix}`,
        );
      }

      // Counted after the policy allowed it and before it runs: a denied
      // command should not burn quota, and an allowed one should be counted
      // even if it later fails on the host — the work was still spent. The limit is
      // read from the connection's live profile, not the one captured above: a reload
      // during the policy or approval await swaps it in place.
      const limit = conn.profile.commandQuotaPerDay;
      const budget = quota.consume(profileName, limit);
      if (!budget.allowed) {
        throw new PolicyRefusedError(
          `QUOTA_EXCEEDED: profile "${profileName}" has used its ${limit} commands ` +
          `for the last 24h. Next slot frees at ${budget.retryAt?.toISOString()}.`,
          { ...evaluation, decision: 'deny', ruleId: 'command-quota' },
        );
      }

      const approved = effective;
      const refineCommand = (refined: string) => {
        if (!refined.startsWith(approved)) {
          throw new Error('Internal: an audited command may only be elaborated, not replaced');
        }
        state.command = refined;
      };

      const { audited, output } = await run({
        conn, command: effective, profileName, onProgress, abortSignal, extra: opts.extra,
        refineCommand,
      });

      // `state.command`, not `effective`: identical unless the handler refined
      // it, and the refinement is exactly what the success record should carry.
      // The failure path below already reads `state`, so the two agree.
      await auditResult(ctx, profileName, state.command, evaluation, audited, approver);
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
      // The sudo password is the one secret that can plausibly end up in this
      // output (GHSA-9m75-x2ch-j4jr): it is written onto the very channel the
      // command reads. Scrub it here whatever the exec path was.
      const sudoPassword = rt.conn.getSudoPassword?.();
      const literalSecrets = sudoPassword ? [sudoPassword] : undefined;
      return { audited, output: commandOutput(audited, { literalSecrets }) };
    };
  }

  return { runAudited, execAndReport, defaultProfileName, makeCtx, auditResult, auditFailure, resolveConn, quota, grants };
}

export type Pipeline = ReturnType<typeof createPipeline>;
