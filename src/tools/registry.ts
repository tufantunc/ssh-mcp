import { z } from 'zod';
import { createHash } from 'crypto';
import { ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { tracer } from '../observability/tracer.js';
import type { ConnectionRegistry } from '../ssh/connection-registry.js';
import type { PolicyEngine } from '../policy/engine.js';
import type { AuditStore } from '../audit/store.js';
import { sanitizeCommand, sanitizeSessionName, shellSingleQuote } from '../guard/sanitizer.js';
import { redactText } from '../guard/redactor.js';
import { requestApproval } from '../guard/elicitation.js';
import { SftpClient } from '../ssh/sftp.js';
import { BackgroundSession } from '../ssh/session.js';
import type { CommandResult, ToolContext, PolicyEvaluation, CommandClass } from '../types.js';

export const TOOL_DESCRIPTIONS: Record<string, string> = {
  'list-connections': 'List all configured SSH profiles and their connection status. Use this to discover available hosts before running commands.',
  'list-sessions': 'List active sessions for a given SSH profile.',
  'open-session': 'Open a named session on a remote host. Use type="interactive" for stateful shell (CWD/env persists between commands) or type="background" for long-running processes.',
  'close-session': 'Close a named session, releasing its resources.',
  'read-session-output': 'Read recent output from a background session (e.g., tail -f logs).',
  'read-command': 'Execute a READ-ONLY command from an allowlist (ls, cat, grep, find, stat, df, etc.). This tool does NOT modify the system. Prefer this tool for all read operations.',
  'run-command': 'Execute an arbitrary shell command on the remote server. May modify the system. Destructive commands require user approval.',
  'privileged-command': 'Execute a command with sudo elevation. ALWAYS requires user approval. The sudo password is piped via stdin (never visible in process list).',
  'sftp-upload': 'Upload a file to the remote server via SFTP (secure file transfer, not shell-based).',
  'sftp-download': 'Download a file from the remote server via SFTP.',
  'signal-process': 'Send a signal (INT, TERM, KILL) to a remote process by PID.',
};

export function getToolHashes(): Record<string, string> {
  const hashes: Record<string, string> = {};
  for (const [name, desc] of Object.entries(TOOL_DESCRIPTIONS)) {
    hashes[name] = createHash('sha256').update(desc).digest('hex').slice(0, 16);
  }
  return hashes;
}

const D = TOOL_DESCRIPTIONS;

/**
 * What we know about a request while it is being processed, so a failure can be
 * audited truthfully.
 *
 * The catch block of a tool handler is reached by two very different events: a
 * policy denial, and a failure *after* the command was allowed, approved and
 * executed. Recording both as `decision: 'deny'` told an auditor that commands
 * which actually ran on the host had been blocked.
 */
interface AuditState {
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
class PolicyRefusedError extends Error {
  constructor(message: string, readonly evaluation: PolicyEvaluation) {
    super(message);
    this.name = 'PolicyRefusedError';
  }
}

function syntheticSuccess(profile: string): CommandResult {
  return { exitCode: 0, stdout: '', stderr: '', durationMs: 0, profile };
}

function textResult(text: string) {
  return { content: [{ type: 'text' as const, text }] };
}

/**
 * Render a CommandResult for the client. A non-zero exit (or a kill signal)
 * is reported as isError with the redacted stderr and the exit status, so a
 * failed remote command cannot be mistaken for an empty success.
 */
function commandOutput(result: CommandResult) {
  // ssh2 reports exitCode null when the process died from a signal.
  const failed = result.exitCode !== 0 || Boolean(result.signal);
  // entropyScan matches the SFTP and session-output paths. Without it a plain
  // `env` dump hands high-entropy secrets straight to the model, since the
  // regex layer only knows a fixed set of token shapes.
  const stdout = redactText(result.stdout, { entropyScan: true });
  const stderr = redactText(result.stderr, { entropyScan: true });

  const parts: string[] = [];
  if (stdout) parts.push(stdout);
  if (stderr) parts.push(`[stderr]\n${stderr}`);
  if (failed) {
    parts.push(result.signal ? `[killed by SIG${result.signal}]` : `[exit ${result.exitCode}]`);
  }

  const content = [{ type: 'text' as const, text: parts.join('\n\n') }];
  return failed ? { content, isError: true } : { content };
}

export function registerTools(
  server: McpServer,
  registry: ConnectionRegistry,
  policy: PolicyEngine,
  audit: AuditStore,
) {
  async function resolveConn(profileName?: string) {
    return registry.getOrCreate(profileName);
  }

  async function checkPolicyAndApprove(
    command: string,
    profileName: string,
    toolName: string,
    ctx: ToolContext,
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

  async function runAudited(
    command: string,
    opts: {
      toolName: string;
      failureClass: CommandClass;
      enforceClass?: CommandClass;
      profile?: string;
      extra: any;
      exec: (conn: Awaited<ReturnType<typeof resolveConn>>, cleanCmd: string, onProgress?: (bytes: number, tail: string) => void, abortSignal?: AbortSignal) => Promise<CommandResult>;
    },
  ) {
    const ctx = makeCtx(opts.extra, opts.profile);
    const profileName = defaultProfileName(opts.profile);
    const profile = registry.getProfile(profileName);
    const onProgress = makeProgressSender(opts.extra);
    const abortSignal = opts.extra?.signal;
    // Sanitization lives inside the try so a rejected (empty, control-char-only,
    // over-length) command still leaves an audit trail — a client probing with
    // malformed payloads used to leave none.
    const state: AuditState = { command };
    try {
      const cleanCmd = sanitizeCommand(command, profile.maxChars);
      state.command = cleanCmd;
      const { conn, evaluation, approver } = await checkPolicyAndApprove(cleanCmd, profileName, opts.toolName, ctx);
      state.evaluation = evaluation;
      if (opts.enforceClass && evaluation.commandClass !== opts.enforceClass) {
        throw new Error(`${opts.toolName} only accepts ${opts.enforceClass} commands, got: ${evaluation.commandClass}`);
      }
      const result = await opts.exec(conn, cleanCmd, onProgress, abortSignal);
      await auditResult(ctx, profileName, cleanCmd, evaluation, result, approver);
      return commandOutput(result);
    } catch (err: any) {
      await auditFailure(ctx, profileName, state, opts.failureClass, err);
      throw err;
    }
  }

  // ─── list-connections ──────────────────────────────────────────────────
  server.tool(
    'list-connections',
    D["list-connections"],
    {},
    { readOnlyHint: true },
    async () => {
      const connections = registry.listConnections();
      const profiles = registry.listAllProfiles();
      const lines = profiles.map((p) => {
        const conn = connections.find((c) => c.profile === p.name);
        const status = conn?.status || 'disconnected';
        const sessions = conn?.sessionCount || 0;
        return `${p.name}: ${p.user}@${p.host}:${p.port} [${status}] sessions=${sessions} role=${p.role}`;
      });
      return textResult(lines.join('\n'));
    },
  );

  // ─── list-sessions ─────────────────────────────────────────────────────
  server.tool(
    'list-sessions',
    D["list-sessions"],
    { profile: z.string().optional().describe('Profile name (uses default if omitted)') },
    { readOnlyHint: true },
    async ({ profile }) => {
      const conn = registry.get(profile);
      if (!conn || conn.listSessions().length === 0) {
        return textResult('No active sessions.');
      }
      const sessions = conn.listSessions().map((s) => {
        const info = s.toInfo();
        return `${info.name} [${info.type}] status=${info.status} idle=${Math.round((Date.now() - info.lastActivity.getTime()) / 1000)}s`;
      });
      return textResult(sessions.join('\n'));
    },
  );

  // ─── open-session ──────────────────────────────────────────────────────
  server.tool(
    'open-session',
    D["open-session"],
    {
      name: z.string().describe('Session name (alphanumeric, dash, underscore, max 64 chars)'),
      type: z.enum(['interactive', 'background']).default('interactive').describe('Session type'),
      command: z.string().optional().describe('Command for background sessions'),
      profile: z.string().optional().describe('Profile name (uses default if omitted)'),
    },
    // No annotations object here on purpose. The SDK's overload resolution
    // treats an EMPTY object as a Zod raw shape (isZodRawShape returns true for
    // `{}`), so passing `{}` in the annotations slot made it consume the
    // callback slot instead — leaving this tool registered with no handler and
    // failing every call with "cb is not a function".
    async ({ name, type, command, profile }, extra) => {
      const cleanName = sanitizeSessionName(name);
      const ctx = makeCtx(extra, profile);
      const profileName = defaultProfileName(profile);

      if (type === 'background' && command) {
        const profileObj = registry.getProfile(profileName);
        const state: AuditState = { command };
        try {
          const cleanCmd = sanitizeCommand(command, profileObj.maxChars);
          state.command = cleanCmd;
          const { conn, evaluation, approver } = await checkPolicyAndApprove(cleanCmd, profileName, 'open-session', ctx);
          state.evaluation = evaluation;
          await conn.openSession({ name: cleanName, type, command: cleanCmd });
          await auditResult(ctx, profileName, cleanCmd, evaluation, syntheticSuccess(profileName), approver);
          return textResult(`Session "${cleanName}" opened on ${conn.profile.name} (${type}).`);
        } catch (err: any) {
          await auditFailure(ctx, profileName, state, 'destructive', err);
          throw err;
        }
      }

      // Opening a stateful shell is a security-relevant lifecycle event, so it
      // gets an audit record too — this branch used to produce none.
      const sessionCommand = `session:open ${type} ${cleanName}`;
      const state: AuditState = { command: sessionCommand };
      try {
        const { conn, evaluation, approver } = await checkPolicyAndApprove(sessionCommand, profileName, 'open-session', ctx);
        state.evaluation = evaluation;
        await conn.openSession({ name: cleanName, type, command });
        await auditResult(ctx, profileName, sessionCommand, evaluation, syntheticSuccess(profileName), approver);
        return textResult(`Session "${cleanName}" opened on ${conn.profile.name} (${type}).`);
      } catch (err: any) {
        await auditFailure(ctx, profileName, state, 'safe', err);
        throw err;
      }
    },
  );

  // ─── close-session ─────────────────────────────────────────────────────
  server.tool(
    'close-session',
    D["close-session"],
    {
      name: z.string().describe('Session name to close'),
      profile: z.string().optional().describe('Profile name'),
    },
    { destructiveHint: true },
    async ({ name, profile }) => {
      const conn = await resolveConn(profile);
      await conn.closeSession(name);
      return textResult(`Session "${name}" closed.`);
    },
  );

  // ─── read-session-output ───────────────────────────────────────────────
  server.tool(
    'read-session-output',
    D["read-session-output"],
    {
      name: z.string().describe('Background session name'),
      lines: z.number().optional().default(50).describe('Number of recent lines to read'),
      profile: z.string().optional().describe('Profile name'),
    },
    { readOnlyHint: true },
    async ({ name, lines, profile }) => {
      const conn = await resolveConn(profile);
      const session = conn.getSession(name);
      if (!session || session.type !== 'background') {
        return textResult(`Background session "${name}" not found.`);
      }
      if (session instanceof BackgroundSession) {
        return textResult(redactText(session.readOutput(lines), { entropyScan: true }));
      }
      return textResult(`Session "${name}" is not a background session.`);
    },
  );

  // ─── read-command ──────────────────────────────────────────────────────
  server.tool(
    'read-command',
    D["read-command"],
    {
      command: z.string().describe('Read-only shell command (must be in the allowlist)'),
      profile: z.string().optional().describe('Profile name'),
    },
    { readOnlyHint: true },
    async ({ command, profile }, extra) => {
      return runAudited(command, {
      toolName: 'read-command',
      failureClass: 'read-only',
      enforceClass: 'read-only',
      profile,
      extra,
      exec: (conn, cleanCmd, onProgress, abortSignal) => conn.exec(cleanCmd, { onProgress, abortSignal }),
      });
    },
  );

  // ─── run-command ───────────────────────────────────────────────────────
  server.tool(
    'run-command',
    D["run-command"],
    {
      command: z.string().describe('Shell command to execute'),
      profile: z.string().optional().describe('Profile name'),
      session: z.string().optional().describe('Run in an existing interactive session (stateful)'),
      tty: z.boolean().optional().describe('Allocate a pseudo-terminal'),
    },
    { destructiveHint: true },
    async ({ command, profile, session, tty }, extra) => {
      const ctx = makeCtx(extra, profile, session);
      const profileName = defaultProfileName(profile);
      const state: AuditState = { command };
      try {
        const cleanCmd = sanitizeCommand(command, registry.getProfile(profileName).maxChars);
        state.command = cleanCmd;
        const { conn, evaluation, approver } = await checkPolicyAndApprove(cleanCmd, profileName, 'run-command', ctx);
        state.evaluation = evaluation;

        let result: CommandResult;
        if (session) {
          const sess = conn.getSession(session);
          if (!sess) throw new Error(`Session "${session}" not found`);
          result = await sess.run(cleanCmd, undefined, extra?.signal);
        } else {
          result = await conn.exec(cleanCmd, { tty, onProgress: makeProgressSender(extra), abortSignal: extra?.signal });
        }

        await auditResult(ctx, profileName, cleanCmd, evaluation, result, approver);
        return commandOutput(result);
      } catch (err: any) {
        await auditFailure(ctx, profileName, state, 'safe', err);
        throw err;
      }
    },
  );

  // ─── privileged-command ────────────────────────────────────────────────
  server.tool(
    'privileged-command',
    D["privileged-command"],
    {
      command: z.string().describe('Command to execute with sudo'),
      profile: z.string().optional().describe('Profile name'),
    },
    { destructiveHint: true },
    async ({ command, profile }, extra) => {
      const ctx = makeCtx(extra, profile);
      const profileName = defaultProfileName(profile);
      const state: AuditState = { command };
      try {
        const cleanCmd = sanitizeCommand(command, registry.getProfile(profileName).maxChars);
        state.command = cleanCmd;
        // Evaluate the bare command too: the sudo wrapper would otherwise hide
        // a denylisted command inside a quoted `sh -c` argument.
        const rawEval = policy.evaluate(cleanCmd, registry.getProfile(profileName), 'privileged-command');
        if (rawEval.decision === 'deny') {
          state.evaluation = rawEval;
          throw new Error(`POLICY_DENIED: ${rawEval.reason || 'Command not allowed'}`);
        }
        const wrapped = `sudo -p "" -S sh -c ${shellSingleQuote(cleanCmd)}`;
        state.command = wrapped;
        const { conn, evaluation, approver } = await checkPolicyAndApprove(wrapped, profileName, 'privileged-command', ctx);
        state.evaluation = evaluation;

        const sudoPassword = conn.getSudoPassword();
        const result = await conn.exec(wrapped, {
          stdin: sudoPassword ? sudoPassword + '\n' : undefined,
          onProgress: makeProgressSender(extra),
          abortSignal: extra?.signal,
        });

        await auditResult(ctx, profileName, wrapped, evaluation, result, approver);
        return commandOutput(result);
      } catch (err: any) {
        await auditFailure(ctx, profileName, state, 'privileged', err);
        throw err;
      }
    },
  );

  // ─── sftp-upload ───────────────────────────────────────────────────────
  server.tool(
    'sftp-upload',
    D["sftp-upload"],
    {
      remotePath: z.string().describe('Remote file path'),
      content: z.string().describe('File content to upload'),
      profile: z.string().optional().describe('Profile name'),
    },
    { destructiveHint: true },
    async ({ remotePath, content, profile }, extra) => {
      const ctx = makeCtx(extra, profile);
      const profileName = defaultProfileName(profile);
      const syntheticCommand = `sftp:upload ${remotePath}`;
      const state: AuditState = { command: syntheticCommand };
      try {
        const { conn, evaluation, approver } = await checkPolicyAndApprove(syntheticCommand, profileName, 'sftp-upload', ctx);
        state.evaluation = evaluation;
        const sftp = new SftpClient(conn);
        await sftp.upload({ remotePath, content });
        await auditResult(ctx, profileName, syntheticCommand, evaluation, syntheticSuccess(profileName), approver);
        return textResult(`Uploaded ${content.length} bytes to ${remotePath}`);
      } catch (err: any) {
        await auditFailure(ctx, profileName, state, 'destructive', err);
        throw err;
      }
    },
  );

  // ─── sftp-download ─────────────────────────────────────────────────────
  server.tool(
    'sftp-download',
    D["sftp-download"],
    {
      remotePath: z.string().describe('Remote file path to download'),
      profile: z.string().optional().describe('Profile name'),
    },
    { readOnlyHint: true },
    async ({ remotePath, profile }, extra) => {
      const ctx = makeCtx(extra, profile);
      const profileName = defaultProfileName(profile);
      const syntheticCommand = `sftp:download ${remotePath}`;
      const state: AuditState = { command: syntheticCommand };
      try {
        const { conn, evaluation, approver } = await checkPolicyAndApprove(syntheticCommand, profileName, 'sftp-download', ctx);
        state.evaluation = evaluation;
        const sftp = new SftpClient(conn);
        const data = await sftp.download({ remotePath });
        await auditResult(ctx, profileName, syntheticCommand, evaluation, syntheticSuccess(profileName), approver);
        return textResult(redactText(data.toString('utf8'), { entropyScan: true }));
      } catch (err: any) {
        await auditFailure(ctx, profileName, state, 'read-only', err);
        throw err;
      }
    },
  );

  // ─── signal-process ────────────────────────────────────────────────────
  server.tool(
    'signal-process',
    D["signal-process"],
    {
      pid: z.number().int().min(1).describe('Process ID to signal (positive integer)'),
      signal: z.enum(['INT', 'TERM', 'KILL']).default('TERM').describe('Signal to send'),
      profile: z.string().optional().describe('Profile name'),
    },
    { destructiveHint: true },
    async ({ pid, signal, profile }, extra) => {
      const ctx = makeCtx(extra, profile);
      const command = `kill -${signal} ${pid}`;
      const profileName = defaultProfileName(profile);
      const state: AuditState = { command };
      try {
        const { conn, evaluation, approver } = await checkPolicyAndApprove(command, profileName, 'signal-process', ctx);
        state.evaluation = evaluation;
        const result = await conn.exec(command, { abortSignal: extra?.signal });
        await auditResult(ctx, profileName, command, evaluation, result, approver);
        const output = commandOutput(result);
        // `kill` is silent on success — confirm what was sent instead of an empty result.
        if (!('isError' in output) && !result.stdout.trim() && !result.stderr.trim()) {
          return textResult(`Signal ${signal} sent to PID ${pid}`);
        }
        return output;
      } catch (err: any) {
        await auditFailure(ctx, profileName, state, 'destructive', err);
        throw err;
      }
    },
  );
}

export function registerResources(
  server: McpServer,
  registry: ConnectionRegistry,
) {
  function jsonResource(uri: string, data: unknown) {
    return {
      contents: [{
        uri,
        mimeType: 'application/json',
        text: JSON.stringify(data, null, 2),
      }],
    };
  }

  server.resource(
    'connections',
    'ssh://connections',
    { description: 'List all SSH profiles and their connection status', mimeType: 'application/json' },
    async () => {
      const connections = registry.listConnections();
      const profiles = registry.listAllProfiles().map((p) => {
        const conn = connections.find((c) => c.profile === p.name);
        return {
          name: p.name,
          host: p.host,
          port: p.port,
          user: p.user,
          role: p.role,
          readOnly: p.readOnly,
          approvalPolicy: p.approvalPolicy,
          status: conn?.status || 'disconnected',
          sessions: conn?.sessionCount || 0,
        };
      });
      return jsonResource('ssh://connections', { profiles });
    },
  );

  server.resource(
    'profile',
    new ResourceTemplate('ssh://connections/{profile}', { list: undefined }),
    { description: 'Get details for a specific SSH profile', mimeType: 'application/json' },
    async (uri, variables) => {
      const profileName = variables.profile as string;
      const profile = registry.listAllProfiles().find((p) => p.name === profileName);
      if (!profile) {
        return jsonResource(uri.href, { error: `Profile "${profileName}" not found` });
      }
      const conn = registry.get(profileName);
      const sessions = conn?.listSessions().map((s) => s.toInfo()) || [];
      return jsonResource(uri.href, {
        profile: {
          name: profile.name,
          host: profile.host,
          port: profile.port,
          user: profile.user,
          role: profile.role,
          readOnly: profile.readOnly,
          auth: profile.auth,
          approvalPolicy: profile.approvalPolicy,
          via: profile.via,
          workdir: profile.workdir,
          tty: profile.tty,
          timeout: profile.timeout,
          maxChars: profile.maxChars,
          sessionMaxPerConnection: profile.sessionMaxPerConnection,
          sessionIdleTimeoutMs: profile.sessionIdleTimeoutMs,
        },
        connection: conn?.toInfo() || null,
        sessions,
      });
    },
  );

  server.resource(
    'session',
    new ResourceTemplate('ssh://sessions/{profile}/{session}', { list: undefined }),
    { description: 'Get metadata for a specific session', mimeType: 'application/json' },
    async (uri, variables) => {
      const profileName = variables.profile as string;
      const sessionName = variables.session as string;
      const conn = registry.get(profileName);
      if (!conn) {
        return jsonResource(uri.href, { error: `Profile "${profileName}" not connected` });
      }
      const session = conn.getSession(sessionName);
      if (!session) {
        return jsonResource(uri.href, { error: `Session "${sessionName}" not found on ${profileName}` });
      }
      return jsonResource(uri.href, session.toInfo());
    },
  );
}
