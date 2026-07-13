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

export const TOOL_METADATA = [
  { name: 'list-connections', description: 'List all configured SSH profiles and their connection status. Use this to discover available hosts before running commands.' },
  { name: 'list-sessions', description: 'List active sessions for a given SSH profile.' },
  { name: 'open-session', description: 'Open a named session on a remote host. Use type="interactive" for stateful shell (CWD/env persists between commands) or type="background" for long-running processes.' },
  { name: 'close-session', description: 'Close a named session, releasing its resources.' },
  { name: 'read-session-output', description: 'Read recent output from a background session (e.g., tail -f logs).' },
  { name: 'read-command', description: 'Execute a READ-ONLY command from an allowlist (ls, cat, grep, find, stat, df, etc.). This tool does NOT modify the system. Prefer this tool for all read operations.' },
  { name: 'run-command', description: 'Execute an arbitrary shell command on the remote server. May modify the system. Destructive commands require user approval.' },
  { name: 'privileged-command', description: 'Execute a command with sudo elevation. ALWAYS requires user approval. The sudo password is piped via stdin (never visible in process list).' },
  { name: 'sftp-upload', description: 'Upload a file to the remote server via SFTP (secure file transfer, not shell-based).' },
  { name: 'sftp-download', description: 'Download a file from the remote server via SFTP.' },
  { name: 'signal-process', description: 'Send a signal (INT, TERM, KILL) to a remote process by PID.' },
] as const;

export function getToolHashes(): Record<string, string> {
  const hashes: Record<string, string> = {};
  for (const tool of TOOL_METADATA) {
    hashes[tool.name] = createHash('sha256').update(tool.description).digest('hex').slice(0, 16);
  }
  return hashes;
}

function deniedEvaluation(commandClass: CommandClass): PolicyEvaluation {
  return { decision: 'deny', commandClass, binary: '', ruleId: 'error' };
}

function textResult(text: string) {
  return { content: [{ type: 'text' as const, text }] };
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
        throw new Error(`POLICY_DENIED: ${evaluation.reason || 'Command not allowed'}`);
      }

      if (evaluation.decision === 'require-approval') {
        const approval = await requestApproval(server, command, conn.profile.name, evaluation);
        if (!approval.approved) {
          throw new Error('APPROVAL_DENIED: User did not approve this command');
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
      exitCode: 'exitCode' in result ? result.exitCode : undefined,
      durationMs: 'durationMs' in result ? result.durationMs : undefined,
      error: 'error' in result ? result.error : undefined,
      approver,
    });
  }

  function makeCtx(extra: any, profile?: string, session?: string): ToolContext {
    return { requestId: extra?.requestId ?? 0, profile, session };
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
      profile?: string;
      extra: any;
      exec: (conn: Awaited<ReturnType<typeof resolveConn>>, onProgress?: (bytes: number, tail: string) => void, abortSignal?: AbortSignal) => Promise<CommandResult>;
    },
  ) {
    const ctx = makeCtx(opts.extra, opts.profile);
    const profileName = defaultProfileName(opts.profile);
    const profile = registry.getProfile(profileName);
    const onProgress = makeProgressSender(opts.extra);
    const abortSignal = opts.extra?.signal;
    const cleanCmd = sanitizeCommand(command, profile.maxChars);
    try {
      const { conn, evaluation, approver } = await checkPolicyAndApprove(cleanCmd, profileName, opts.toolName, ctx);
      const result = await opts.exec(conn, onProgress, abortSignal);
      await auditResult(ctx, profileName, cleanCmd, evaluation, result, approver);
      return textResult(redactText(result.stdout));
    } catch (err: any) {
      await auditResult(ctx, profileName, cleanCmd, deniedEvaluation(opts.failureClass), { error: err.message });
      throw err;
    }
  }

  // ─── list-connections ──────────────────────────────────────────────────
  server.tool(
    'list-connections',
    'List all configured SSH profiles and their connection status. Use this to discover available hosts before running commands.',
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
    'List active sessions for a given SSH profile.',
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
    'Open a named session on a remote host. Use type="interactive" for stateful shell (CWD/env persists between commands) or type="background" for long-running processes.',
    {
      name: z.string().describe('Session name (alphanumeric, dash, underscore, max 64 chars)'),
      type: z.enum(['interactive', 'background']).default('interactive').describe('Session type'),
      command: z.string().optional().describe('Command for background sessions'),
      profile: z.string().optional().describe('Profile name (uses default if omitted)'),
    },
    {},
    async ({ name, type, command, profile }, extra) => {
      const cleanName = sanitizeSessionName(name);
      const ctx = makeCtx(extra, profile);
      const profileName = defaultProfileName(profile);

      if (type === 'background' && command) {
        try {
          await checkPolicyAndApprove(command, profileName, 'open-session', ctx);
        } catch (err: any) {
          await auditResult(ctx, profileName, command, deniedEvaluation('destructive'), { error: err.message });
          throw err;
        }
      }

      const conn = await resolveConn(profile);
      const session = await conn.openSession({ name: cleanName, type, command });
      return textResult(`Session "${cleanName}" opened on ${conn.profile.name} (${type}).`);
    },
  );

  // ─── close-session ─────────────────────────────────────────────────────
  server.tool(
    'close-session',
    'Close a named session, releasing its resources.',
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
    'Read recent output from a background session (e.g., tail -f logs).',
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
        return textResult(session.readOutput(lines));
      }
      return textResult(`Session "${name}" is not a background session.`);
    },
  );

  // ─── read-command ──────────────────────────────────────────────────────
  server.tool(
    'read-command',
    'Execute a READ-ONLY command from an allowlist (ls, cat, grep, find, stat, df, etc.). This tool does NOT modify the system. Prefer this tool for all read operations.',
    {
      command: z.string().describe('Read-only shell command (must be in the allowlist)'),
      profile: z.string().optional().describe('Profile name'),
    },
    { readOnlyHint: true },
    async ({ command, profile }, extra) => {
      return runAudited(command, {
        toolName: 'read-command',
        failureClass: 'read-only',
        profile,
        extra,
        exec: (conn, onProgress, abortSignal) => conn.exec(command, { onProgress, abortSignal }),
      });
    },
  );

  // ─── run-command ───────────────────────────────────────────────────────
  server.tool(
    'run-command',
    'Execute an arbitrary shell command on the remote server. May modify the system. Destructive commands require user approval.',
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
      const cleanCmd = sanitizeCommand(command, registry.getProfile(profileName).maxChars);
      try {
        const { conn, evaluation, approver } = await checkPolicyAndApprove(cleanCmd, profileName, 'run-command', ctx);

        let result: CommandResult;
        if (session) {
          const sess = conn.getSession(session);
          if (!sess) throw new Error(`Session "${session}" not found`);
          result = await sess.run(cleanCmd);
        } else {
          result = await conn.exec(cleanCmd, { tty, onProgress: makeProgressSender(extra), abortSignal: extra?.signal });
        }

        await auditResult(ctx, profileName, cleanCmd, evaluation, result, approver);
        return textResult(redactText(result.stdout));
      } catch (err: any) {
        await auditResult(ctx, profileName, cleanCmd, deniedEvaluation('safe'), { error: err.message });
        throw err;
      }
    },
  );

  // ─── privileged-command ────────────────────────────────────────────────
  server.tool(
    'privileged-command',
    'Execute a command with sudo elevation. ALWAYS requires user approval. The sudo password is piped via stdin (never visible in process list).',
    {
      command: z.string().describe('Command to execute with sudo'),
      profile: z.string().optional().describe('Profile name'),
    },
    { destructiveHint: true },
    async ({ command, profile }, extra) => {
      const ctx = makeCtx(extra, profile);
      const profileName = defaultProfileName(profile);
      const cleanCmd = sanitizeCommand(command, registry.getProfile(profileName).maxChars);
      try {
        const { conn, evaluation, approver } = await checkPolicyAndApprove(`sudo ${cleanCmd}`, profileName, 'privileged-command', ctx);

        const sudoPassword = conn.getSudoPassword();
        const wrapped = `sudo -p "" -S sh -c ${shellSingleQuote(cleanCmd)}`;
        const result = await conn.exec(wrapped, {
          stdin: sudoPassword ? sudoPassword + '\n' : undefined,
          onProgress: makeProgressSender(extra),
          abortSignal: extra?.signal,
        });

        await auditResult(ctx, profileName, `sudo ${cleanCmd}`, evaluation, result, approver);
        return textResult(redactText(result.stdout));
      } catch (err: any) {
        await auditResult(ctx, profileName, `sudo ${cleanCmd}`, deniedEvaluation('privileged'), { error: err.message });
        throw err;
      }
    },
  );

  // ─── sftp-upload ───────────────────────────────────────────────────────
  server.tool(
    'sftp-upload',
    'Upload a file to the remote server via SFTP (secure file transfer, not shell-based).',
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
      try {
        const { conn, evaluation, approver } = await checkPolicyAndApprove(syntheticCommand, profileName, 'sftp-upload', ctx);
        const sftp = new SftpClient(conn);
        await sftp.upload({ remotePath, content });
        await auditResult(ctx, profileName, syntheticCommand, evaluation, { exitCode: 0, stdout: '', stderr: '', durationMs: 0, profile: profileName } as CommandResult, approver);
        return textResult(`Uploaded ${content.length} bytes to ${remotePath}`);
      } catch (err: any) {
        await auditResult(ctx, profileName, syntheticCommand, deniedEvaluation('destructive'), { error: err.message });
        throw err;
      }
    },
  );

  // ─── sftp-download ─────────────────────────────────────────────────────
  server.tool(
    'sftp-download',
    'Download a file from the remote server via SFTP.',
    {
      remotePath: z.string().describe('Remote file path to download'),
      profile: z.string().optional().describe('Profile name'),
    },
    { readOnlyHint: true },
    async ({ remotePath, profile }, extra) => {
      const ctx = makeCtx(extra, profile);
      const profileName = defaultProfileName(profile);
      const syntheticCommand = `sftp:download ${remotePath}`;
      try {
        const { conn, evaluation, approver } = await checkPolicyAndApprove(syntheticCommand, profileName, 'sftp-download', ctx);
        const sftp = new SftpClient(conn);
        const data = await sftp.download({ remotePath });
        await auditResult(ctx, profileName, syntheticCommand, evaluation, { exitCode: 0, stdout: '', stderr: '', durationMs: 0, profile: profileName } as CommandResult, approver);
        return textResult(redactText(data.toString('utf8'), { entropyScan: true }));
      } catch (err: any) {
        await auditResult(ctx, profileName, syntheticCommand, deniedEvaluation('read-only'), { error: err.message });
        throw err;
      }
    },
  );

  // ─── signal-process ────────────────────────────────────────────────────
  server.tool(
    'signal-process',
    'Send a signal (INT, TERM, KILL) to a remote process by PID.',
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
      try {
        const { conn, evaluation, approver } = await checkPolicyAndApprove(command, profileName, 'signal-process', ctx);
        const result = await conn.exec(command);
        await auditResult(ctx, profileName, command, evaluation, result, approver);
        return textResult(result.stdout || `Signal ${signal} sent to PID ${pid}`);
      } catch (err: any) {
        await auditResult(ctx, profileName, command, deniedEvaluation('destructive'), { error: err.message });
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
