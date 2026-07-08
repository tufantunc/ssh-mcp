import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { ConnectionRegistry } from '../ssh/connection-registry.js';
import type { PolicyEngine } from '../policy/engine.js';
import type { AuditStore } from '../audit/store.js';
import { sanitizeCommand, sanitizeSessionName } from '../guard/sanitizer.js';
import { redactText } from '../guard/redactor.js';
import { requestApproval } from '../guard/elicitation.js';
import { SftpClient } from '../ssh/sftp.js';
import type { CommandResult, ToolContext } from '../types.js';

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
    const conn = await resolveConn(profileName);
    const evaluation = policy.evaluate(command, conn.profile, toolName);

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
  }

  async function auditResult(
    ctx: ToolContext,
    profileName: string,
    command: string,
    evaluation: any,
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
      return { content: [{ type: 'text', text: lines.join('\n') }] };
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
        return { content: [{ type: 'text', text: 'No active sessions.' }] };
      }
      const sessions = conn.listSessions().map((s) => {
        const info = s.toInfo();
        return `${info.name} [${info.type}] status=${info.status} idle=${Math.round((Date.now() - info.lastActivity.getTime()) / 1000)}s`;
      });
      return { content: [{ type: 'text', text: sessions.join('\n') }] };
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
    async ({ name, type, command, profile }) => {
      const cleanName = sanitizeSessionName(name);
      const conn = await resolveConn(profile);
      const session = await conn.openSession({ name: cleanName, type, command });
      return {
        content: [{
          type: 'text',
          text: `Session "${cleanName}" opened on ${conn.profile.name} (${type}).`,
        }],
      };
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
      return {
        content: [{ type: 'text', text: `Session "${name}" closed.` }],
      };
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
        return { content: [{ type: 'text', text: `Background session "${name}" not found.` }] };
      }
      const bg = session as any;
      return { content: [{ type: 'text', text: bg.readOutput(lines) }] };
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
      const ctx: ToolContext = { requestId: (extra as any)?.requestId ?? 0, profile };
      const cleanCmd = sanitizeCommand(command, Infinity);
      const profileName = profile || registry.getProfile().name;
      try {
        const { conn, evaluation } = await checkPolicyAndApprove(cleanCmd, profileName, 'read-command', ctx);
        const result = await conn.exec(cleanCmd);
        await auditResult(ctx, profileName, cleanCmd, evaluation, result);
        return { content: [{ type: 'text', text: redactText(result.stdout) }] };
      } catch (err: any) {
        await auditResult(ctx, profileName, cleanCmd, { commandClass: 'read-only', binary: '', decision: 'deny' }, { error: err.message });
        throw err;
      }
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
    {},
    async ({ command, profile, session, tty }, extra) => {
      const ctx: ToolContext = { requestId: (extra as any)?.requestId ?? 0, profile, session };
      const cleanCmd = sanitizeCommand(command, Infinity);
      const profileName = profile || registry.getProfile().name;
      try {
        const { conn, evaluation, approver } = await checkPolicyAndApprove(cleanCmd, profileName, 'run-command', ctx);

        let result: CommandResult;
        if (session) {
          const sess = conn.getSession(session);
          if (!sess) throw new Error(`Session "${session}" not found`);
          result = await sess.run(cleanCmd);
        } else {
          result = await conn.exec(cleanCmd, { tty });
        }

        await auditResult(ctx, profileName, cleanCmd, evaluation, result, approver);
        return { content: [{ type: 'text', text: redactText(result.stdout) }] };
      } catch (err: any) {
        await auditResult(ctx, profileName, cleanCmd, { commandClass: 'safe', binary: '', decision: 'deny' }, { error: err.message });
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
      const ctx: ToolContext = { requestId: (extra as any)?.requestId ?? 0, profile };
      const cleanCmd = sanitizeCommand(command, Infinity);
      const profileName = profile || registry.getProfile().name;
      try {
        const { conn, evaluation, approver } = await checkPolicyAndApprove(`sudo ${cleanCmd}`, profileName, 'privileged-command', ctx);

        const conn2 = await resolveCredentialsWithSudo(profileName);
        const wrapped = `sudo -p "" -S sh -c '${cleanCmd.replace(/'/g, "'\\''")}'`;
        const result = await conn2.exec(wrapped, { stdin: conn2.getClient() ? undefined : undefined });

        await auditResult(ctx, profileName, `sudo ${cleanCmd}`, evaluation, result, approver);
        return { content: [{ type: 'text', text: redactText(result.stdout) }] };
      } catch (err: any) {
        await auditResult(ctx, profileName, `sudo ${cleanCmd}`, { commandClass: 'privileged', binary: '', decision: 'deny' }, { error: err.message });
        throw err;
      }
    },
  );

  async function resolveCredentialsWithSudo(profileName: string) {
    return resolveConn(profileName);
  }

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
    async ({ remotePath, content, profile }) => {
      const conn = await resolveConn(profile);
      const sftp = new SftpClient(conn);
      await sftp.upload({ remotePath, content });
      return { content: [{ type: 'text', text: `Uploaded ${content.length} bytes to ${remotePath}` }] };
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
    async ({ remotePath, profile }) => {
      const conn = await resolveConn(profile);
      const sftp = new SftpClient(conn);
      const data = await sftp.download({ remotePath });
      return { content: [{ type: 'text', text: data.toString('utf8') }] };
    },
  );

  // ─── signal-process ────────────────────────────────────────────────────
  server.tool(
    'signal-process',
    'Send a signal (INT, TERM, KILL) to a remote process by PID.',
    {
      pid: z.number().describe('Process ID to signal'),
      signal: z.enum(['INT', 'TERM', 'KILL']).default('TERM').describe('Signal to send'),
      profile: z.string().optional().describe('Profile name'),
    },
    { destructiveHint: true },
    async ({ pid, signal, profile }) => {
      const conn = await resolveConn(profile);
      const result = await conn.exec(`kill -${signal} ${pid}`);
      return { content: [{ type: 'text', text: result.stdout || `Signal ${signal} sent to PID ${pid}` }] };
    },
  );
}
