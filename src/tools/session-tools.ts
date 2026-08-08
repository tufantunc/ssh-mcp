import { z } from 'zod';
import { sanitizeSessionName } from '../guard/sanitizer.js';
import { redactText } from '../guard/redactor.js';
import { BackgroundSession } from '../ssh/session.js';
import { TOOL_DESCRIPTIONS as D } from './descriptions.js';
import { syntheticSuccess, textResult } from './results.js';
import type { ToolDeps, Pipeline } from './pipeline.js';

/** Connection and session discovery/lifecycle tools. */
export function registerSessionTools(
  { server, registry }: ToolDeps,
  pipeline: Pipeline,
) {
  const { runAudited, resolveConn } = pipeline;

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
      const isBackground = type === 'background' && Boolean(command);

      // A background session runs a caller-supplied command, so that command is
      // what policy must evaluate. An interactive session runs no command yet,
      // but opening a stateful shell is still a lifecycle event worth auditing
      // — that branch used to produce no record at all.
      return runAudited(
        isBackground ? command! : `session:open ${type} ${cleanName}`,
        {
          toolName: 'open-session',
          failureClass: isBackground ? 'destructive' : 'safe',
          profile,
          session: cleanName,
          extra,
          synthetic: !isBackground,
        },
        async (rt) => {
          await rt.conn.openSession({
            name: cleanName,
            type,
            command: isBackground ? rt.command : command,
          });
          return {
            audited: syntheticSuccess(rt.profileName),
            output: textResult(`Session "${cleanName}" opened on ${rt.conn.profile.name} (${type}).`),
          };
        },
      );
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
}
