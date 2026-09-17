import { z } from 'zod';
import { sanitizeSessionName } from '../guard/sanitizer.js';
import { redactText } from '../guard/redactor.js';
import { BackgroundSession, type CloseOutcome } from '../ssh/session.js';
import { COULD_NOT_SIGNAL } from '../ssh/channel-signal.js';
import { TOOL_DESCRIPTIONS as D } from './descriptions.js';
import { syntheticSuccess, textResult } from './results.js';
import type { ToolDeps, Pipeline } from './pipeline.js';
import type { PolicyEvaluation } from '../types.js';

/** Connection and session discovery/lifecycle tools. */
/**
 * The evaluation recorded for a session release.
 *
 * Releasing a session is audited but never refused, which is why this is a constant rather
 * than an engine call. The first version of this routed the close through `runAudited`, and
 * that made the stop *refusable*: `session:close <name>` classifies as `safe`, so a
 * `readOnly` profile — which can open a background session, because a `tail -f` classifies
 * `read-only` — was denied permission to close it, and had no other way to stop the
 * command for an hour. `ask-all` prompted on every close, and an exhausted
 * `commandQuotaPerDay` wedged the profile entirely.
 *
 * A control whose refusal mode is "the thing you asked me to stop keeps running" is worse
 * than the unaudited stop it replaced. The record was the part worth having; the veto was
 * not. `ruleId` says so, so the log distinguishes this from an engine `allow`.
 */
const RELEASE: PolicyEvaluation = {
  decision: 'allow',
  commandClass: 'safe',
  binary: 'session:close',
  ruleId: 'session-release',
  reason: 'A session release is audited but not policy-gated; see SECURITY.md.',
};

/** What to append to the caller's confirmation for each outcome. */
const CLOSE_NOTES: Record<CloseOutcome, string> = {
  closed: '',
  unsignalled: COULD_NOT_SIGNAL,
  'stop-unconfirmed':
    ' The command was signalled but the channel had not closed in time, so it may still be running on the host.',
};

export function registerSessionTools(
  { server, registry }: ToolDeps,
  pipeline: Pipeline,
) {
  const { runAudited, resolveConn, auditResult, auditFailure, makeCtx, defaultProfileName } = pipeline;

  // ─── list-connections ──────────────────────────────────────────────────
  server.tool(
    'list-connections',
    D["list-connections"],
    {},
    { readOnlyHint: true },
    async () => {
      // The one tool that reads only `listAllProfiles()` and so never touches
      // `getProfile`. Without this it answered an unconfigured server with a
      // zero-length success — on the tool whose own description sends an agent here
      // first ("discover available hosts before running commands"), and on the one
      // channel where the startup stderr warning is not visible. The agent saw "no
      // hosts" rather than "not configured". Refusing here is what makes the claim in
      // the README, the changeset and the startup warning true of every tool.
      registry.assertConfigured();
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
    async ({ name, profile }, extra) => {
      const cleanName = sanitizeSessionName(name);
      // Both the profile name and the connection are resolved inside the try below. They
      // used to be resolved above it, so a refusal — an unconfigured server, an unknown
      // profile name — escaped before `auditFailure` could record that a release was
      // attempted. The placeholders are what the record is filed under if resolution is
      // itself what failed.
      let profileName = profile ?? '(default)';
      const ctx = makeCtx(extra, profileName, cleanName);
      let command = `session:close unknown ${cleanName}`;
      const startedAt = Date.now();

      try {
        profileName = defaultProfileName(profile);
        ctx.profile = profileName;
        const conn = await resolveConn(profile);
        // Recorded with the session's kind, so a remote SIGKILL is greppable in the log and
        // distinguishable from ending a local shell — `open-session` encodes its type the
        // same way.
        // Through `toInfo()` rather than an `instanceof` check: the type is public API, and a
        // tool handler reaching for a constructor identity is the layer leak this repo's own
        // rules call out.
        const kind = conn.getSession(cleanName)?.toInfo().type ?? 'unknown';
        command = `session:close ${kind} ${cleanName}`;
        const outcome = await conn.closeSession(cleanName);
        await auditResult(ctx, profileName, command, RELEASE, {
          stdout: '',
          stderr: '',
          exitCode: outcome === 'closed' ? 0 : 1,
          durationMs: Date.now() - startedAt,
          profile: profileName,
        });
        return textResult(`Session "${cleanName}" closed.${CLOSE_NOTES[outcome]}`);
      } catch (err) {
        await auditFailure(ctx, profileName, { command }, 'safe', err);
        throw err;
      }
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
