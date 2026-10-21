import { z } from 'zod';
import { shellSingleQuote } from '../guard/sanitizer.js';
import { TOOL_DESCRIPTIONS as D } from './descriptions.js';
import { commandOutput, textResult } from './results.js';
import { PolicyRefusedError, type ToolDeps, type Pipeline } from './pipeline.js';
import type { CommandResult } from '../types.js';

/** Tools that run a command on the remote host. */
export function registerCommandTools(
  { server, registry, policy }: ToolDeps,
  pipeline: Pipeline,
) {
  const { runAudited, execAndReport, defaultProfileName } = pipeline;

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
      return runAudited(
        command,
        { toolName: 'read-command', failureClass: 'read-only', enforceClass: 'read-only', profile, extra },
        execAndReport(),
      );
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
      return runAudited(
        command,
        { toolName: 'run-command', failureClass: 'safe', profile, session, extra },
        async (rt) => {
          // A session run keeps the caller's shell state; a plain exec does not.
          let audited: CommandResult;
          if (session) {
            const sess = rt.conn.getSession(session);
            if (!sess) throw new Error(`Session "${session}" not found`);
            audited = await sess.run(rt.command, undefined, rt.abortSignal);
          } else {
            audited = await rt.conn.exec(rt.command, {
              tty, onProgress: rt.onProgress, abortSignal: rt.abortSignal,
            });
          }
          return { audited, output: commandOutput(audited) };
        },
      );
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
      return runAudited(
        command,
        {
          toolName: 'privileged-command',
          failureClass: 'privileged',
          profile,
          extra,
          // Evaluate the bare command too: the sudo wrapper would otherwise
          // hide a forbidden command inside a quoted `sh -c` argument.
          preCheck: (cleanCmd) => {
            // Resolved here rather than before `runAudited`: `defaultProfileName` reaches
            // `registry.getProfile()`, which refuses on an unconfigured server, and outside
            // the pipeline's try that refusal escaped without an audit record. `preCheck`
            // runs inside it.
            const rawEval = policy.evaluate(
              cleanCmd,
              registry.getProfile(defaultProfileName(profile)),
            );
            if (rawEval.decision === 'deny') {
              throw new PolicyRefusedError(
                `POLICY_DENIED: ${rawEval.reason || 'Command not allowed'}`,
                rawEval,
              );
            }
          },
          // `sudo -S` reads stdin only when it actually needs a password. Under
          // NOPASSWD — or any policy that skips the prompt — the password line
          // written for it stays in the pipe, and sudo exec's this `sh -c` with
          // that same stdin, so a stdin-reading command could hand the password
          // straight back (GHSA-9m75-x2ch-j4jr). Re-pointing fd 0 at /dev/null
          // before the command runs means sudo still gets its password from the
          // channel when it does prompt, and the command can never see it.
          // stdin carries nothing else the command could want: the password
          // line was the only thing ever written.
          wrap: (cleanCmd) => `sudo -p "" -S sh -c ${shellSingleQuote(`exec 0</dev/null; ${cleanCmd}`)}`,
        },
        (rt) => {
          const sudoPassword = rt.conn.getSudoPassword();
          return execAndReport({ stdin: sudoPassword ? sudoPassword + '\n' : undefined })(rt);
        },
      );
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
      return runAudited(
        `kill -${signal} ${pid}`,
        { toolName: 'signal-process', failureClass: 'destructive', profile, extra, synthetic: true },
        async (rt) => {
          const { audited, output } = await execAndReport()(rt);
          // `kill` is silent on success — confirm what was sent rather than
          // returning an empty result.
          const silentSuccess = !output.isError && !audited.stdout.trim() && !audited.stderr.trim();
          return {
            audited,
            output: silentSuccess ? textResult(`Signal ${signal} sent to PID ${pid}`) : output,
          };
        },
      );
    },
  );
}
