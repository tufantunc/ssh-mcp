import type { CommandResult } from '../types.js';
import { redactText } from '../guard/redactor.js';

export function syntheticSuccess(profile: string): CommandResult {
  return { exitCode: 0, stdout: '', stderr: '', durationMs: 0, profile };
}

export type ToolResult = { content: { type: 'text'; text: string }[]; isError?: boolean };

export function textResult(text: string): ToolResult {
  return { content: [{ type: 'text' as const, text }] };
}

/**
 * Render a CommandResult for the client. A non-zero exit (or a kill signal)
 * is reported as isError with the redacted stderr and the exit status, so a
 * failed remote command cannot be mistaken for an empty success.
 */
export function commandOutput(result: CommandResult) {
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
