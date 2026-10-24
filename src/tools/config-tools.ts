import { z } from 'zod';
import { TOOL_DESCRIPTIONS as D } from './descriptions.js';
import { textResult, type ToolResult } from './results.js';
import type { ToolDeps } from './pipeline.js';
import type { ConfigReloader, ReloadOutcome } from '../config/reload.js';
import { errorName } from '../errors.js';

/**
 * `reload-config`: the config file's status, or a reload of it.
 *
 * Not approval-gated and not quota-counted: the file is the operator's consent, and a
 * caller can only make the server re-read what the operator wrote. The reloader audits
 * every attempt itself. Nothing here prints a value from the file: the status is the path,
 * the source, the load time and the hash, and the outcome text is `formatOutcome`, which
 * names profiles and fields only.
 */
export function registerConfigTools({ server, reloader }: Pick<ToolDeps, 'server' | 'reloader'>) {
  server.tool(
    'reload-config',
    D['reload-config'],
    {
      action: z
        .enum(['status', 'reload'])
        .optional()
        .describe('"status" (default) reports the loaded config; "reload" re-reads and applies the file'),
    },
    // A reload can close connections and their sessions.
    { destructiveHint: true },
    async ({ action = 'status' }, extra): Promise<ToolResult> => {
      if (!reloader) {
        return { ...textResult('Config reload is not available on this server.'), isError: true };
      }
      if (action === 'status') return textResult(formatStatus(reloader));

      let outcome: ReloadOutcome;
      try {
        outcome = await reloader.reload('tool', extra?.requestId ?? 0);
      } catch (err) {
        // reload() resolves on every failure it knows of; this is a defect. Its message
        // may quote the file, so only the class is reported.
        const name = errorName(err);
        console.error(`Config reload (tool) failed unexpectedly (${name}).`);
        return {
          ...textResult(
            `Config reload failed unexpectedly (${name}). Check reload-config status, ` +
            'and restart the server if it does not show the new config.',
          ),
          isError: true,
        };
      }
      const result = textResult(reloader.formatOutcome(outcome));
      return outcome.ok ? result : { ...result, isError: true };
    },
  );
}

function formatStatus(reloader: ConfigReloader): string {
  const s = reloader.status();
  const lines = [
    `Config file: ${s.path}`,
    `Source: ${s.source}`,
    `Loaded at: ${s.loadedAt}`,
    `sha256: ${s.sha256 ?? 'none (no file has been loaded)'}`,
  ];
  if (!s.last) {
    lines.push('Last reload: none.');
  } else {
    const result = s.last.ok ? 'applied' : s.last.partial ? 'failed after the swap began' : 'refused';
    lines.push(`Last reload: ${s.last.at} (${s.last.trigger}), ${result}.`, reloader.formatOutcome(s.last));
  }
  return lines.join('\n');
}
