import { z } from 'zod';
import { redactText } from '../guard/redactor.js';
import { remotePathForAudit, sanitizeRemotePath } from '../guard/sanitizer.js';
import { SftpClient } from '../ssh/sftp.js';
import { TOOL_DESCRIPTIONS as D } from './descriptions.js';
import { syntheticSuccess, textResult } from './results.js';
import type { ToolDeps, Pipeline } from './pipeline.js';

/**
 * SFTP transfer tools.
 *
 * Both paths go through `sanitizeRemotePath`, the same bar the streaming tools
 * hold. `synthetic: true` skips `sanitizeCommand`, and these two interpolated
 * the caller's raw string, so nothing refused a bidi override or a zero-width
 * character in a path that is quoted back in the approval prompt and written
 * into a hash-chained audit record — the exact confusion that validator exists
 * to stop. The check runs as a `preCheck`, inside the pipeline's try, so a
 * refused call still leaves an audit record.
 *
 * Pre-existing, and reachable before only by roles holding `safe`; lowering
 * `sftp:download` to `read-only` (#217) is what would have opened it to every
 * `readOnly` profile, so it is closed here rather than after.
 */
export function registerFileTools(
  { server }: ToolDeps,
  pipeline: Pipeline,
) {
  const { runAudited } = pipeline;

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
      return runAudited(
        `sftp:upload ${remotePathForAudit(remotePath)}`,
        {
          toolName: 'sftp-upload',
          failureClass: 'destructive',
          profile,
          extra,
          synthetic: true,
          preCheck: () => { sanitizeRemotePath(remotePath); },
        },
        async (rt) => {
          await new SftpClient(rt.conn).upload({ remotePath, content });
          return {
            audited: syntheticSuccess(rt.profileName),
            // Byte count, not string length: `content` is a JS string, so
            // `.length` counts UTF-16 code units and under-reports every
            // multi-byte character. SftpClient.upload writes Buffer.from(content),
            // which is utf8, so this is exactly what lands on the remote side.
            output: textResult(`Uploaded ${Buffer.byteLength(content, 'utf8')} bytes to ${remotePath}`),
          };
        },
      );
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
      return runAudited(
        `sftp:download ${remotePathForAudit(remotePath)}`,
        {
          toolName: 'sftp-download',
          failureClass: 'read-only',
          profile,
          extra,
          synthetic: true,
          preCheck: () => { sanitizeRemotePath(remotePath); },
        },
        async (rt) => {
          const data = await new SftpClient(rt.conn).download({ remotePath });
          return {
            audited: syntheticSuccess(rt.profileName),
            output: textResult(redactText(data.toString('utf8'), { entropyScan: true })),
          };
        },
      );
    },
  );
}
