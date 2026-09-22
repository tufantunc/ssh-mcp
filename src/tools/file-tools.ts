import { z } from 'zod';
import { redactText } from '../guard/redactor.js';
import { remotePathForAudit, sanitizeRemotePath } from '../guard/sanitizer.js';
import { SftpClient } from '../ssh/sftp.js';
import { effectSuffix, payloadSuffix } from './audit-effects.js';
import { TOOL_DESCRIPTIONS as D } from './descriptions.js';
import { syntheticSuccess, textResult } from './results.js';
import type { ToolDeps, Pipeline } from './pipeline.js';

/**
 * SFTP transfer tools.
 *
 * Both paths go through `sanitizeRemotePath`, the same bar the streaming tools
 * hold — for the *path*. `sftp-upload` still truncates an existing remote file
 * unconditionally where `sftp-upload-file` refuses unless `overwrite` is passed;
 * what changed with #223 is that the approved string now says so, and carries a
 * descriptor for the inline payload, so an approver is no longer shown a string
 * that means "will not clobber" on the sibling tool while approving an
 * unconditional replacement with bytes they were never shown. The behaviour is
 * unchanged on purpose: a default of `overwrite: false` would break every caller
 * that relies on replacement, and one of `true` would put `--overwrite` on almost
 * every call and train the approver to skip it. `synthetic: true` skips `sanitizeCommand`, and these two interpolated
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
      remotePath: z.string().describe('Remote file path. No leading or trailing whitespace, and no control, bidirectional or zero-width characters: the approval prompt and the audit record quote this path back.'),
      content: z.string().describe('File content to upload'),
      profile: z.string().optional().describe('Profile name'),
    },
    { destructiveHint: true },
    async ({ remotePath, content, profile }, extra) => {
      return runAudited(
        // `effectSuffix(true)` rather than a literal ' --overwrite': this tool
        // always replaces, and spelling it through the same helper the streaming
        // pair uses is what keeps the two vocabularies from drifting apart again.
        `sftp:upload ${remotePathForAudit(remotePath)}${effectSuffix(true)}${payloadSuffix(content)}`,
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
      remotePath: z.string().describe('Remote file path. No leading or trailing whitespace, and no control, bidirectional or zero-width characters: the approval prompt and the audit record quote this path back.'),
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
