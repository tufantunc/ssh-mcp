import { z } from 'zod';
import { redactText } from '../guard/redactor.js';
import { remotePathForAudit, sanitizeRemotePath } from '../guard/sanitizer.js';
import { SftpClient } from '../ssh/sftp.js';
import { OVERWRITE_FLAG, payloadSuffix } from './audit-effects.js';
import { TOOL_DESCRIPTIONS as D } from './descriptions.js';
import { syntheticSuccess, textResult } from './results.js';
import type { ToolDeps, Pipeline } from './pipeline.js';

/**
 * SFTP transfer tools.
 *
 * Both paths go through `sanitizeRemotePath`, the same bar the streaming tools
 * hold — for the *path*.
 *
 * `sftp-upload` truncates an existing remote file unconditionally where
 * `sftp-upload-file` refuses unless `overwrite` is passed. What #223 changed is
 * that the approved string says so: before it named a destination and no effect,
 * and said nothing at all about the bytes, so two uploads to one path were one
 * string — one approval, one indistinguishable audit record. The behaviour is
 * unchanged on purpose: a default of `overwrite: false` would break every caller
 * that relies on replacement. `--overwrite` is therefore constant here, which does
 * mean it carries no per-call information — the per-call signal is `--bytes` and
 * `--sha256`. It stays because the sibling tool omits the flag when it will not
 * clobber, so an approver comparing the two needs its presence to mean something.
 *
 * `synthetic: true` skips `sanitizeCommand`, and these two interpolated
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
        // Constant, because this tool has no overwrite parameter — it always replaces.
        `sftp:upload ${remotePathForAudit(remotePath)}${OVERWRITE_FLAG}${payloadSuffix(content)}`,
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
            // utf8 bytes, matching the count the approved string already carries —
            // see `payloadSuffix` in audit-effects.ts for why `.length` is wrong.
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
