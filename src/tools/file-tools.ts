import { z } from 'zod';
import { redactText } from '../guard/redactor.js';
import { SftpClient } from '../ssh/sftp.js';
import { TOOL_DESCRIPTIONS as D } from './descriptions.js';
import { syntheticSuccess, textResult } from './results.js';
import type { ToolDeps, Pipeline } from './pipeline.js';

/** SFTP transfer tools. */
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
        `sftp:upload ${remotePath}`,
        { toolName: 'sftp-upload', failureClass: 'destructive', profile, extra, synthetic: true },
        async (rt) => {
          await new SftpClient(rt.conn).upload({ remotePath, content });
          return {
            audited: syntheticSuccess(rt.profileName),
            output: textResult(`Uploaded ${content.length} bytes to ${remotePath}`),
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
        `sftp:download ${remotePath}`,
        { toolName: 'sftp-download', failureClass: 'read-only', profile, extra, synthetic: true },
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
