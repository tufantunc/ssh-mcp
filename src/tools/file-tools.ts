import { z } from 'zod';
import { copyFile, stat, unlink } from 'node:fs/promises';
import { constants } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { redactText } from '../guard/redactor.js';
import { SftpClient } from '../ssh/sftp.js';
import { TOOL_DESCRIPTIONS as D } from './descriptions.js';
import { syntheticSuccess, textResult } from './results.js';
import { localFileForRead, localFileForWrite } from './local-path.js';
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

  // ─── sftp-list ─────────────────────────────────────────────────────────
  server.tool(
    'sftp-list',
    D['sftp-list'],
    {
      remotePath: z.string().describe('Remote directory path to list'),
      maxEntries: z.number().int().positive().max(10_000).optional().default(1_000)
        .describe('Maximum entries returned (default 1000, maximum 10000)'),
      profile: z.string().optional().describe('Profile name'),
    },
    { readOnlyHint: true },
    async ({ remotePath, maxEntries, profile }, extra) => {
      return runAudited(
        `sftp:list ${remotePath}`,
        { toolName: 'sftp-list', failureClass: 'read-only', profile, extra, synthetic: true },
        async (rt) => {
          const entries = await new SftpClient(rt.conn).list(remotePath);
          const rendered = JSON.stringify({
            entries: entries.slice(0, maxEntries),
            totalEntries: entries.length,
            truncated: entries.length > maxEntries,
          }, null, 2);
          if (Buffer.byteLength(rendered, 'utf8') > rt.conn.profile.maxOutputBytes) {
            throw new Error(
              `SFTP listing exceeds the ${rt.conn.profile.maxOutputBytes} byte output limit; lower maxEntries.`,
            );
          }
          return {
            audited: syntheticSuccess(rt.profileName),
            output: textResult(redactText(rendered)),
          };
        },
      );
    },
  );

  // ─── sftp-upload-file ──────────────────────────────────────────────────
  server.tool(
    'sftp-upload-file',
    D['sftp-upload-file'],
    {
      localPath: z.string().describe('File inside the MCP working directory to upload'),
      remotePath: z.string().describe('Remote destination path'),
      profile: z.string().optional().describe('Profile name'),
    },
    { destructiveHint: true },
    async ({ localPath, remotePath, profile }, extra) => {
      return runAudited(
        `sftp:upload-file ${remotePath}`,
        { toolName: 'sftp-upload-file', failureClass: 'destructive', profile, extra, synthetic: true },
        async (rt) => {
          const local = await localFileForRead(localPath);
          await new SftpClient(rt.conn).uploadFile(local.path, remotePath);
          return {
            audited: syntheticSuccess(rt.profileName),
            output: textResult(`Uploaded ${local.size} bytes from ${local.path} to ${remotePath}`),
          };
        },
      );
    },
  );

  // ─── sftp-download-file ────────────────────────────────────────────────
  server.tool(
    'sftp-download-file',
    D['sftp-download-file'],
    {
      remotePath: z.string().describe('Remote file path to download'),
      localPath: z.string().describe('Destination inside the MCP working directory'),
      overwrite: z.boolean().optional().default(false).describe('Allow replacing an existing local file'),
      profile: z.string().optional().describe('Profile name'),
    },
    { destructiveHint: true },
    async ({ remotePath, localPath, overwrite, profile }, extra) => {
      return runAudited(
        `sftp:download-file ${remotePath}`,
        { toolName: 'sftp-download-file', failureClass: 'destructive', profile, extra, synthetic: true },
        async (rt) => {
          const destination = await localFileForWrite(localPath, overwrite);
          const temporary = `${destination}.ssh-mcp-${randomUUID()}.part`;
          try {
            await new SftpClient(rt.conn).downloadFile(remotePath, temporary);
            await copyFile(
              temporary,
              destination,
              overwrite ? 0 : constants.COPYFILE_EXCL,
            );
          } finally {
            await unlink(temporary).catch(() => {});
          }
          const local = await stat(destination);
          return {
            audited: syntheticSuccess(rt.profileName),
            output: textResult(`Downloaded ${local.size} bytes from ${remotePath} to ${destination}`),
          };
        },
      );
    },
  );
}
