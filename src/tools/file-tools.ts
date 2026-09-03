import { z } from 'zod';
import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import { createReadStream, createWriteStream } from 'node:fs';
import { redactText } from '../guard/redactor.js';
import { sanitizeRemotePath } from '../guard/sanitizer.js';
import { SftpClient, type SftpListResult } from '../ssh/sftp.js';
import { TOOL_DESCRIPTIONS as D } from './descriptions.js';
import { syntheticSuccess, textResult } from './results.js';
import {
  createLocalDownload,
  localFileForRead,
  type LocalDownload,
  type LocalReadFile,
} from './local-path.js';
import type { ToolDeps, Pipeline } from './pipeline.js';

function renderListing(result: SftpListResult, maxBytes: number): string {
  const render = (count: number) => redactText(JSON.stringify({
    entries: result.entries.slice(0, count),
    returnedEntries: count,
    totalEntries: result.truncated ? null : result.entries.length,
    atLeastEntries: result.truncated ? result.entries.length + 1 : result.entries.length,
    truncated: result.truncated || count < result.entries.length,
  }), { entropyScan: true });

  let low = 0;
  let high = result.entries.length;
  let best = render(0);
  if (Buffer.byteLength(best, 'utf8') > maxBytes) {
    return maxBytes === 1 ? '0' : '{}';
  }
  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    const candidate = render(middle);
    if (Buffer.byteLength(candidate, 'utf8') <= maxBytes) {
      best = candidate;
      low = middle + 1;
    } else {
      high = middle - 1;
    }
  }
  return best;
}

function requestedLocalForAudit(path: string): string {
  return /[\u0000-\u001f\u007f-\u009f\u2028-\u202e\u2066-\u2069]/.test(path)
    ? '[invalid local path]'
    : path;
}

/** SFTP transfer tools. */
export function registerFileTools(
  { server, transferRoot, configPath }: ToolDeps,
  pipeline: Pipeline,
) {
  const { runAudited } = pipeline;
  const maxPreparedTransfers = 8;
  let preparedTransfers = 0;
  const reserveTransfer = () => {
    if (preparedTransfers >= maxPreparedTransfers) {
      throw new McpError(ErrorCode.InvalidRequest, 'Too many SFTP file transfers are awaiting approval or completion');
    }
    preparedTransfers++;
    let released = false;
    return () => {
      if (!released) preparedTransfers--;
      released = true;
    };
  };

  server.tool(
    'sftp-upload',
    D['sftp-upload'],
    {
      remotePath: z.string().min(1).describe('Remote file path'),
      content: z.string().describe('File content to upload'),
      profile: z.string().optional().describe('Profile name'),
    },
    { destructiveHint: true },
    async ({ remotePath, content, profile }, extra) => {
      const cleanRemote = sanitizeRemotePath(remotePath);
      return runAudited(
        `sftp:upload ${cleanRemote} overwrite=true mode=0600`,
        { toolName: 'sftp-upload', failureClass: 'destructive', profile, extra, synthetic: true },
        async (rt) => {
          await new SftpClient(rt.conn).upload({ remotePath: cleanRemote, content });
          return {
            audited: syntheticSuccess(rt.profileName),
            output: textResult(`Uploaded ${Buffer.byteLength(content)} bytes to ${cleanRemote}`),
          };
        },
      );
    },
  );

  server.tool(
    'sftp-download',
    D['sftp-download'],
    {
      remotePath: z.string().min(1).describe('Remote file path to download'),
      profile: z.string().optional().describe('Profile name'),
    },
    { readOnlyHint: true },
    async ({ remotePath, profile }, extra) => {
      const cleanRemote = sanitizeRemotePath(remotePath);
      return runAudited(
        `sftp:download ${cleanRemote}`,
        { toolName: 'sftp-download', failureClass: 'read-only', profile, extra, synthetic: true },
        async (rt) => {
          const data = await new SftpClient(rt.conn).download({ remotePath: cleanRemote });
          return {
            audited: syntheticSuccess(rt.profileName),
            output: textResult(redactText(data.toString('utf8'), { entropyScan: true })),
          };
        },
      );
    },
  );

  server.tool(
    'sftp-list',
    D['sftp-list'],
    {
      remotePath: z.string().min(1).describe('Remote directory path to list'),
      maxEntries: z.number().int().positive().max(10_000).optional().default(1_000)
        .describe('Maximum entries returned (default 1000, maximum 10000)'),
      profile: z.string().optional().describe('Profile name'),
    },
    { readOnlyHint: true },
    async ({ remotePath, maxEntries, profile }, extra) => {
      const cleanRemote = sanitizeRemotePath(remotePath);
      return runAudited(
        `sftp:list ${cleanRemote}`,
        { toolName: 'sftp-list', failureClass: 'read-only', profile, extra, synthetic: true },
        async (rt) => {
          const result = await new SftpClient(rt.conn).list(cleanRemote, maxEntries, {
            maxBytes: rt.conn.profile.maxOutputBytes,
            timeoutMs: rt.conn.profile.timeout,
            abortSignal: rt.abortSignal,
          });
          return {
            audited: syntheticSuccess(rt.profileName),
            output: textResult(renderListing(result, rt.conn.profile.maxOutputBytes)),
          };
        },
      );
    },
  );

  server.tool(
    'sftp-upload-file',
    D['sftp-upload-file'],
    {
      localPath: z.string().min(1).describe('File inside defaults.transferRoot to upload'),
      remotePath: z.string().min(1).describe('Remote destination path'),
      overwrite: z.boolean().optional().default(false).describe('Allow replacing an existing remote file'),
      profile: z.string().optional().describe('Profile name'),
    },
    { destructiveHint: true },
    async ({ localPath, remotePath, overwrite, profile }, extra) => {
      const cleanRemote = sanitizeRemotePath(remotePath);
      const requestedLocal = requestedLocalForAudit(localPath);
      let local: LocalReadFile | undefined;
      let releaseTransfer: (() => void) | undefined;
      try {
        return await runAudited(
          `sftp:upload-file ${requestedLocal} -> ${cleanRemote} overwrite=${overwrite} mode=0600`,
          {
            toolName: 'sftp-upload-file',
            failureClass: 'destructive',
            profile,
            extra,
            synthetic: true,
            prepareCommand: async (setCommand) => {
              releaseTransfer = reserveTransfer();
              local = await localFileForRead(transferRoot, localPath, configPath, (displayPath) => {
                setCommand(`sftp:upload-file ${displayPath} -> ${cleanRemote} overwrite=${overwrite} mode=0600`);
              });
              return `sftp:upload-file ${local.displayPath} -> ${cleanRemote} overwrite=${overwrite} mode=0600`;
            },
          },
          async (rt) => {
            if (!local) throw new Error('Local upload file was not prepared');
            if (local.size > rt.conn.profile.maxTransferBytes) {
              throw new Error(`Local upload exceeds the ${rt.conn.profile.maxTransferBytes} byte transfer limit`);
            }
            const bytes = await new SftpClient(rt.conn).uploadFile(
              createReadStream('', { fd: local.handle.fd, autoClose: false, emitClose: false }),
              cleanRemote,
              {
                maxBytes: rt.conn.profile.maxTransferBytes,
                timeoutMs: rt.conn.profile.timeout,
                abortSignal: rt.abortSignal,
                overwrite,
                mode: 0o600,
              },
            );
            return {
              audited: syntheticSuccess(rt.profileName),
              output: textResult(`Uploaded ${bytes} bytes from ${local.displayPath} to ${cleanRemote}`),
            };
          },
        );
      } finally {
        await local?.handle.close().catch(() => {});
        releaseTransfer?.();
      }
    },
  );

  server.tool(
    'sftp-download-file',
    D['sftp-download-file'],
    {
      remotePath: z.string().min(1).describe('Remote file path to download'),
      localPath: z.string().min(1).describe('Destination inside defaults.transferRoot'),
      overwrite: z.boolean().optional().default(false).describe('Allow replacing an existing local file'),
      profile: z.string().optional().describe('Profile name'),
    },
    { destructiveHint: true },
    async ({ remotePath, localPath, overwrite, profile }, extra) => {
      const cleanRemote = sanitizeRemotePath(remotePath);
      const requestedLocal = requestedLocalForAudit(localPath);
      let download: LocalDownload | undefined;
      let releaseTransfer: (() => void) | undefined;
      try {
        return await runAudited(
          `sftp:download-file ${cleanRemote} -> ${requestedLocal} overwrite=${overwrite}`,
          {
            toolName: 'sftp-download-file',
            failureClass: 'destructive',
            profile,
            extra,
            synthetic: true,
            prepareCommand: async (setCommand) => {
              releaseTransfer = reserveTransfer();
              download = await createLocalDownload(transferRoot, localPath, overwrite, configPath, (target) => {
                setCommand(`sftp:download-file ${cleanRemote} -> ${target.displayPath} overwrite=${overwrite}`);
              });
              return `sftp:download-file ${cleanRemote} -> ${download.target.displayPath} overwrite=${overwrite}`;
            },
          },
          async (rt) => {
            if (!download) throw new Error('Local download file was not prepared');
            const bytes = await new SftpClient(rt.conn).downloadFile(
              cleanRemote,
              createWriteStream('', { fd: download.handle.fd, autoClose: false, emitClose: false }),
              {
                maxBytes: rt.conn.profile.maxTransferBytes,
                timeoutMs: rt.conn.profile.timeout,
                abortSignal: rt.abortSignal,
              },
            );
            await download.publish();
            return {
              audited: syntheticSuccess(rt.profileName),
              output: textResult(`Downloaded ${bytes} bytes from ${cleanRemote} to ${download.target.displayPath}`),
            };
          },
        );
      } finally {
        await download?.cleanup();
        releaseTransfer?.();
      }
    },
  );
}
