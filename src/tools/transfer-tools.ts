import { z } from 'zod';
import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import { redactText } from '../guard/redactor.js';
import { sanitizeRemotePath } from '../guard/sanitizer.js';
import { SftpClient } from '../ssh/sftp.js';
import type { SftpStat } from '../types.js';
import { TOOL_DESCRIPTIONS as D } from './descriptions.js';
import { createLocalDownload, localFileForRead, type LocalPathContext } from './local-path.js';
import { syntheticSuccess, textResult } from './results.js';
import type { ToolDeps, Pipeline } from './pipeline.js';

/**
 * Upper bound on `maxEntries`, independent of what the caller asks for.
 *
 * The response is also capped in bytes by the profile's `maxOutputBytes`, so
 * this is not the thing that keeps a huge directory out of the model's context
 * — that bound does. This one keeps the *count* an argument cannot inflate, so
 * a caller cannot turn one tool call into an unbounded walk of a remote tree.
 */
const MAX_LIST_ENTRIES = 1000;
const DEFAULT_LIST_ENTRIES = 200;

/** rwx triples from the low nine bits, the way `ls -l` prints them. */
function renderPermissions(mode: number): string {
  const bits = 'rwxrwxrwx';
  let out = '';
  for (let i = 0; i < 9; i++) {
    out += (mode & (1 << (8 - i))) ? bits[i] : '-';
  }
  return out;
}

/**
 * The `ls -l` type character, from the mode's file-type bits.
 *
 * Read from the mode rather than from `isDirectory`/`isFile`, which between
 * them cover two of the seven types and report everything else as neither.
 * Measured against the test image's `/usr/bin`, where nearly every entry is a
 * symlink: a listing built from those two booleans rendered the whole directory
 * as `?`, which tells a model less than the raw filename did.
 */
function typeChar(mode: number): string {
  switch (mode & 0o170000) {
    case 0o040000: return 'd';
    case 0o100000: return '-';
    case 0o120000: return 'l';
    case 0o060000: return 'b';
    case 0o020000: return 'c';
    case 0o010000: return 'p';
    case 0o140000: return 's';
    default: return '?';
  }
}

function renderEntry(entry: SftpStat): string {
  const size = String(entry.size).padStart(12, ' ');
  return `${typeChar(entry.mode)}${renderPermissions(entry.mode)} ${size}  ${entry.mtime.toISOString()}  ${entry.path}`;
}

/**
 * Refuse a mode that grants authority the transfer itself does not carry.
 *
 * Everything above the low nine bits is setuid, setgid and the sticky bit. A
 * caller allowed to write a file is not thereby allowed to write one that runs
 * as its owner, and `uploadFile` passes this straight to the remote `open`.
 */
function checkMode(mode: number | undefined): number | undefined {
  if (mode === undefined) return undefined;
  if (!Number.isInteger(mode) || mode < 0 || mode > 0o777) {
    throw new McpError(
      ErrorCode.InvalidParams,
      'mode must be between 0 and 511 (0o777). setuid, setgid and the sticky bit are refused: ' +
      'uploading a file does not carry the authority to make it run as its owner.',
    );
  }
  return mode;
}

/**
 * Streaming SFTP tools: bounded directory listing, and transfers that move
 * between the remote host and local disk without passing through model context.
 *
 * The ordering inside each handler is the subject of #207 and is the reason
 * these are not simply three more entries in file-tools.ts. Nothing here
 * touches the local filesystem before the policy decision: the audited string
 * is built from the *remote* path, which `sanitizeRemotePath` validates without
 * any I/O, and every local effect — the existence check, the staged `.part`,
 * the operator-configuration errors the transfer-root gate produces — happens
 * inside `run()`, which the pipeline only reaches after the call is allowed and
 * approved. The resolved local path then reaches the audit record through
 * `refineCommand`.
 */
export function registerTransferTools(
  { server, localPath }: ToolDeps,
  pipeline: Pipeline,
) {
  const { runAudited } = pipeline;
  // Absent only when nothing was configured. The gate reads `transferRoot` and
  // refuses with the message that names the config key, which is the same
  // answer an operator who has a config but no root should get.
  const ctx: LocalPathContext = localPath ?? { transferRoot: undefined };

  // ─── sftp-list ─────────────────────────────────────────────────────────
  server.tool(
    'sftp-list',
    D['sftp-list'],
    {
      remotePath: z.string().describe('Remote directory to list'),
      maxEntries: z.number().int().min(1).max(MAX_LIST_ENTRIES).optional()
        .describe(`Max entries to return (default ${DEFAULT_LIST_ENTRIES}, hard cap ${MAX_LIST_ENTRIES})`),
      profile: z.string().optional().describe('Profile name'),
    },
    { readOnlyHint: true },
    async ({ remotePath, maxEntries, profile }, extra) => {
      const target = sanitizeRemotePath(remotePath);
      return runAudited(
        `sftp:list ${target}`,
        { toolName: 'sftp-list', failureClass: 'read-only', profile, extra, synthetic: true },
        async (rt) => {
          const { entries, truncated } = await new SftpClient(rt.conn).list(target, {
            maxEntries: maxEntries ?? DEFAULT_LIST_ENTRIES,
            // The listing is output headed for the model, so it is billed
            // against the same budget every other tool's output is.
            maxResponseBytes: rt.conn.profile.maxOutputBytes,
            idleTimeoutMs: rt.conn.profile.transferTimeoutMs,
            abortSignal: rt.abortSignal,
          });

          const body = entries.length
            ? entries.map(renderEntry).join('\n')
            : '(empty directory)';
          const note = truncated
            ? '\n\n[truncated: more entries exist than the entry or byte budget allowed]'
            : '';
          return {
            audited: syntheticSuccess(rt.profileName),
            // Filenames are remote, attacker-influenced content on their way
            // into model context, exactly like command output.
            output: textResult(redactText(body, { entropyScan: true }) + note),
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
      localPath: z.string().describe('Local file to upload, inside defaults.transferRoot'),
      remotePath: z.string().describe('Remote destination path'),
      overwrite: z.boolean().optional().describe('Replace an existing remote file (default false)'),
      mode: z.number().int().min(0).max(0o777).optional()
        .describe('Remote file mode, e.g. 420 for 0644. Defaults to 0600 for a new file, or the replaced file’s mode.'),
      profile: z.string().optional().describe('Profile name'),
    },
    { destructiveHint: true },
    async ({ localPath: source, remotePath, overwrite, mode, profile }, extra) => {
      const target = sanitizeRemotePath(remotePath);
      const fileMode = checkMode(mode);
      return runAudited(
        `sftp:upload-file ${target}`,
        { toolName: 'sftp-upload-file', failureClass: 'destructive', profile, extra, synthetic: true },
        async (rt) => {
          const maxBytes = rt.conn.profile.transferMaxBytes;
          const local = await localFileForRead(ctx, source);
          rt.refineCommand(`sftp:upload-file ${target} <- ${local.displayPath}`);
          try {
            // Checked here as well as inside the transfer, because the size is
            // already known: refusing before a byte moves beats refusing after
            // the cap is passed mid-stream and a remote `.part` has to be
            // cleaned up.
            if (local.size > maxBytes) {
              throw new McpError(
                ErrorCode.InvalidParams,
                `Local file is ${local.size} bytes, over this profile's ${maxBytes} byte transfer limit`,
              );
            }
            const bytes = await new SftpClient(rt.conn).uploadFile(
              local.handle.createReadStream({ autoClose: false }),
              target,
              {
                maxBytes,
                idleTimeoutMs: rt.conn.profile.transferTimeoutMs,
                abortSignal: rt.abortSignal,
                overwrite,
                mode: fileMode,
              },
            );
            return {
              audited: syntheticSuccess(rt.profileName),
              output: textResult(`Uploaded ${bytes} bytes from ${local.displayPath} to ${target}`),
            };
          } finally {
            await local.handle.close().catch(() => {});
          }
        },
      );
    },
  );

  // ─── sftp-download-file ────────────────────────────────────────────────
  server.tool(
    'sftp-download-file',
    D['sftp-download-file'],
    {
      remotePath: z.string().describe('Remote file to download'),
      localPath: z.string().describe('Local destination, inside defaults.transferRoot'),
      overwrite: z.boolean().optional().describe('Replace an existing local file (default false)'),
      profile: z.string().optional().describe('Profile name'),
    },
    { destructiveHint: true },
    async ({ remotePath, localPath: destination, overwrite, profile }, extra) => {
      const target = sanitizeRemotePath(remotePath);
      return runAudited(
        `sftp:download-file ${target}`,
        { toolName: 'sftp-download-file', failureClass: 'destructive', profile, extra, synthetic: true },
        async (rt) => {
          const download = await createLocalDownload(ctx, destination, overwrite ?? false);
          rt.refineCommand(`sftp:download-file ${target} -> ${download.target.displayPath}`);
          try {
            const bytes = await new SftpClient(rt.conn).downloadFile(
              target,
              download.createStream(),
              {
                maxBytes: rt.conn.profile.transferMaxBytes,
                idleTimeoutMs: rt.conn.profile.transferTimeoutMs,
                abortSignal: rt.abortSignal,
              },
            );
            await download.publish();
            return {
              audited: syntheticSuccess(rt.profileName),
              output: textResult(`Downloaded ${bytes} bytes from ${target} to ${download.target.displayPath}`),
            };
          } finally {
            // Always, and after publish(): destroying the stream closes the
            // handle, and publish() needs it open to sync(). On the failure
            // path this is what removes the staged `.part`.
            await download.cleanup();
          }
        },
      );
    },
  );
}
