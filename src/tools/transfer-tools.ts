import { z } from 'zod';
import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import { redactText } from '../guard/redactor.js';
import { remotePathForAudit, sanitizeRemotePath } from '../guard/sanitizer.js';
import { SftpClient } from '../ssh/sftp.js';
import type { SftpStat } from '../types.js';
import { TOOL_DESCRIPTIONS as D } from './descriptions.js';
import {
  createLocalDownload,
  localFileForRead,
  localPathForAudit,
  type LocalPathContext,
} from './local-path.js';
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

/**
 * rwx triples the way `ls -l` prints them, setuid/setgid/sticky included.
 *
 * Reading only the low nine bits renders `-rwsr-xr-x` as `-rwxr-xr-x`: a format
 * that imitates `ls -l` while dropping the only three bits that carry privilege.
 * An operator or a model deciding whether a remote file is safe to overwrite
 * could not see that it was setuid — which is precisely the precondition that
 * makes overwriting one dangerous.
 */
function renderPermissions(mode: number): string {
  const rwx = 'rwxrwxrwx';
  const out: string[] = [];
  for (let i = 0; i < 9; i++) out.push((mode & (1 << (8 - i))) ? rwx[i] : '-');

  // Each special bit replaces the x of its own triple, upper-case when that x is
  // not set — setuid without execute is `S`, with it `s`, as `ls` renders it.
  const special: [number, number, string][] = [
    [0o4000, 2, 's'],
    [0o2000, 5, 's'],
    [0o1000, 8, 't'],
  ];
  for (const [bit, at, char] of special) {
    if (mode & bit) out[at] = out[at] === 'x' ? char : char.toUpperCase();
  }
  return out.join('');
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

/** Width of an ISO timestamp, so the placeholder below keeps the columns aligned. */
const MTIME_WIDTH = 24;

/**
 * A remote mtime is optional on the wire, so it may be no date at all.
 *
 * ssh2 fills `attrs.mtime` only when the entry carries SSH_FILEXFER_ACMODTIME,
 * and `toSftpStat` turns a missing one into `new Date(NaN)`. `toISOString()`
 * throws `RangeError: Invalid time value` on that, inside the `map` that builds
 * the response — so a single entry from a server that omits the flag failed the
 * whole listing with an opaque error instead of returning the directory. The
 * mode fields already degrade rather than throw (`undefined & mask` is 0, which
 * renders as `?` and `---------`); this makes the timestamp behave the same way.
 */
function renderMtime(mtime: Date): string {
  return Number.isNaN(mtime.getTime()) ? '(no mtime)'.padStart(MTIME_WIDTH) : mtime.toISOString();
}

function renderEntry(entry: SftpStat): string {
  const size = String(entry.size).padStart(12, ' ');
  return `${typeChar(entry.mode)}${renderPermissions(entry.mode)} ${size}  ${renderMtime(entry.mtime)}  ${entry.path}`;
}

/**
 * Render the listing, stopping at the byte budget the caller's profile sets.
 *
 * `SftpClient.list` bills `filename + longname + 256` per retained entry, which
 * is a proxy for what a line costs and not the line itself: `entry.path` is the
 * directory joined to the filename, so the directory is repeated on every line
 * and the flat 256 never covered it. With a long remote path the rendered body
 * ran several times past the profile's `maxOutputBytes` while the layer that
 * believed it was enforcing the budget had spent a fraction of it.
 *
 * So the bound is applied to the bytes actually produced. The primitive's budget
 * still matters — it is what stops a hostile server's `longname` being retained
 * in memory — but the number the operator configured now describes the thing
 * they configured it for, which is what reaches the model.
 */
function renderListing(entries: SftpStat[], maxBytes: number): { body: string; truncated: boolean } {
  const lines: string[] = [];
  let bytes = 0;
  for (const entry of entries) {
    const line = renderEntry(entry);
    const cost = Buffer.byteLength(line, 'utf8') + 1;
    if (bytes + cost > maxBytes) return { body: lines.join('\n'), truncated: true };
    bytes += cost;
    lines.push(line);
  }
  return { body: lines.join('\n'), truncated: false };
}

/**
 * Refuse a mode that grants authority the transfer itself does not carry.
 *
 * Everything above the low nine bits is setuid, setgid and the sticky bit. A
 * caller allowed to write a file is not thereby allowed to write one that runs
 * as its owner, and `uploadFile` passes this straight to the remote `open`.
 *
 * `0` is refused rather than accepted. `uploadFile` reads it as "unset" through
 * an `||`, so a caller asking for mode 0 got 0600 — and on the overwrite path it
 * also suppressed the inherit-the-destination's-mode step, yielding neither the
 * mode asked for nor the one replaced. An argument silently rewritten is worse
 * than one refused.
 *
 * Runs as a `preCheck`, i.e. inside the pipeline, so a caller probing the
 * boundary leaves an audit record. The range is deliberately *not* duplicated as
 * a zod bound on the field: the SDK validates the schema before the handler is
 * entered, so a bound there refused a setuid mode outside the pipeline — no
 * audit record, and this message unreachable. Measured: with both in place, a
 * probe at 0o4755 produced no audit record at all.
 */
export function checkMode(mode: number | undefined): number | undefined {
  if (mode === undefined) return undefined;
  if (!Number.isInteger(mode) || mode < 1 || mode > 0o777) {
    throw new McpError(
      ErrorCode.InvalidParams,
      'mode must be between 1 and 511 (0o777), or omitted. setuid, setgid and the sticky bit ' +
      'are refused: uploading a file does not carry the authority to make it run as its owner. ' +
      '0 is refused because it is read as "unset" downstream rather than as a mode.',
    );
  }
  return mode;
}

/** The arguments that change what a transfer does, spelled for policy and the approver. */
function effectSuffix(overwrite: boolean | undefined, mode?: number): string {
  return (overwrite ? ' --overwrite' : '') + (mode !== undefined ? ` --mode=${mode.toString(8)}` : '');
}

/**
 * What the audit record adds once the local path has been resolved.
 *
 * Appended rather than substituted, and empty when the two agree. The refinement
 * has to satisfy the pipeline's append-only rule — the audited string may
 * elaborate what was approved, never replace it — and swapping `./sub/../x.bin`
 * for `x.bin` is a replacement, which `refineCommand` correctly threw on.
 *
 * Appending turns out to be the better record anyway: an auditor sees the
 * spelling the caller sent *and* the file it resolved to, so a divergence
 * between them is visible rather than silently normalised away.
 */
function resolvedSuffix(asked: unknown, resolved: string): string {
  return asked === resolved ? '' : ` (resolved ${resolved})`;
}

/**
 * Streaming SFTP tools: bounded directory listing, and transfers that move
 * between the remote host and local disk without passing through model context.
 *
 * Two orderings are load-bearing here, and both come from #207.
 *
 * **Nothing observable precedes the decision.** The audited string is built from
 * the caller's own spelling of both paths, through `remotePathForAudit` and
 * `localPathForAudit`, neither of which performs any I/O. Every local effect —
 * the existence check, the staged `.part`, the operator-configuration errors the
 * transfer-root gate produces — happens inside `run()`, which the pipeline
 * reaches only after the call is allowed and approved. The throwing validators
 * run as `preCheck`, inside the pipeline's own try, so a refused call still
 * leaves an audit record rather than letting a client probe the boundary
 * invisibly.
 *
 * **The decision is about the whole operation.** `overwrite` and `mode` change
 * what a call does — one destroys an existing remote file, the other sets its
 * permissions — so they belong in the string policy classifies, in the prompt a
 * human reads, and in the key an approval grant is remembered under. Left out,
 * one approval of a path covered every other spelling of the call.
 *
 * The resolved local path is then *appended* to the audit record through
 * `onResolved`, which the gate fires after confining the path and before it
 * stats or opens anything — so a refusal raised by the checks that follow is
 * audited with the resolution too, not only a success. Appended and not
 * substituted, because the pipeline's rule is that an audited string may be
 * elaborated and never replaced, and because an auditor is better served seeing
 * both the spelling that was approved and the file it resolved to.
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
      return runAudited(
        `sftp:list ${remotePathForAudit(remotePath)}`,
        {
          toolName: 'sftp-list',
          failureClass: 'read-only',
          profile,
          extra,
          synthetic: true,
          preCheck: () => { sanitizeRemotePath(remotePath); },
        },
        async (rt) => {
          const budget = rt.conn.profile.maxOutputBytes;
          const { entries, truncated } = await new SftpClient(rt.conn).list(remotePath, {
            maxEntries: maxEntries ?? DEFAULT_LIST_ENTRIES,
            // The listing is output headed for the model, so it is billed
            // against the same budget every other tool's output is.
            maxResponseBytes: budget,
            idleTimeoutMs: rt.conn.profile.transferTimeoutMs,
            abortSignal: rt.abortSignal,
          });

          const rendered = renderListing(entries, budget);
          const body = rendered.body || '(empty directory)';
          const note = truncated || rendered.truncated
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
      // The range is deliberately NOT declared here, only in `checkMode`. The SDK
      // validates this schema before the handler runs, so a zod bound refuses a
      // setuid mode *outside* the pipeline — no audit record, and the message
      // explaining why setuid is refused unreachable. A probe at a security
      // boundary that leaves no trace is the thing `preCheck` exists to prevent,
      // so the bound lives where the refusal can be logged. `.int()` stays,
      // because a non-integer is a type error rather than a probe.
      mode: z.number().int().optional()
        .describe('Remote file mode, 1 to 511 (0o777); setuid, setgid and the sticky bit are refused. e.g. 420 for 0644. Omit for 0600 on a new file, or the replaced file’s permission bits.'),
      profile: z.string().optional().describe('Profile name'),
    },
    { destructiveHint: true },
    async ({ localPath: source, remotePath, overwrite, mode, profile }, extra) => {
      const target = remotePathForAudit(remotePath);
      const approved =
        `sftp:upload-file ${target}${effectSuffix(overwrite, mode)} <- ${localPathForAudit(source)}`;
      return runAudited(
        approved,
        {
          toolName: 'sftp-upload-file',
          failureClass: 'destructive',
          profile,
          extra,
          synthetic: true,
          preCheck: () => { sanitizeRemotePath(remotePath); checkMode(mode); },
        },
        async (rt) => {
          const maxBytes = rt.conn.profile.transferMaxBytes;
          // Refined through `onResolved`, which the gate fires after confining
          // the path and before it stats or opens anything. Refining after the
          // call returned covered only the success path — every refusal the gate
          // itself raises (symlink source, outside the root, the root's own
          // misconfiguration) audited the caller's spelling instead.
          const local = await localFileForRead(ctx, source, (displayPath) => {
            rt.refineCommand(`${approved}${resolvedSuffix(source, displayPath)}`);
          });
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
              remotePath,
              {
                maxBytes,
                idleTimeoutMs: rt.conn.profile.transferTimeoutMs,
                abortSignal: rt.abortSignal,
                overwrite,
                mode,
              },
            );
            return {
              audited: syntheticSuccess(rt.profileName),
              output: textResult(`Uploaded ${bytes} bytes from ${local.displayPath} to ${remotePath}`),
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
      const target = remotePathForAudit(remotePath);
      const approved =
        `sftp:download-file ${target}${effectSuffix(overwrite)} -> ${localPathForAudit(destination)}`;
      return runAudited(
        approved,
        {
          toolName: 'sftp-download-file',
          failureClass: 'destructive',
          profile,
          extra,
          synthetic: true,
          preCheck: () => { sanitizeRemotePath(remotePath); },
        },
        async (rt) => {
          // As on the upload side, and for the same reason: refined before the
          // `.part` exists, so the overwrite and symlink refusals are audited
          // with the resolved destination, and a throw from `refineCommand`
          // itself cannot strand a staged file.
          const download = await createLocalDownload(ctx, destination, overwrite ?? false, (t) => {
            rt.refineCommand(`${approved}${resolvedSuffix(destination, t.displayPath)}`);
          });
          try {
            const bytes = await new SftpClient(rt.conn).downloadFile(
              remotePath,
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
              output: textResult(`Downloaded ${bytes} bytes from ${remotePath} to ${download.target.displayPath}`),
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
