import { randomUUID } from 'node:crypto';
import { constants, realpath as realpathCb } from 'node:fs';
import { open, lstat, rename, link, unlink, stat } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { platform } from 'node:os';
import { basename, dirname, isAbsolute, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import { isWithinRoot, pathsOverlap } from '../config/path-containment.js';

const INSTALL_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;
const PATH_CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f\u2028-\u202e\u2066-\u2069]/;

/**
 * `fs.promises.realpath` does not expand Windows 8.3 short names, so two
 * spellings of one path can compare unequal. The native binding does. On POSIX
 * the two behave alike, so this is the safe default everywhere rather than a
 * platform branch that only ever gets exercised on one OS.
 */
const realpath = promisify(realpathCb.native);

/** A directory the transfer root must not overlap, with the reason to report. */
export interface ForbiddenDir {
  path: string;
  reason: string;
}

/** Everything the local-path gate needs that does not come from the caller. */
export interface LocalPathContext {
  transferRoot: string | undefined;
  configPath?: string;
  forbidden?: readonly ForbiddenDir[];
}

export interface LocalReadFile {
  handle: FileHandle;
  size: number;
  displayPath: string;
}

export interface LocalWriteTarget {
  destination: string;
  displayPath: string;
  parent: string;
}

export interface LocalDownload {
  handle: FileHandle;
  temporary: string;
  target: LocalWriteTarget;
  publish(): Promise<void>;
  cleanup(): Promise<void>;
}

/**
 * The root in both spellings. Containment decisions use `canonical`; a caller's
 * absolute path is additionally allowed to be spelled against `configured`,
 * because that is how an operator's shell shows it.
 */
interface ResolvedRoot {
  configured: string;
  canonical: string;
}

function invalid(message: string): never {
  throw new McpError(ErrorCode.InvalidParams, message);
}

function validateInput(input: string): void {
  if (!input.trim()) invalid('Local path cannot be empty');
  if (PATH_CONTROL_CHARS.test(input)) {
    invalid('Local path cannot contain control or bidi formatting characters');
  }
}

function display(root: string, candidate: string): string {
  const value = relative(root, candidate);
  return value || '.';
}

function confined(root: string, candidate: string): void {
  if (!isWithinRoot(root, candidate)) invalid('Local path must stay within defaults.transferRoot');
}

async function assertPrivateTransferRoot(root: string): Promise<void> {
  const info = await stat(root);
  const uid = process.getuid?.();
  if (uid !== undefined && info.uid !== uid) {
    invalid('defaults.transferRoot must be owned by the SSH MCP account');
  }
  if ((info.mode & 0o077) !== 0) {
    invalid('defaults.transferRoot permissions must be 0700');
  }

  // A writable ancestor could replace the root between realpath() and open(). Sticky
  // directories such as /tmp are safe for an owner-controlled child and are allowed.
  let child = root;
  for (let parent = dirname(root); parent !== child; child = parent, parent = dirname(parent)) {
    const parentInfo = await stat(parent);
    if (uid !== undefined && parentInfo.uid !== uid && parentInfo.uid !== 0) {
      invalid('defaults.transferRoot has a parent owned by an untrusted account');
    }
    const writableByOthers = (parentInfo.mode & 0o022) !== 0;
    const sticky = (parentInfo.mode & 0o1000) !== 0;
    if (writableByOthers && !sticky) {
      invalid('defaults.transferRoot has an unsafe writable parent directory');
    }
  }
}

async function configuredRoot(ctx: LocalPathContext): Promise<ResolvedRoot> {
  // Windows is refused outright rather than verified with the config-file ACL
  // posture, which waives a read-exposed directory, never reads the `O:` owner,
  // and treats a missing or slow `icacls.exe` as a pass. A transfer root that
  // cannot be verified must disable the tools, not enable them.
  if (platform() === 'win32') {
    invalid(
      'Streaming SFTP file tools are not available on Windows: the transfer root cannot yet ' +
      'be verified private there, and an unverifiable root would leave every downloaded file ' +
      'readable by other accounts on the machine.',
    );
  }

  const input = ctx.transferRoot;
  if (!input) invalid('Streaming SFTP file tools require defaults.transferRoot in config.toml');
  if (!isAbsolute(input)) invalid('defaults.transferRoot must be an absolute path');

  let canonical: string;
  try {
    canonical = await realpath(input);
  } catch {
    invalid('defaults.transferRoot is not an accessible directory');
  }
  const info = await stat(canonical);
  if (!info.isDirectory()) invalid('defaults.transferRoot must name a directory');

  const install = await realpath(INSTALL_DIR);
  if (pathsOverlap(canonical, install)) {
    invalid('defaults.transferRoot must be separate from the SSH MCP installation');
  }
  if (ctx.configPath) {
    let configDir: string;
    try {
      configDir = dirname(await realpath(resolve(ctx.configPath)));
    } catch {
      invalid('The SSH MCP config directory cannot be resolved safely');
    }
    if (pathsOverlap(canonical, configDir)) {
      invalid('defaults.transferRoot must be separate from the SSH MCP config directory');
    }
  }

  // The install and config directories are not the only sensitive ones. A root
  // containing the audit log lets a download replace the tamper-evident record
  // of the transfer that wrote it, and a root shaped like ~/.ssh turns the same
  // tools into "read the private key" and "append to authorized_keys". Both are
  // conventionally 0700 and owner-owned, so the privacy checks above accept
  // them; they have to be excluded by name.
  for (const entry of ctx.forbidden ?? []) {
    let forbidden: string;
    try {
      forbidden = await realpath(entry.path);
    } catch {
      // A directory that does not exist yet cannot contain the root, but its
      // lexical form still can once it is created.
      forbidden = resolve(entry.path);
    }
    if (pathsOverlap(canonical, forbidden)) {
      invalid(`defaults.transferRoot must be separate from ${entry.reason}`);
    }
  }

  await assertPrivateTransferRoot(canonical);
  return { configured: resolve(input), canonical };
}

/**
 * Make a caller's path comparable to the canonical root without touching the
 * filesystem outside it.
 *
 * `resolve(root, input)` ignores `root` entirely when `input` is absolute, so a
 * legitimate absolute path spelled the way a shell shows it — macOS `/var/...`
 * for a root canonicalized to `/private/var/...` — is not yet comparable. The
 * previous shape confined this lexical form immediately and therefore refused
 * those outright, on every host whose transfer root sits behind a symlink.
 *
 * Accepting either spelling fixes that. The check stays lexical so that a path
 * outside the root is refused before anything stats it, which is what keeps
 * these tools from answering "does this file exist?" for arbitrary paths.
 */
function lexicalCandidate(root: ResolvedRoot, input: string): string {
  const candidate = resolve(root.canonical, input);
  if (isWithinRoot(root.canonical, candidate)) return candidate;
  if (isWithinRoot(root.configured, candidate)) return candidate;
  invalid('Local path must stay within defaults.transferRoot');
}

/** Open an existing regular file once, so the transfer never re-resolves its path. */
export async function localFileForRead(
  ctx: LocalPathContext,
  input: string,
  onResolved?: (displayPath: string) => void,
): Promise<LocalReadFile> {
  try {
    validateInput(input);
    const root = await configuredRoot(ctx);
    const lexical = lexicalCandidate(root, input);

    // Canonicalize the parent before the leaf: the leaf may be a symlink that
    // has to be refused rather than followed, and its own realpath would hide
    // that. Confining the parent first also means the leaf is only ever lstat'd
    // once it is known to be inside the root.
    const parent = await realpath(dirname(lexical));
    confined(root.canonical, parent);
    const candidate = resolve(parent, basename(lexical));
    confined(root.canonical, candidate);
    onResolved?.(display(root.canonical, candidate));

    if ((await lstat(candidate)).isSymbolicLink()) {
      invalid(`Local upload source cannot be a symlink: ${input}`);
    }
    const real = await realpath(candidate);
    confined(root.canonical, real);

    const handle = await open(real, constants.O_RDONLY | NO_FOLLOW);
    try {
      const info = await handle.stat();
      if (!info.isFile()) invalid(`Local path is not a regular file: ${input}`);
      return { handle, size: info.size, displayPath: display(root.canonical, real) };
    } catch (err) {
      await handle.close().catch(() => {});
      throw err;
    }
  } catch (err) {
    if (err instanceof McpError) throw err;
    invalid(`Local upload source is not an accessible regular file: ${input}`);
  }
}

/** Resolve a destination through its real parent and enforce overwrite policy. */
export async function localFileForWrite(
  ctx: LocalPathContext,
  input: string,
  overwrite: boolean,
  onResolved?: (target: LocalWriteTarget) => void,
): Promise<LocalWriteTarget> {
  try {
    validateInput(input);
    const root = await configuredRoot(ctx);
    const lexical = lexicalCandidate(root, input);

    const parent = await realpath(dirname(lexical));
    confined(root.canonical, parent);
    const destination = resolve(parent, basename(lexical));
    confined(root.canonical, destination);
    const target = { destination, displayPath: display(root.canonical, destination), parent };
    onResolved?.(target);

    try {
      const info = await lstat(destination);
      if (!overwrite) invalid(`Refusing to overwrite existing local file: ${input}`);
      if (info.isSymbolicLink()) invalid(`Refusing to overwrite a local symlink: ${input}`);
      if (!info.isFile()) invalid(`Local destination is not a regular file: ${input}`);
    } catch (err: any) {
      if (err?.code !== 'ENOENT') throw err;
    }

    return target;
  } catch (err) {
    if (err instanceof McpError) throw err;
    invalid(`Local download destination is not accessible: ${input}`);
  }
}

async function assertParentUnchanged(target: LocalWriteTarget): Promise<void> {
  let currentParent: string;
  try {
    currentParent = await realpath(dirname(target.destination));
  } catch {
    invalid('Local destination parent changed during transfer');
  }
  if (currentParent !== target.parent) invalid('Local destination parent changed during transfer');
}

/** Create a same-directory temporary file and publish it atomically. */
export async function createLocalDownload(
  ctx: LocalPathContext,
  input: string,
  overwrite: boolean,
  onResolved?: (target: LocalWriteTarget) => void,
): Promise<LocalDownload> {
  const target = await localFileForWrite(ctx, input, overwrite, onResolved);
  await assertParentUnchanged(target);
  const temporary = resolve(target.parent, `.ssh-mcp-download-${randomUUID()}.part`);
  let handle: FileHandle;
  try {
    handle = await open(
      temporary,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NO_FOLLOW,
      0o600,
    );
  } catch {
    invalid('Local download temporary file could not be created safely');
  }
  let published = false;

  return {
    handle,
    temporary,
    target,
    async publish() {
      await assertParentUnchanged(target);
      try {
        await handle.sync();
        if (overwrite) {
          await rename(temporary, target.destination);
          published = true;
        } else {
          // link() fails with EEXIST rather than clobbering, which is the
          // no-overwrite guarantee; the temporary is unlinked afterwards.
          await link(temporary, target.destination);
          published = true;
          await unlink(temporary).catch(() => {
            console.error('Warning: an SFTP download was published but its stale .part hard link could not be removed');
          });
        }
      } catch (err: any) {
        if (err?.code === 'EEXIST') invalid('Refusing to overwrite a local file created during transfer');
        throw new McpError(ErrorCode.InternalError, 'Local download could not be published safely');
      }
      try {
        const parentHandle = await open(target.parent, constants.O_RDONLY);
        try { await parentHandle.sync(); } finally { await parentHandle.close(); }
      } catch {
        console.error('Warning: SFTP download was published, but its directory metadata could not be synced');
      }
    },
    async cleanup() {
      await handle.close().catch(() => {});
      if (!published) {
        await unlink(temporary).catch((err: any) => {
          console.error(
            err?.code === 'ENOENT'
              ? 'Warning: an unpublished SFTP temporary file is no longer reachable; check transferRoot for stale .part files'
              : 'Warning: an unpublished SFTP temporary file could not be removed; check transferRoot for stale .part files',
          );
        });
      }
    },
  };
}
