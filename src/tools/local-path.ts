import { randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { open, lstat, realpath, rename, link, unlink, stat } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { platform } from 'node:os';
import { basename, dirname, isAbsolute, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import { isWithinRoot, pathsOverlap } from '../config/path-containment.js';
import { assertPrivateOnWindows } from '../config/windows-acl.js';

const INSTALL_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;
const PATH_CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f\u2028-\u202e\u2066-\u2069]/;

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

async function assertParentUnchanged(target: LocalWriteTarget): Promise<void> {
  let currentParent: string;
  try {
    currentParent = await realpath(dirname(target.destination));
  } catch {
    invalid('Local destination parent changed during transfer');
  }
  if (currentParent !== target.parent) invalid('Local destination parent changed during transfer');
}

function invalid(message: string): never {
  throw new McpError(ErrorCode.InvalidParams, message);
}

function validateInput(input: string): void {
  if (!input.trim()) invalid('Local path cannot be empty');
  if (PATH_CONTROL_CHARS.test(input)) invalid('Local path cannot contain control or bidi formatting characters');
}

async function assertPrivateTransferRoot(root: string): Promise<void> {
  if (platform() === 'win32') {
    try {
      await assertPrivateOnWindows(root);
    } catch {
      invalid('defaults.transferRoot must not be writable by other accounts');
    }
    return;
  }

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

function display(root: string, candidate: string): string {
  const value = relative(root, candidate);
  return value || '.';
}

async function configuredRoot(input: string | undefined, configPath?: string): Promise<string> {
  if (!input) invalid('Streaming SFTP file tools require defaults.transferRoot in config.toml');
  if (!isAbsolute(input)) invalid('defaults.transferRoot must be an absolute path');

  let root: string;
  try {
    root = await realpath(input);
  } catch {
    invalid('defaults.transferRoot is not an accessible directory');
  }
  const info = await stat(root!);
  if (!info.isDirectory()) invalid('defaults.transferRoot must name a directory');

  const install = await realpath(INSTALL_DIR);
  if (pathsOverlap(root!, install)) {
    invalid('defaults.transferRoot must be separate from the SSH MCP installation');
  }
  if (configPath) {
    let configDir: string;
    try {
      const canonicalConfig = await realpath(resolve(configPath));
      configDir = dirname(canonicalConfig);
    } catch {
      invalid('The SSH MCP config directory cannot be resolved safely');
    }
    if (pathsOverlap(root!, configDir)) {
      invalid('defaults.transferRoot must be separate from the SSH MCP config directory');
    }
  }
  await assertPrivateTransferRoot(root!);
  return root!;
}

function confined(root: string, candidate: string): void {
  if (!isWithinRoot(root, candidate)) invalid('Local path must stay within defaults.transferRoot');
}

/** Open an existing regular file once, so the transfer never re-resolves its path. */
export async function localFileForRead(
  transferRoot: string | undefined,
  input: string,
  configPath?: string,
  onResolved?: (displayPath: string) => void,
): Promise<LocalReadFile> {
  try {
    validateInput(input);
    const root = await configuredRoot(transferRoot, configPath);
    const lexical = resolve(root, input);
    confined(root, lexical);
    onResolved?.(display(root, lexical));
    if ((await lstat(lexical)).isSymbolicLink()) {
      invalid(`Local upload source cannot be a symlink: ${input}`);
    }
    const candidate = await realpath(lexical);
    confined(root, candidate);

    const handle = await open(candidate, constants.O_RDONLY | NO_FOLLOW);
    try {
      const info = await handle.stat();
      if (!info.isFile()) invalid(`Local path is not a regular file: ${input}`);
      return { handle, size: info.size, displayPath: display(root, candidate) };
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
  transferRoot: string | undefined,
  input: string,
  overwrite: boolean,
  configPath?: string,
  onResolved?: (target: LocalWriteTarget) => void,
): Promise<LocalWriteTarget> {
  try {
    validateInput(input);
    const root = await configuredRoot(transferRoot, configPath);
    const lexical = resolve(root, input);
    confined(root, lexical);
    const parent = await realpath(dirname(lexical));
    confined(root, parent);
    const destination = resolve(parent, basename(lexical));
    confined(root, destination);
    const target = { destination, displayPath: display(root, destination), parent };
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

/** Create a same-directory temporary file and publish it atomically. */
export async function createLocalDownload(
  transferRoot: string | undefined,
  input: string,
  overwrite: boolean,
  configPath?: string,
  onResolved?: (target: LocalWriteTarget) => void,
): Promise<LocalDownload> {
  const target = await localFileForWrite(transferRoot, input, overwrite, configPath, onResolved);
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
      if (platform() !== 'win32') {
        try {
          const parentHandle = await open(target.parent, constants.O_RDONLY);
          try { await parentHandle.sync(); } finally { await parentHandle.close(); }
        } catch {
          console.error('Warning: SFTP download was published, but its directory metadata could not be synced');
        }
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
