import { lstat, realpath, stat } from 'node:fs/promises';
import { dirname, isAbsolute, relative, resolve } from 'node:path';

function assertWithinRoot(root: string, candidate: string): void {
  const rel = relative(root, candidate);
  if (rel === '..' || rel.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) || isAbsolute(rel)) {
    throw new Error(`Local path must stay within the MCP working directory: ${root}`);
  }
}

/** Resolve an existing regular file and reject symlink/path traversal outside cwd. */
export async function localFileForRead(input: string): Promise<{ path: string; size: number }> {
  const root = await realpath(process.cwd());
  const candidate = await realpath(resolve(root, input));
  assertWithinRoot(root, candidate);
  const info = await stat(candidate);
  if (!info.isFile()) throw new Error(`Local path is not a regular file: ${input}`);
  return { path: candidate, size: info.size };
}

/** Resolve a destination whose real parent is inside cwd and enforce overwrite policy. */
export async function localFileForWrite(input: string, overwrite: boolean): Promise<string> {
  const root = await realpath(process.cwd());
  const candidate = resolve(root, input);
  const parent = await realpath(dirname(candidate));
  assertWithinRoot(root, parent);

  try {
    const info = await lstat(candidate);
    if (!overwrite) throw new Error(`Refusing to overwrite existing local file: ${input}`);
    // fastGet follows a final symlink. Rejecting it prevents an in-root name
    // from redirecting the write to an arbitrary path outside the root.
    if (info.isSymbolicLink()) throw new Error(`Refusing to overwrite a local symlink: ${input}`);
    if (!info.isFile()) throw new Error(`Local destination is not a regular file: ${input}`);
  } catch (err: any) {
    if (err?.code !== 'ENOENT') throw err;
  }

  return candidate;
}
