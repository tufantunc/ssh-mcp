/**
 * A remote path as a `[policy].denylist` pattern should also see it (#230).
 *
 * Lexical only: nothing is asked of the target, so a relative path stays relative and a
 * symlink is not followed. What it removes is the spelling that keeps a rule from seeing
 * a path it was written for — `//`, `/./`, `..`, a trailing separator — and it reads `\`
 * as a separator too, so a Windows target's `C:\Users\a\.ssh\authorized_keys` is also
 * seen as `C:/Users/a/.ssh/authorized_keys`. On a POSIX target a filename containing `\`
 * can then match where it did not before; that only ever widens a refusal.
 *
 * An absolute path — `/…`, or one starting with a drive letter — cannot climb above its
 * root. A relative path keeps a leading `..` it has nothing to resolve against.
 *
 * Not `node:path`: `posix.normalize` lets `..` climb above a drive root (`C:/../x` →
 * `x`) and keeps a trailing separator, and `win32.normalize` answers in backslashes —
 * while a deny rule needs one reading, in forward slashes, that never climbs.
 */
const DRIVE_LETTER = /^[A-Za-z]:$/;

export function normalizeRemotePath(path: string): string {
  const segments = path.replace(/\\/g, '/').split('/');
  let root: string | null = null;
  if (segments[0] === '') {
    root = '';
    segments.shift();
  } else if (DRIVE_LETTER.test(segments[0])) {
    root = segments.shift()!;
  }

  const kept: string[] = [];
  for (const segment of segments) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') {
      if (kept.length > 0 && kept[kept.length - 1] !== '..') kept.pop();
      else if (root === null) kept.push('..');
      continue;
    }
    kept.push(segment);
  }

  if (root === null) return kept.length > 0 ? kept.join('/') : '.';
  if (root === '') return kept.length > 0 ? `/${kept.join('/')}` : '/';
  return kept.length > 0 ? `${root}/${kept.join('/')}` : `${root}/`;
}

/**
 * The same path as Win32 would resolve it, for a denylist that must not depend on how
 * the caller spelled the file (#230).
 *
 * Every transformation here was measured over SFTP on the Windows test VM (Windows 11
 * build 26200): the spellings below reached the same file as the canonical one, so a
 * rule that caught one spelling and not the other was a bypass, not a distinction.
 *
 * - `\` is read as `/`, as above.
 * - A trailing run of dots and spaces is dropped from every segment (`authorized_keys.`
 *   and `authorized_keys..` are the same file). A segment that is nothing but dots
 *   (`a.../b`) therefore disappears, the way Win32 reads it.
 * - A `::` suffix is cut (`authorized_keys::$DATA` is the file's default stream, not a
 *   different file). A single `:` is left alone: that names a different stream, and the
 *   measurement showed it does not reach the same bytes.
 * - A drive-relative spelling (`C:x/…`, resolved against the drive's current directory
 *   on Windows) is rooted at the drive. Where it actually resolves depends on process
 *   state this server cannot see; rooting is the fail-closed reading.
 * - `\\?\` and `\\.\` device prefixes are dropped. SFTP itself rejects them, but a rule
 *   should not have to know that.
 * - A UNC spelling keeps its root (`\\server\share\…` → `//server/share/…`), which the
 *   plain reading collapses; `..` cannot climb above the share.
 *
 * Case is deliberately untouched — the engine tests this reading case-insensitively,
 * which also covers a case-variant spelling of an otherwise identical path.
 *
 * Two Windows equivalences remain outside any lexical reading, because resolving them
 * needs the target's own directory state, and are documented residuals in the README:
 * 8.3 short names (`AUTHOR~1`), and symlinks.
 *
 * On a POSIX target these readings can only widen a refusal: a file genuinely named
 * `authorized_keys.` is a different file there, but refusing it is the safe direction,
 * exactly as with `\` above.
 */
export function normalizeRemotePathForWindows(path: string): string {
  let slashed = path.replace(/\\/g, '/');
  if (slashed.startsWith('//?/') || slashed.startsWith('//./')) slashed = slashed.slice(4);

  const segments = slashed.split('/');
  let root: string | null = null;
  let rest = segments;
  if (segments[0] === '' && segments[1] === '') {
    // A UNC root: the share is as high as `..` may climb.
    root = `//${segments[2] ?? ''}/${segments[3] ?? ''}`;
    rest = segments.slice(4);
  } else if (segments[0] === '') {
    root = '/';
    rest = segments.slice(1);
  } else if (/^[A-Za-z]:/.test(segments[0])) {
    const drive = segments[0].slice(0, 2);
    const after = segments[0].slice(2);
    root = drive;
    rest = after === '' ? segments.slice(1) : [after, ...segments.slice(1)];
  }

  const kept: string[] = [];
  for (const segment of rest) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') {
      if (kept.length > 0 && kept[kept.length - 1] !== '..') kept.pop();
      else if (root === null) kept.push('..');
      continue;
    }
    const plain = segment.split('::')[0].replace(/[ .]+$/, '');
    if (plain === '') continue;
    kept.push(plain);
  }

  if (root === null) return kept.length > 0 ? kept.join('/') : '.';
  if (root === '/') return kept.length > 0 ? `/${kept.join('/')}` : '/';
  return kept.length > 0 ? `${root}/${kept.join('/')}` : `${root}/`;
}
