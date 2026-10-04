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
  return `${root}/${kept.join('/')}`;
}
