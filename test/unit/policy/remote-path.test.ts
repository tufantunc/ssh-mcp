import { describe, it, expect } from 'vitest';
import { normalizeRemotePath, normalizeRemotePathForWindows } from '../../../src/policy/remote-path.js';

describe('normalizeRemotePath', () => {
  it.each([
    ['/root//.ssh/authorized_keys', '/root/.ssh/authorized_keys'],
    ['/root/./.ssh/x', '/root/.ssh/x'],
    ['/srv/x/../../root/.ssh/authorized_keys', '/root/.ssh/authorized_keys'],
    ['/../etc/passwd', '/etc/passwd'],
    ['../../x', '../../x'],
    ['a/../../x', '../x'],
    ['/srv/data/', '/srv/data'],
    ['/', '/'],
    ['.', '.'],
    ['./', '.'],
    ['C:\\Users\\a\\.ssh\\authorized_keys', 'C:/Users/a/.ssh/authorized_keys'],
    ['C:\\Users\\a/.ssh\\..\\x', 'C:/Users/a/x'],
    ['C:/../x', 'C:/x'],
    ['C:', 'C:/'],
    // The `//` root of a UNC spelling collapses here; the Windows reading keeps it.
    ['\\\\server\\share\\pub\\file', '/server/share/pub/file'],
  ])('reads %s as %s', (input, expected) => {
    expect(normalizeRemotePath(input)).toBe(expected);
  });

  it.each(['/srv/backup.tar', '.ssh/authorized_keys', 'C:/Users/a', 'x'])(
    'returns an already-normal path unchanged: %s',
    (path) => {
      expect(normalizeRemotePath(path)).toBe(path);
    },
  );
});

describe('normalizeRemotePathForWindows', () => {
  // Every row is a spelling that reached the same file as the canonical one when
  // measured over SFTP on the Windows test VM (build 26200): case variants, trailing
  // dots and spaces, the `::$DATA` default-stream spelling, 8.3 names (kept as a
  // documented residual below), UNC roots and `.`/`//` segments. Case itself is left
  // to the engine, which tests this reading case-insensitively.
  it.each([
    ['C:\\Users\\a\\.ssh\\Authorized_Keys.', 'C:/Users/a/.ssh/Authorized_Keys'],
    ['/root/.ssh/authorized_keys..', '/root/.ssh/authorized_keys'],
    ['C:\\Users\\a\\.ssh\\authorized_keys ', 'C:/Users/a/.ssh/authorized_keys'],
    ['/root/.ssh/authorized_keys::$DATA', '/root/.ssh/authorized_keys'],
    ['C:x/../../Users/a/.ssh/authorized_keys', 'C:/Users/a/.ssh/authorized_keys'],
    ['C:Users/a/.ssh/authorized_keys', 'C:/Users/a/.ssh/authorized_keys'],
    ['\\\\server\\share\\root\\.ssh\\authorized_keys', '//server/share/root/.ssh/authorized_keys'],
    ['\\\\?\\C:\\Users\\a\\.ssh\\authorized_keys', 'C:/Users/a/.ssh/authorized_keys'],
    ['C:', 'C:/'],
    ['/root/.SSH/Authorized_Keys', '/root/.SSH/Authorized_Keys'],
    ['.ssh/authorized_keys.', '.ssh/authorized_keys'],
    ['/x/a.../b', '/x/a/b'],
  ])('reads %s as %s', (input, expected) => {
    expect(normalizeRemotePathForWindows(input)).toBe(expected);
  });
});
