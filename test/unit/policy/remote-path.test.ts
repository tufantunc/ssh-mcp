import { describe, it, expect } from 'vitest';
import { normalizeRemotePath } from '../../../src/policy/remote-path.js';

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
    ['C:\\Users\\a\\.ssh\\authorized_keys', 'C:/Users/a/.ssh/authorized_keys'],
    ['C:\\Users\\a/.ssh\\..\\x', 'C:/Users/a/x'],
    ['C:/../x', 'C:/x'],
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
