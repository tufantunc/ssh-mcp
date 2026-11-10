import { homedir, platform } from 'os';
import { join } from 'path';

/**
 * Where the server reads its config when `--config` does not say.
 *
 * In its own module so `windows-acl.ts` can name this path in its refusals: the loader
 * imports the ACL check, so the ACL check importing the loader back would be a cycle.
 * Depends only on `os` and `path` for the same reason.
 */
export function getConfigPath(customPath?: string): string {
  if (customPath) return customPath;

  const home = homedir();
  const p = platform();

  if (p === 'darwin') {
    return join(home, 'Library', 'Application Support', 'ssh-mcp', 'config.toml');
  }
  if (p === 'win32') {
    return join(process.env.APPDATA || join(home, 'AppData', 'Roaming'), 'ssh-mcp', 'config.toml');
  }
  const xdgConfig = process.env.XDG_CONFIG_HOME || join(home, '.config');
  return join(xdgConfig, 'ssh-mcp', 'config.toml');
}
