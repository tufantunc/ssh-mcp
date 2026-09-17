import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { getAuditLogPath } from '../audit/store.js';
import type { ForbiddenDir } from './local-path.js';

/**
 * Directories the transfer root must not overlap, beyond the two the gate
 * already derives for itself (the installation and the config directory).
 *
 * Its own module rather than a literal at the call site in index.ts, because
 * index.ts runs `main()` on import and so cannot be tested: the list would have
 * been the one part of the transfer-root gate with no way to check that it
 * names what it claims to. The gate takes the list as an argument precisely so
 * that knowing where the audit log went is somebody else's job — this is that
 * somebody.
 *
 * Both entries are conventionally 0700 and owner-owned, so every privacy check
 * the gate applies accepts them. They have to be excluded by name:
 *
 * - a root containing the audit log lets a download replace the tamper-evident
 *   record of the transfer that wrote it;
 * - a root shaped like `~/.ssh` turns the same two tools into "read the private
 *   key" and "append to authorized_keys".
 */
export function transferForbiddenDirs(): ForbiddenDir[] {
  return [
    { path: dirname(getAuditLogPath()), reason: 'the audit log directory' },
    { path: join(homedir(), '.ssh'), reason: 'the SSH client directory (~/.ssh)' },
  ];
}
