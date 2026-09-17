import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { getAuditLogPath } from '../audit/store.js';
import type { ForbiddenDir } from './local-path.js';

/**
 * Directories the transfer root must not overlap, beyond the two the gate
 * already derives for itself (the installation and the config directory).
 *
 * Its own module rather than a literal at the call site in index.ts, because
 * there the list sat inside `main()`'s body, which no test can reach — it is not
 * exported, and nothing short of starting the server evaluates it. So the list
 * was the one input to the transfer-root gate that nothing verified, while the
 * gate itself was thoroughly tested against whatever it was handed. (index.ts
 * does not run `main()` under test: the call is gated on SSH_MCP_DISABLE_MAIN,
 * which every test script sets. Unreachable, not unimportable.) The gate takes
 * the list as an argument precisely so that knowing where the audit log went is
 * somebody else's job — this is that somebody.
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
