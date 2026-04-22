import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';

/**
 * Validate and trim a command string. Enforces maxChars if finite.
 * Shared by both transports so limit semantics are identical.
 */
export function sanitizeCommand(command: string, maxChars: number): string {
  if (typeof command !== 'string') {
    throw new McpError(ErrorCode.InvalidParams, 'Command must be a string');
  }

  const trimmedCommand = command.trim();
  if (!trimmedCommand) {
    throw new McpError(ErrorCode.InvalidParams, 'Command cannot be empty');
  }

  if (Number.isFinite(maxChars) && trimmedCommand.length > maxChars) {
    throw new McpError(
      ErrorCode.InvalidParams,
      `Command is too long (max ${maxChars} characters)`
    );
  }

  return trimmedCommand;
}

/**
 * Return undefined for empty/non-string; otherwise the raw password.
 * No content mutation, no logging.
 */
export function sanitizePassword(password: string | undefined): string | undefined {
  if (typeof password !== 'string') return undefined;
  if (password.length === 0) return undefined;
  return password;
}

/**
 * Escape a command for safe embedding inside a single-quoted POSIX shell
 * context on the remote side, e.g. `sh -c '<escaped>'`. Applies the canonical
 * `'\''` technique: close-quote, escape a single quote, re-open-quote.
 */
export function escapeCommandForShell(command: string): string {
  return command.replace(/'/g, "'\"'\"'");
}
