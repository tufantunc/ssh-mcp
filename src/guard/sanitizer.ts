import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';

const CONTROL_CHARS = /[\r\n\u2028\u2029\x00]/g;
// Paths are rendered in approval prompts and audit tools. Reject terminal controls and
// bidi overrides as well as line breaks so a filename cannot disguise what is approved.
const PATH_CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f\u2028-\u202e\u2066-\u2069]/;

export function sanitizeCommand(command: unknown, maxChars: number): string {
  if (typeof command !== 'string') {
    throw new McpError(ErrorCode.InvalidParams, 'Command must be a string');
  }
  const cleaned = command.replace(CONTROL_CHARS, ' ').trim();
  if (!cleaned) {
    throw new McpError(ErrorCode.InvalidParams, 'Command cannot be empty');
  }
  if (Number.isFinite(maxChars) && cleaned.length > maxChars) {
    throw new McpError(ErrorCode.InvalidParams, `Command is too long (max ${maxChars} characters)`);
  }
  return cleaned;
}

export function sanitizeSessionName(name: string): string {
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(name)) {
    throw new McpError(
      ErrorCode.InvalidParams,
      'Session name must be 1-64 chars, alphanumeric/dash/underscore only',
    );
  }
  return name;
}

/** Validate an SFTP path without rewriting the remote filesystem operand. */
export function sanitizeRemotePath(path: unknown): string {
  if (typeof path !== 'string') {
    throw new McpError(ErrorCode.InvalidParams, 'Remote path must be a string');
  }
  if (!path.trim()) {
    throw new McpError(ErrorCode.InvalidParams, 'Remote path cannot be empty');
  }
  if (PATH_CONTROL_CHARS.test(path)) {
    throw new McpError(ErrorCode.InvalidParams, 'Remote path cannot contain control characters');
  }
  return path;
}

export function shellSingleQuote(s: string): string {
  return `'${s.replace(/'/g, "'\\''")}'`;
}
