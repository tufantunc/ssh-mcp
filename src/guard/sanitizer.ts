import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';

const CONTROL_CHARS = /[\r\n\u2028\u2029\x00]/g;

export function sanitizeCommand(command: unknown, maxChars: number): string {
  if (typeof command !== 'string') {
    throw new McpError(ErrorCode.InvalidParams, 'Command must be a string');
  }
  const trimmed = command.trim();
  if (!trimmed) {
    throw new McpError(ErrorCode.InvalidParams, 'Command cannot be empty');
  }
  if (Number.isFinite(maxChars) && trimmed.length > maxChars) {
    throw new McpError(ErrorCode.InvalidParams, `Command is too long (max ${maxChars} characters)`);
  }
  return trimmed;
}

export function sanitizeMetadata(value: unknown, maxLength = 500): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string') return undefined;
  const cleaned = value.replace(CONTROL_CHARS, ' ').trim();
  return cleaned.length > maxLength ? cleaned.slice(0, maxLength) : cleaned;
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
