import type { ClientChannel } from 'ssh2';

// ─── Config Types ───────────────────────────────────────────────────────────

export type AuthMethod = 'agent' | 'key' | 'password' | 'keychain';
export type HostKeyMode = 'tofu' | 'strict' | 'insecure';
export type ApprovalMode = 'auto' | 'ask-destructive' | 'ask-all' | 'deny';

export interface Profile {
  name: string;
  host: string;
  port: number;
  user: string;
  auth: AuthMethod;
  keyRef?: string;
  keychainEntry?: string;
  via?: string;
  workdir?: string;
  trustedHostKey?: string;
  hostFingerprint?: string;
  tty: boolean;
  timeout: number;
  maxChars: number;
  role: string;
  readOnly: boolean;
  approvalPolicy: ApprovalMode;
  cert: boolean;
  caFingerprint?: string;
  sessionMaxPerConnection: number;
  sessionIdleTimeoutMs: number;
}

export interface Defaults {
  defaultProfile?: string;
  sessionMaxPerConnection: number;
  sessionIdleTimeoutMs: number;
  sessionBackgroundMaxMs: number;
  commandTimeoutMs: number;
  commandMaxChars: number;
  commandMaxOutputBytes: number;
  connectionIdleReapMs: number;
  approvalMode: ApprovalMode;
}

export interface AppConfig {
  defaults: Defaults;
  profiles: Profile[];
}

// ─── SSH Connection Types ───────────────────────────────────────────────────

export type ConnectionStatus = 'pending' | 'connected' | 'reconnecting' | 'error' | 'closed';

export interface ConnectionInfo {
  profile: string;
  host: string;
  port: number;
  user: string;
  status: ConnectionStatus;
  sessionCount: number;
  activeChannels: number;
  connectedAt?: Date;
  lastActivity?: Date;
}

// ─── Session Types ──────────────────────────────────────────────────────────

export type SessionType = 'interactive' | 'background';
export type SessionStatus = 'active' | 'disconnected' | 'expired' | 'closed';

export interface SessionOpts {
  name: string;
  type: SessionType;
  command?: string;
  tty?: boolean;
  ttlMs?: number;
}

export interface SessionInfo {
  id: string;
  name: string;
  profile: string;
  type: SessionType;
  status: SessionStatus;
  cwd?: string;
  createdAt: Date;
  lastActivity: Date;
  ttlMs: number;
}

// ─── Command Types ──────────────────────────────────────────────────────────

export type CommandClass = 'read-only' | 'safe' | 'destructive' | 'privileged';

export interface ExecOpts {
  tty?: boolean;
  stdin?: string;
  timeoutMs?: number;
  profile?: string;
  session?: string;
  onProgress?: (bytesReceived: number, recentOutput: string) => void;
}

export interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  durationMs: number;
  cwd?: string;
  sessionId?: string;
  profile: string;
  signal?: string;
}

export interface ParsedCommand {
  binary: string;
  fullCommand: string;
  class: CommandClass;
}

// ─── Policy Types ───────────────────────────────────────────────────────────

export type PolicyDecision = 'allow' | 'deny' | 'require-approval';

export interface PolicyEvaluation {
  decision: PolicyDecision;
  commandClass: CommandClass;
  binary: string;
  ruleId?: string;
  reason?: string;
}

// ─── Credential Types ───────────────────────────────────────────────────────

export interface ResolvedCredentials {
  password?: string;
  privateKey?: string;
  certificate?: string;
  passphrase?: string;
  sudoPassword?: string;
  agentSocket?: string;
}

// ─── Audit Types ────────────────────────────────────────────────────────────

export interface AuditRecord {
  timestamp: string;
  eventId: string;
  mcpRequestId: string | number;
  profile: string;
  user: string;
  command: string;
  commandClass: CommandClass;
  binary: string;
  decision: PolicyDecision;
  exitCode?: number;
  durationMs?: number;
  bytesIn?: number;
  bytesOut?: number;
  sessionId?: string;
  approvalId?: string;
  approver?: string;
  error?: string;
}

// ─── Tool Types ─────────────────────────────────────────────────────────────

export interface ToolContext {
  requestId: string | number;
  profile?: string;
  session?: string;
  clientIdentity?: string;
}

// ─── SFTP Types ─────────────────────────────────────────────────────────────

export interface SftpUploadOpts {
  profile?: string;
  remotePath: string;
  content: string | Buffer;
  mode?: number;
}

export interface SftpDownloadOpts {
  profile?: string;
  remotePath: string;
}

export interface SftpStat {
  path: string;
  size: number;
  mode: number;
  isDirectory: boolean;
  isFile: boolean;
  mtime: Date;
  atime: Date;
}
