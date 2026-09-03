import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { ElicitRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { registerTools, registerResources } from '../../../src/tools/registry.js';
import { PolicyEngine, DEFAULT_RULES } from '../../../src/policy/engine.js';
import { AuditStore } from '../../../src/audit/store.js';
import type { CommandResult, Profile } from '../../../src/types.js';
import type { CloseOutcome } from '../../../src/ssh/session.js';
import { ConnectionRegistry } from '../../../src/ssh/connection-registry.js';
import { defaultsFromArgv } from '../../../src/cli.js';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable, Writable } from 'node:stream';

/**
 * In-process MCP client + server over InMemoryTransport, with the SSH layer
 * stubbed. The point is the handler layer — enforceClass, the approval gate,
 * output redaction, exit-status reporting and audit records — which is where
 * every per-request security decision lives and which had no tests at all.
 */

export const testProfile: Profile = {
  name: 'dev',
  group: 'dev',
  host: 'stub',
  port: 22,
  user: 'tester',
  auth: 'password',
  tty: false,
  timeout: 5000,
  maxChars: 5000,
  maxOutputBytes: 1_048_576,
  maxTransferBytes: 1_073_741_824,
  role: 'admin',
  readOnly: false,
  approvalPolicy: 'ask-destructive',
  cert: false,
  sessionMaxPerConnection: 5,
  sessionIdleTimeoutMs: 60_000,
  sessionBackgroundMaxMs: 3_600_000,
  commandQuotaPerDay: 0,
};

export interface ExecCall {
  command: string;
  stdin?: string;
}

export interface Harness {
  client: Client;
  transferRoot: string;
  execCalls: ExecCall[];
  auditRecords: any[];
  /** What the stubbed exec returns; override per test. */
  setExecResult(result: Partial<CommandResult>): void;
  /** Whether the client approves elicitation prompts. */
  setApproval(approve: boolean): void;
  /** How many times the client was actually prompted. */
  approvalPrompts(): number;
  /**
   * What `closeSession` reports; override per test.
   *
   * Configurable because the stub used to return `void`, so `outcome === 'unsignalled'` was
   * never true and the branch that warns the caller a stop was not dispatched was dead in
   * every unit test — including the ones written to cover it.
   */
  setCloseOutcome(outcome: CloseOutcome): void;
  close(): Promise<void>;
}

export async function createHarness(
  overrides: Partial<Profile> = {},
  toolOpts: { approvalGrantTtlMs?: number; transferRoot?: string; configPath?: string } = {},
): Promise<Harness> {
  const profile: Profile = { ...testProfile, ...overrides };
  const execCalls: ExecCall[] = [];
  const auditRecords: any[] = [];
  let approve = true;
  let closeOutcome: CloseOutcome = 'closed';
  let approvalPrompts = 0;
  let execResult: Partial<CommandResult> = {};

  const makeResult = (command: string): CommandResult => ({
    stdout: `stdout for ${command}`,
    stderr: '',
    exitCode: 0,
    durationMs: 1,
    profile: profile.name,
    ...execResult,
  });

  const sessions = new Map<string, any>();
  const remoteFiles = new Map<string, Buffer>();
  const transferRoot = toolOpts.transferRoot ?? await mkdtemp(join(tmpdir(), 'ssh-mcp-harness-'));
  const ownedTransferRoot = toolOpts.transferRoot === undefined;
  const directoryHandles = new Map<string, { entries: any[]; consumed: boolean }>();

  const sftp = {
    end() {},
    createWriteStream(remotePath: string) {
      const chunks: Buffer[] = [];
      return new Writable({
        write(chunk, _encoding, callback) { chunks.push(Buffer.from(chunk)); callback(); },
        final(callback) { remoteFiles.set(remotePath, Buffer.concat(chunks)); callback(); },
      });
    },
    createReadStream(remotePath: string) {
      const data = remoteFiles.get(remotePath);
      return data
        ? Readable.from(data)
        : new Readable({ read() { this.destroy(new Error(`No such remote file: ${remotePath}`)); } });
    },
    stat(remotePath: string, callback: (err?: Error, stats?: any) => void) {
      const data = remoteFiles.get(remotePath);
      if (!data) callback(Object.assign(new Error(`No such remote file: ${remotePath}`), { code: 2 }));
      else callback(undefined, { size: data.length, mode: 0o100644, mtime: 1, atime: 1 });
    },
    rename(source: string, destination: string, callback: (err?: Error) => void) {
      const data = remoteFiles.get(source);
      if (!data) callback(new Error(`No such remote file: ${source}`));
      else {
        remoteFiles.set(destination, data);
        remoteFiles.delete(source);
        callback();
      }
    },
    ext_openssh_rename(source: string, destination: string, callback: (err?: Error) => void) {
      this.rename(source, destination, callback);
    },
    ext_openssh_hardlink(source: string, destination: string, callback: (err?: Error) => void) {
      const data = remoteFiles.get(source);
      if (!data) callback(new Error(`No such remote file: ${source}`));
      else if (remoteFiles.has(destination)) callback(new Error(`Remote file exists: ${destination}`));
      else {
        remoteFiles.set(destination, data);
        callback();
      }
    },
    unlink(remotePath: string, callback: (err?: Error) => void) {
      remoteFiles.delete(remotePath);
      callback();
    },
    opendir(remotePath: string, callback: (err: Error | undefined, handle?: Buffer) => void) {
      const prefix = remotePath.endsWith('/') ? remotePath : `${remotePath}/`;
      const entries = [...remoteFiles.entries()]
        .filter(([path]) => path.startsWith(prefix))
        .map(([path, data]) => ({
          filename: path.slice(prefix.length),
          attrs: { size: data.length, mode: 0o100644, mtime: 1, atime: 1 },
        }));
      const id = `handle-${directoryHandles.size}`;
      directoryHandles.set(id, { entries, consumed: false });
      callback(undefined, Buffer.from(id));
    },
    readdir(handle: Buffer, callback: (err: any, entries?: any[]) => void) {
      const state = directoryHandles.get(handle.toString());
      if (!state) { callback(new Error('Invalid directory handle')); return; }
      if (state.consumed) { callback(Object.assign(new Error('EOF'), { code: 1 })); return; }
      state.consumed = true;
      callback(undefined, state.entries);
    },
    close(handle: Buffer, callback: (err?: Error) => void) {
      directoryHandles.delete(handle.toString());
      callback();
    },
  };

  const conn: any = {
    profile,
    async ensureConnected() {},
    getClient: () => ({ sftp: (callback: any) => callback(undefined, sftp) }),
    async exec(command: string, opts: any = {}) {
      execCalls.push({ command, stdin: opts.stdin });
      return makeResult(command);
    },
    getSudoPassword: () => 'sudo-secret',
    getSession: (name: string) => sessions.get(name),
    // Matches SSHConnection.listSessions(): Session objects, not SessionInfo —
    // the handler calls toInfo() itself.
    listSessions: () => [...sessions.values()],
    async openSession({ name, type }: any) {
      const session = {
        toInfo: () => ({ id: name, name, profile: profile.name, type, status: 'active', createdAt: new Date(), lastActivity: new Date(), ttlMs: 1000 }),
        run: async (command: string) => { execCalls.push({ command }); return makeResult(command); },
        readOutput: () => 'session output line',
      };
      sessions.set(name, session);
      return session;
    },
    async closeSession(name: string): Promise<CloseOutcome> {
      sessions.delete(name);
      return closeOutcome;
    },
    toInfo: () => ({
      profile: profile.name, host: profile.host, port: profile.port, user: profile.user,
      status: 'connected', sessionCount: sessions.size, activeChannels: 0,
    }),
  };

  const registry: any = {
    getOrCreate: async () => conn,
    get: () => conn,
    getProfile: () => profile,
    listConnections: () => [conn.toInfo()],
    listAllProfiles: () => [profile],
  };

  // Capture audit records instead of writing to disk.
  const audit = { record: async (r: any) => { auditRecords.push(r); } } as unknown as AuditStore;

  const server = new McpServer(
    { name: 'test', version: '0.0.0' },
    { capabilities: { tools: {}, resources: {} } },
  );
  registerTools(server, registry, new PolicyEngine(DEFAULT_RULES), audit, { ...toolOpts, transferRoot });
  registerResources(server, registry);

  const client = new Client(
    { name: 'test-client', version: '0.0.0' },
    { capabilities: { elicitation: {} } },
  );
  // Stand in for the human at the approval prompt.
  client.setRequestHandler(ElicitRequestSchema, async () => {
    approvalPrompts++;
    return approve ? { action: 'accept', content: { confirm: true } } : { action: 'decline' };
  });

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

  return {
    client,
    transferRoot,
    execCalls,
    auditRecords,
    setExecResult(result) { execResult = result; },
    setApproval(value) { approve = value; },
    setCloseOutcome(outcome) { closeOutcome = outcome; },
    approvalPrompts: () => approvalPrompts,
    async close() {
      await client.close();
      await server.close();
      if (ownedTransferRoot) await rm(transferRoot, { recursive: true, force: true });
    },
  };
}

/**
 * The same handler layer, wired to a real `ConnectionRegistry` that has no profiles.
 *
 * A real registry rather than a stub, because the thing under test is the guard inside it
 * and a stub would only re-state the expectation. What this adds over the e2e probe is the
 * audit store: a refused tool call has to leave a record, and for eight of the eleven tools
 * it did not — the profile was resolved above `runAudited`'s try, so the `OperatorError`
 * escaped before `auditFailure` could see it, and an operator watching an unconfigured
 * server get probed saw an empty log rather than the probing.
 */
export async function createUnconfiguredHarness(): Promise<Pick<Harness, 'client' | 'auditRecords' | 'close'>> {
  const auditRecords: any[] = [];
  const registry = new ConnectionRegistry({ defaults: defaultsFromArgv({}), profiles: [] });
  const audit = { record: async (r: any) => { auditRecords.push(r); } } as unknown as AuditStore;

  const server = new McpServer(
    { name: 'test', version: '0.0.0' },
    { capabilities: { tools: {}, resources: {} } },
  );
  registerTools(server, registry, new PolicyEngine(DEFAULT_RULES), audit, {});
  registerResources(server, registry);

  const client = new Client({ name: 'test-client', version: '0.0.0' }, { capabilities: {} });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

  return {
    client,
    auditRecords,
    async close() { await client.close(); await server.close(); },
  };
}

/** Flatten a CallToolResult's text content. */
export function textOf(result: any): string {
  return (result.content ?? []).map((c: any) => c.text ?? '').join('\n');
}
