import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { ElicitRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { registerTools, registerResources } from '../../../src/tools/registry.js';
import { PolicyEngine, DEFAULT_RULES } from '../../../src/policy/engine.js';
import { AuditStore } from '../../../src/audit/store.js';
import type { CommandResult, Profile } from '../../../src/types.js';

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
  execCalls: ExecCall[];
  auditRecords: any[];
  /** What the stubbed exec returns; override per test. */
  setExecResult(result: Partial<CommandResult>): void;
  /** Whether the client approves elicitation prompts. */
  setApproval(approve: boolean): void;
  /** How many times the client was actually prompted. */
  approvalPrompts(): number;
  close(): Promise<void>;
}

export async function createHarness(
  overrides: Partial<Profile> = {},
  toolOpts: { approvalGrantTtlMs?: number } = {},
): Promise<Harness> {
  const profile: Profile = { ...testProfile, ...overrides };
  const execCalls: ExecCall[] = [];
  const auditRecords: any[] = [];
  let approve = true;
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

  const conn: any = {
    profile,
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
    async closeSession(name: string) { sessions.delete(name); },
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

  const server = new McpServer({
    name: 'test', version: '0.0.0',
    capabilities: { tools: {}, resources: {} },
  });
  registerTools(server, registry, new PolicyEngine(DEFAULT_RULES), audit, toolOpts);
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
    execCalls,
    auditRecords,
    setExecResult(result) { execResult = result; },
    setApproval(value) { approve = value; },
    approvalPrompts: () => approvalPrompts,
    async close() { await client.close(); await server.close(); },
  };
}

/** Flatten a CallToolResult's text content. */
export function textOf(result: any): string {
  return (result.content ?? []).map((c: any) => c.text ?? '').join('\n');
}
