import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { ElicitRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { mkdtemp, writeFile, chmod, rm } from 'fs/promises';
import { existsSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import { checkAllServers, allServersUp, PORTS } from '../integration/fixtures.js';
import { SSH_HOST, assertAvailable } from '../integration/helpers.js';

/**
 * End-to-end: the built server binary, driven over a real stdio transport by a
 * real MCP SDK client, against the real SSH servers in docker-compose.
 *
 * Nothing is stubbed. The handler tests in test/unit/tools cover the same
 * decisions in-process; what this adds is the process boundary, real JSON-RPC
 * serialisation, real config-file loading and a real SSH connection — the parts
 * a client actually exercises and an in-process harness cannot prove.
 */

export const SERVER_ENTRY = resolve(import.meta.dirname, '../../build/index.js');
const REPO_ROOT = resolve(import.meta.dirname, '../..');

/** The suite needs a current build; a stale or missing one would test nothing. */
export const serverBuilt = existsSync(SERVER_ENTRY);

export async function e2eAvailable(): Promise<boolean> {
  // A missing build must not quietly skip: these tests exist to exercise the
  // built artifact, so in CI (SSH_MCP_REQUIRE_SERVERS=1) that is a failure.
  assertAvailable(serverBuilt, `build missing at ${SERVER_ENTRY} — run npm run build`);
  return serverBuilt && allServersUp(await checkAllServers());
}

export interface E2EClient {
  client: Client;
  /** Prompts the server sent to the client (approval requests). */
  prompts: string[];
  /** Whether the client accepts approval prompts; flip per test. */
  setApproval(accept: boolean): void;
  callTool(name: string, args?: Record<string, unknown>): Promise<any>;
  close(): Promise<void>;
}

export interface StartOptions {
  /** Extra `[defaults]` lines for the generated TOML config. */
  defaults?: string;
  /** Extra lines appended to the admin profile. */
  adminProfile?: string;
  /** Extra CLI args for the server process. */
  args?: string[];
}

function configToml(opts: StartOptions): string {
  return `[defaults]
defaultProfile = "admin"
${opts.defaults ?? ''}

[[profiles]]
name = "admin"
host = "${SSH_HOST}"
port = ${PORTS.admin}
user = "admin"
auth = "password"
role = "admin"
group = "dev"
${opts.adminProfile ?? ''}

[[profiles]]
name = "viewer"
host = "${SSH_HOST}"
port = ${PORTS.viewer}
user = "viewer"
auth = "password"
role = "viewer"
group = "dev"
readOnly = true
`;
}

/**
 * Boots a server process with a generated config and connects a client to it.
 * The caller must close() to reap the child.
 */
export async function startE2E(opts: StartOptions = {}): Promise<E2EClient & { cleanup(): Promise<void> }> {
  const dir = await mkdtemp(join(tmpdir(), 'ssh-mcp-e2e-'));
  await chmod(dir, 0o700);
  const configPath = join(dir, 'config.toml');
  await writeFile(configPath, configToml(opts), 'utf8');
  // The loader refuses group/world-readable config, as it should.
  await chmod(configPath, 0o600);

  // The suite runs under SSH_MCP_DISABLE_MAIN=1, which the child would inherit —
  // main() would never run and the server would never start.
  const { SSH_MCP_DISABLE_MAIN: _omit, ...parentEnv } = process.env;

  const transport = new StdioClientTransport({
    command: 'node',
    args: [SERVER_ENTRY, `--config=${configPath}`, '--insecureHostKey', ...(opts.args ?? [])],
    cwd: REPO_ROOT,
    env: {
      ...parentEnv,
      SSH_MCP_ADMIN_PASSWORD: 'secret',
      SSH_MCP_ADMIN_SUDO_PASSWORD: 'secret',
      SSH_MCP_VIEWER_PASSWORD: 'viewpass',
    } as Record<string, string>,
    stderr: 'pipe',
  });

  const prompts: string[] = [];
  let accept = true;

  const client = new Client(
    { name: 'e2e-client', version: '0.0.0' },
    { capabilities: { elicitation: {} } },
  );
  // Stands in for the human at the approval prompt. A client that does NOT
  // register this is exactly the failure mode worth knowing about: the server
  // fails closed and every destructive command is refused.
  client.setRequestHandler(ElicitRequestSchema, async (req) => {
    prompts.push(req.params.message);
    return accept ? { action: 'accept', content: { confirm: true } } : { action: 'decline' };
  });

  await client.connect(transport);

  return {
    client,
    prompts,
    setApproval(value) { accept = value; },
    async callTool(name, args = {}) {
      return client.callTool({ name, arguments: args }) as Promise<any>;
    },
    async close() {
      await client.close().catch(() => {});
    },
    async cleanup() {
      await client.close().catch(() => {});
      await rm(dir, { recursive: true, force: true });
    },
  };
}

/** Flatten a tool result's text content. */
export function textOf(result: any): string {
  return (result?.content ?? []).map((c: any) => c.text ?? '').join('\n');
}
