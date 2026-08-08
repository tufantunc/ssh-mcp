import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { spawn, type ChildProcess } from 'child_process';
import { mkdtemp, writeFile, chmod, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { request } from 'http';
import { SERVER_ENTRY, e2eAvailable } from './harness.js';
import { PORTS } from '../integration/fixtures.js';
import { SSH_HOST } from '../integration/helpers.js';

// The HTTP transport served exactly one MCP session and stayed dead after that
// client left. This exercises the multi-session behaviour against the real
// server with real clients, which is the only way that failure is visible.
const PORT = 18422;
const BEARER = 'e2e-bearer-token';

let child: ChildProcess;
let dir: string;
const available = await e2eAvailable();

function httpGet(path: string, headers: Record<string, string> = {}): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request(
      { hostname: '127.0.0.1', port: PORT, path, method: 'GET', headers, agent: false },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body: data }));
      },
    );
    req.on('error', reject);
    req.end();
  });
}

async function connectClient(): Promise<Client> {
  const client = new Client({ name: 'e2e-http', version: '0.0.0' }, { capabilities: {} });
  const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${PORT}/`), {
    requestInit: { headers: { authorization: `Bearer ${BEARER}` } },
  });
  await client.connect(transport);
  return client;
}

beforeAll(async () => {
  if (!available) return;
  dir = await mkdtemp(join(tmpdir(), 'ssh-mcp-e2e-http-'));
  await chmod(dir, 0o700);
  const configPath = join(dir, 'config.toml');
  await writeFile(configPath, `[defaults]
defaultProfile = "admin"

[[profiles]]
name = "admin"
host = "${SSH_HOST}"
port = ${PORTS.admin}
user = "admin"
auth = "password"
role = "admin"
group = "dev"
`, 'utf8');
  await chmod(configPath, 0o600);

  const { SSH_MCP_DISABLE_MAIN: _omit, ...env } = process.env;
  child = spawn('node', [
    SERVER_ENTRY, `--config=${configPath}`, '--insecureHostKey',
    '--transport=http', `--httpPort=${PORT}`, `--bearerToken=${BEARER}`,
  ], { env: { ...env, SSH_MCP_ADMIN_PASSWORD: 'secret' } as Record<string, string>, stdio: 'pipe' });

  // Wait for the listener rather than sleeping a fixed amount.
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('HTTP server did not start')), 15000);
    child.stderr?.on('data', (d) => {
      if (d.toString().includes('listening on')) { clearTimeout(timer); resolve(); }
    });
    child.on('exit', (code) => { clearTimeout(timer); reject(new Error(`server exited: ${code}`)); });
  });
}, 30000);

afterAll(async () => {
  child?.kill('SIGTERM');
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe.skipIf(!available)('E2E — HTTP transport', () => {
  it('serves /health without a token but requires one elsewhere', async () => {
    const health = await httpGet('/health');
    expect(health.status).toBe(200);
    expect(JSON.parse(health.body).healthy).toBe(true);

    const unauthorised = await httpGet('/status');
    expect(unauthorised.status).toBe(401);

    const authorised = await httpGet('/status', { authorization: `Bearer ${BEARER}` });
    expect(authorised.status).toBe(200);
  });

  // Regression: one shared transport meant the SDK rejected the second client
  // with "Server already initialized", and closing the first left the endpoint
  // permanently unusable.
  it('serves two concurrent clients and survives one leaving', async () => {
    const first = await connectClient();
    const second = await connectClient();

    expect((await first.listTools()).tools.length).toBe(11);
    expect((await second.listTools()).tools.length).toBe(11);

    // First client goes away; the endpoint must stay usable.
    await first.close();

    const third = await connectClient();
    const res = await third.callTool({ name: 'read-command', arguments: { command: 'whoami' } }) as any;
    expect(res.isError).toBeFalsy();
    expect((res.content ?? []).map((c: any) => c.text).join('')).toContain('admin');

    await second.close();
    await third.close();
  }, 40000);
});
