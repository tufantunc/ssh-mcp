import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { chmod, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { registerTools } from '../../src/tools/registry.js';
import { PolicyEngine, DEFAULT_RULES } from '../../src/policy/engine.js';
import { ConnectionRegistry } from '../../src/ssh/connection-registry.js';
import { defaultsFromArgv } from '../../src/cli.js';
import { SSHConnection } from '../../src/ssh/connection.js';
import { resolveCredentials } from '../../src/config/credential-resolver.js';
import type { AuditStore } from '../../src/audit/store.js';
import type { Profile } from '../../src/types.js';
import type { HostKeyMode } from '../../src/ssh/host-key.js';
import { sshAvailable, SSH_HOST, SSH_PORT } from './helpers.js';

/**
 * The three streaming SFTP tools as a client actually reaches them: through the
 * MCP server, the audited pipeline, the policy engine and a real SSH host.
 *
 * sftp-file-transfer.test.ts covers the primitives underneath — the byte cap,
 * the idle deadline, staging and publish. What only this file can show is the
 * handler layer: that the tools are reachable at all, that a round trip through
 * both of them returns the same bytes, and that the audit record names the
 * resolved local path rather than the argument the caller sent.
 */

const testProfile: Profile = {
  name: 'admin',
  host: SSH_HOST,
  port: SSH_PORT,
  user: 'admin',
  auth: 'password',
  tty: false,
  timeout: 10_000,
  maxChars: 5000,
  maxOutputBytes: 1_048_576,
  role: 'admin',
  readOnly: false,
  // The handler layer is what this file tests, not the elicitation prompt.
  approvalPolicy: 'auto',
  cert: false,
  sessionMaxPerConnection: 5,
  sessionIdleTimeoutMs: 60_000,
  sessionBackgroundMaxMs: 3_600_000,
  commandQuotaPerDay: 0,
  transferMaxBytes: 1_048_576,
  transferTimeoutMs: 10_000,
};

const SSH_AVAILABLE = await sshAvailable();

let client: Client;
let server: McpServer;
let registry: ConnectionRegistry;
let root: string;
let audited: any[];
let savedEnv: NodeJS.ProcessEnv;

/** Remote paths this file creates, removed in afterAll so reruns start clean. */
const REMOTE_BLOB = '/tmp/ssh-mcp-tool-blob.bin';
const REMOTE_DIR = '/tmp/ssh-mcp-tool-dir';

const call = (name: string, args: Record<string, unknown>) =>
  client.callTool({ name, arguments: args }) as Promise<any>;
const textOf = (result: any) => (result.content ?? []).map((c: any) => c.text ?? '').join('\n');

beforeAll(async () => {
  if (!SSH_AVAILABLE) return;
  savedEnv = { ...process.env };
  process.env.SSH_MCP_ADMIN_PASSWORD = 'secret';

  root = await mkdtemp(join(tmpdir(), 'ssh-mcp-tools-it-'));
  await chmod(root, 0o700);

  audited = [];
  const audit = { record: async (r: any) => { audited.push(r); } } as unknown as AuditStore;
  registry = new ConnectionRegistry(
    { defaults: { ...defaultsFromArgv({}), transferRoot: root }, profiles: [testProfile] },
    'insecure' as HostKeyMode,
  );
  server = new McpServer({ name: 'test', version: '0.0.0' }, { capabilities: { tools: {} } });
  registerTools(server, registry, new PolicyEngine(DEFAULT_RULES), audit, {
    localPath: { transferRoot: root },
  });

  client = new Client({ name: 'test-client', version: '0.0.0' }, { capabilities: {} });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

  // A directory with known contents, so the listing assertions name something
  // this file put there rather than whatever the image happens to ship.
  const conn = new SSHConnection(
    testProfile,
    await resolveCredentials(testProfile),
    new Map(),
    'insecure' as HostKeyMode,
  );
  await conn.ensureConnected();
  await conn.exec(`rm -rf ${REMOTE_DIR} && mkdir -p ${REMOTE_DIR} && echo one > ${REMOTE_DIR}/alpha && echo two > ${REMOTE_DIR}/beta`);
  await conn.close();
}, 60_000);

afterAll(async () => {
  if (!SSH_AVAILABLE) return;
  await client?.close().catch(() => {});
  await server?.close().catch(() => {});
  await registry?.closeAll().catch(() => {});
  if (root) await rm(root, { recursive: true, force: true });
  if (savedEnv) process.env = savedEnv;
});

describe.skipIf(!SSH_AVAILABLE)('the streaming SFTP tools, end to end', () => {
  describe('sftp-list', () => {
    it('lists a remote directory', async () => {
      const result = await call('sftp-list', { remotePath: REMOTE_DIR });
      expect(result.isError).toBeFalsy();
      const body = textOf(result);
      expect(body).toContain(`${REMOTE_DIR}/alpha`);
      expect(body).toContain(`${REMOTE_DIR}/beta`);
      // The rendered mode and size, not just the name: a listing that printed
      // only filenames would pass a `toContain` check while telling the model
      // nothing it could act on.
      expect(body).toMatch(/^-rw-r--r--\s+\d+\s{2}\d{4}-\d\d-\d\dT/m);
    });

    it('does not report "." or ".." as entries', async () => {
      const body = textOf(await call('sftp-list', { remotePath: REMOTE_DIR }));
      expect(body.split('\n').filter(Boolean)).toHaveLength(2);
    });

    it('says so when it truncates, rather than reporting a short listing as complete', async () => {
      const result = await call('sftp-list', { remotePath: '/usr/bin', maxEntries: 3 });
      const body = textOf(result);
      expect(body).toContain('[truncated');
      // Every line renders a type character, so counting them counts entries.
      // `/usr/bin` in this image is almost entirely symlinks, which is why this
      // matches the whole set rather than just files and directories.
      expect(body.split('\n').filter((l: string) => /^[-dlbcps?][-r]/.test(l))).toHaveLength(3);
    });

    it('reports a missing directory as an error rather than an empty listing', async () => {
      const result = await call('sftp-list', { remotePath: '/tmp/definitely-not-here-9f3a' });
      expect(result.isError).toBeTruthy();
      expect(textOf(result)).not.toContain('(empty directory)');
    });
  });

  describe('a round trip through both transfer tools', () => {
    it('returns the same bytes it sent, without either file passing through the response', async () => {
      // Not compressible and not text: the point of these tools is that the
      // payload never becomes a string in model context, and a binary body is
      // what would break if it did.
      const payload = Buffer.from(
        Array.from({ length: 300_000 }, (_, i) => (i * 7 + (i >> 3)) & 0xff),
      );
      await writeFile(join(root, 'source.bin'), payload);

      const uploaded = await call('sftp-upload-file', {
        localPath: 'source.bin',
        remotePath: REMOTE_BLOB,
        overwrite: true,
      });
      expect(uploaded.isError, textOf(uploaded)).toBeFalsy();
      expect(textOf(uploaded)).toContain(`Uploaded ${payload.length} bytes`);

      const downloaded = await call('sftp-download-file', {
        remotePath: REMOTE_BLOB,
        localPath: 'back.bin',
      });
      expect(downloaded.isError, textOf(downloaded)).toBeFalsy();

      const back = await readFile(join(root, 'back.bin'));
      expect(back.equals(payload)).toBe(true);

      // The response carries a byte count and two paths, and nothing else. A
      // handler that fell back to reading the file would show up here.
      expect(textOf(downloaded).length).toBeLessThan(200);
      // And nothing staged is left behind on either call.
      expect((await readdir(root)).filter((f) => f.includes('.part'))).toEqual([]);
    }, 60_000);

    it('audits the resolved local path, not the argument the caller sent', async () => {
      await writeFile(join(root, 'audited.txt'), 'hello');
      audited.length = 0;
      await call('sftp-upload-file', {
        // A spelling that only resolves inside the root. The audit record has
        // to name where it landed, which is the whole reason the pipeline lets
        // a handler elaborate the command string after approval (#207).
        localPath: './sub/../audited.txt',
        remotePath: '/tmp/ssh-mcp-tool-audited.txt',
        overwrite: true,
      });

      const record = audited.find((r) => r.command.startsWith('sftp:upload-file'));
      expect(record).toBeDefined();
      expect(record.decision).not.toBe('deny');
      expect(record.commandClass).toBe('destructive');
      expect(record.command).toBe('sftp:upload-file /tmp/ssh-mcp-tool-audited.txt <- audited.txt');
      expect(record.command).not.toContain('..');
    });
  });

  describe('refusals', () => {
    it('refuses a local path outside the transfer root, and stages nothing', async () => {
      const result = await call('sftp-download-file', {
        remotePath: '/etc/hostname',
        localPath: '../escape.txt',
      });
      expect(result.isError).toBeTruthy();
      expect(textOf(result)).toContain('transferRoot');
      expect((await readdir(root)).filter((f) => f.includes('.part'))).toEqual([]);
    });

    it('refuses to overwrite an existing local file unless asked', async () => {
      await writeFile(join(root, 'occupied.txt'), 'mine');
      const result = await call('sftp-download-file', {
        remotePath: '/etc/hostname',
        localPath: 'occupied.txt',
      });
      expect(result.isError).toBeTruthy();
      expect(await readFile(join(root, 'occupied.txt'), 'utf8')).toBe('mine');
    });

    it('refuses a local file over the profile transfer cap before any byte moves', async () => {
      // The profile above caps at 1 MiB; this is comfortably past it.
      await writeFile(join(root, 'huge.bin'), Buffer.alloc(2_000_000, 1));
      const result = await call('sftp-upload-file', {
        localPath: 'huge.bin',
        remotePath: '/tmp/ssh-mcp-tool-huge.bin',
      });
      expect(result.isError).toBeTruthy();
      expect(textOf(result)).toContain('transfer limit');
    });
  });
});
