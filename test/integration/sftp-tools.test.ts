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
/** Kept open for out-of-band assertions about the remote side (modes, contents). */
let shell: SSHConnection;

/** Remote paths this file creates, removed in afterAll so reruns start clean. */
const REMOTE_BLOB = '/tmp/ssh-mcp-tool-blob.bin';
const REMOTE_DIR = '/tmp/ssh-mcp-tool-dir';
const REMOTE_EMPTY = '/tmp/ssh-mcp-tool-empty';
const REMOTE_NOCLOBBER = '/tmp/ssh-mcp-tool-noclobber.txt';
const REMOTE_MODE = '/tmp/ssh-mcp-tool-mode.txt';
const REMOTE_SUID = '/tmp/ssh-mcp-tool-suid';

const call = (name: string, args: Record<string, unknown>) =>
  client.callTool({ name, arguments: args }) as Promise<any>;
const textOf = (result: any) => (result.content ?? []).map((c: any) => c.text ?? '').join('\n');

/** The default the handler applies when the caller names no `maxEntries`. */
const DEFAULT_LIST_ENTRIES = 200;

/**
 * A second server over the same transfer root, with a tweaked profile.
 *
 * So a bound can be tested at a value small enough to reach without building a
 * fixture sized to the default. The suite's main server stays untouched.
 */
async function startServer(overrides: Partial<Profile> = {}) {
  const profile = { ...testProfile, ...overrides };
  const reg = new ConnectionRegistry(
    { defaults: { ...defaultsFromArgv({}), transferRoot: root }, profiles: [profile] },
    'insecure' as HostKeyMode,
  );
  const srv = new McpServer({ name: 'test', version: '0.0.0' }, { capabilities: { tools: {} } });
  registerTools(srv, reg, new PolicyEngine(DEFAULT_RULES), { record: async () => {} } as any, {
    localPath: { transferRoot: root },
  });
  const cli = new Client({ name: 'test-client', version: '0.0.0' }, { capabilities: {} });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await Promise.all([srv.connect(st), cli.connect(ct)]);
  return {
    call: (name: string, args: Record<string, unknown>) =>
      cli.callTool({ name, arguments: args }) as Promise<any>,
    async close() {
      await cli.close().catch(() => {});
      await srv.close().catch(() => {});
      await reg.closeAll().catch(() => {});
    },
  };
}

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
  shell = new SSHConnection(
    testProfile,
    await resolveCredentials(testProfile),
    new Map(),
    'insecure' as HostKeyMode,
  );
  await shell.ensureConnected();
  // Two regular files, a directory and a symlink, so the listing's type column
  // has something other than `-` to render. Reruns start from a clean slate.
  await shell.exec(
    `rm -rf ${REMOTE_DIR} ${REMOTE_EMPTY} && mkdir -p ${REMOTE_DIR} ${REMOTE_EMPTY} ` +
    `&& echo one > ${REMOTE_DIR}/alpha && echo two > ${REMOTE_DIR}/beta ` +
    `&& mkdir ${REMOTE_DIR}/sub && ln -s alpha ${REMOTE_DIR}/link`,
  );
}, 60_000);

afterAll(async () => {
  if (!SSH_AVAILABLE) return;
  await client?.close().catch(() => {});
  await server?.close().catch(() => {});
  await registry?.closeAll().catch(() => {});
  if (root) await rm(root, { recursive: true, force: true });
  // Actually remove what this file wrote on the host. The comment above used to
  // promise this and afterAll did not do it, so every run inherited the
  // previous one's files — invisible while every writing call passed
  // `overwrite: true`, and a guaranteed second-run failure the moment one did
  // not (which the no-clobber case below now does).
  await shell?.exec(
    `rm -rf ${REMOTE_DIR} ${REMOTE_EMPTY} ${REMOTE_BLOB} ${REMOTE_NOCLOBBER} ${REMOTE_MODE} ${REMOTE_SUID} /tmp/ssh-mcp-tool-audited.txt`,
  ).catch(() => {});
  await shell?.close().catch(() => {});
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
      // alpha, beta, sub, link — and nothing else.
      expect(body.split('\n').filter(Boolean)).toHaveLength(4);
      expect(body).not.toMatch(/\/\.$|\/\.\.$/m);
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

    it('renders the type of every entry, not only regular files', async () => {
      const body = textOf(await call('sftp-list', { remotePath: REMOTE_DIR }));
      expect(body, 'no directory entry rendered').toMatch(/^d.*\/sub$/m);
      expect(body, 'no symlink entry rendered').toMatch(/^l.*\/link$/m);
      expect(body).toMatch(/^-.*\/alpha$/m);
    });

    it('renders an empty directory as such', async () => {
      const result = await call('sftp-list', { remotePath: REMOTE_EMPTY });
      expect(result.isError, textOf(result)).toBeFalsy();
      expect(textOf(result)).toBe('(empty directory)');
    });

    it('truncates on the byte budget, not only on the entry count', async () => {
      // A budget small enough that the rendered lines exhaust it well before
      // `maxEntries` does, so only the byte bound can have produced the note.
      const narrow = await startServer({ maxOutputBytes: 400 });
      try {
        const result = await narrow.call('sftp-list', { remotePath: '/usr/bin' });
        const body = (result.content ?? []).map((c: any) => c.text ?? '').join('\n');
        expect(body).toContain('[truncated');
        const lines = body.split('\n').filter((l: string) => /^[-dlbcps?][-r]/.test(l));
        expect(lines.length).toBeGreaterThan(0);
        expect(lines.length).toBeLessThan(DEFAULT_LIST_ENTRIES);
        // The bound is on what is produced: the rendered body must fit.
        expect(Buffer.byteLength(lines.join('\n'), 'utf8')).toBeLessThanOrEqual(400);
      } finally {
        await narrow.close();
      }
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

    it('audits both the spelling the caller sent and the file it resolved to', async () => {
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
      // The caller's spelling *and* what it resolved to, so a divergence between
      // them is visible to an auditor rather than normalised away.
      expect(record.command).toBe(
        'sftp:upload-file /tmp/ssh-mcp-tool-audited.txt --overwrite <- ./sub/../audited.txt (resolved audited.txt)',
      );
      // The resolution is appended, never substituted: the pipeline's rule is
      // that an audited string may only elaborate what policy evaluated, and a
      // record that quietly normalised the request would hide the difference.
      expect(record.command.indexOf('sftp:upload-file')).toBe(0);
      expect(record.command).toContain('(resolved audited.txt)');
    });
  });

  describe('the arguments that shape the transfer', () => {
    it('sets the remote mode the caller asked for', async () => {
      await writeFile(join(root, 'moded.txt'), 'x');
      const result = await call('sftp-upload-file', {
        localPath: 'moded.txt', remotePath: REMOTE_MODE, mode: 0o640, overwrite: true,
      });
      expect(result.isError, textOf(result)).toBeFalsy();
      expect((await shell.exec(`stat -c '%a' ${REMOTE_MODE}`)).stdout.trim()).toBe('640');
    });

    it('publishes 0600 when no mode is given and nothing is being replaced', async () => {
      await writeFile(join(root, 'moded.txt'), 'x');
      await shell.exec(`rm -f ${REMOTE_MODE}`);
      await call('sftp-upload-file', { localPath: 'moded.txt', remotePath: REMOTE_MODE });
      expect((await shell.exec(`stat -c '%a' ${REMOTE_MODE}`)).stdout.trim()).toBe('600');
    });

    it('refuses to replace a remote file unless overwrite is asked for', async () => {
      await shell.exec(`rm -f ${REMOTE_NOCLOBBER} && echo first > ${REMOTE_NOCLOBBER}`);
      await writeFile(join(root, 'second.txt'), 'second\n');

      const result = await call('sftp-upload-file', {
        localPath: 'second.txt', remotePath: REMOTE_NOCLOBBER,
      });
      expect(result.isError).toBeTruthy();
      expect(textOf(result)).toMatch(/Refusing to overwrite an existing remote file/);
      // And the original is still there — a silent clobber would pass the check
      // above if the handler reported an error for some other reason.
      expect((await shell.exec(`cat ${REMOTE_NOCLOBBER}`)).stdout.trim()).toBe('first');
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

    it('does not carry setuid across an overwrite', async () => {
      // The route `checkMode` does not cover: with `overwrite` and no `mode`,
      // `uploadFile` stats the destination and re-applies its mode. Carrying the
      // whole 0o7777 across turned "may replace this file" into "may run code as
      // its owner" — measured against this exact fixture, which came back 4755
      // with the caller's content in it.
      await shell.exec(`echo original > ${REMOTE_SUID} && chmod 4755 ${REMOTE_SUID}`);
      await writeFile(join(root, 'replacement.bin'), 'replaced\n');

      const result = await call('sftp-upload-file', {
        localPath: 'replacement.bin',
        remotePath: REMOTE_SUID,
        overwrite: true,
      });
      expect(result.isError, textOf(result)).toBeFalsy();

      const after = await shell.exec(`stat -c '%a' ${REMOTE_SUID}; cat ${REMOTE_SUID}`);
      const [mode, content] = after.stdout.trim().split('\n');
      // The permission bits survive, which is the point of inheriting at all.
      expect(mode).toBe('755');
      expect(content).toBe('replaced');
    });

    it('removes the staged file when the transfer fails after staging it', async () => {
      // The only path where the handler's `finally { cleanup() }` does the work
      // its comment credits it with. The other `.part`-absence assertions in
      // this file cover a refusal *before* staging and a clean success, so
      // deleting the finally broke nothing.
      await writeFile(join(root, 'big-source.bin'), Buffer.alloc(200_000, 7));
      await call('sftp-upload-file', {
        localPath: 'big-source.bin', remotePath: REMOTE_BLOB, overwrite: true,
      });

      // Small enough that the copy trips the cap mid-stream, which is after
      // `createLocalDownload` has opened the `.part`.
      const tight = await startServer({ transferMaxBytes: 4096 });
      try {
        const result = await tight.call('sftp-download-file', {
          remotePath: REMOTE_BLOB, localPath: 'tight.bin',
        });
        expect(result.isError).toBeTruthy();
      } finally {
        await tight.close();
      }

      const left = await readdir(root);
      expect(left.filter((f) => f.includes('.part'))).toEqual([]);
      expect(left, 'a failed download published its destination anyway').not.toContain('tight.bin');
    }, 60_000);

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
