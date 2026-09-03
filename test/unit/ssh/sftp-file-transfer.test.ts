import { describe, expect, it } from 'vitest';
import { Readable, Writable } from 'node:stream';
import { SftpClient } from '../../../src/ssh/sftp.js';
import { testProfile } from '../tools/harness.js';

function clientWith(sftp: Record<string, unknown>): SftpClient {
  const missing = Object.assign(new Error('missing'), { code: 2 });
  const wrapper = {
    end() {},
    stat: (_path: string, callback: any) => callback(missing),
    rename: (_source: string, _destination: string, callback: any) => callback(),
    ext_openssh_rename: (_source: string, _destination: string, callback: any) => callback(),
    ext_openssh_hardlink: (_source: string, _destination: string, callback: any) => callback(),
    unlink: (_path: string, callback: any) => callback(),
    ...sftp,
  };
  const conn = {
    profile: testProfile,
    async ensureConnected() {},
    getClient: () => ({ sftp: (callback: any) => callback(undefined, wrapper) }),
  };
  return new SftpClient(conn as any);
}

describe('streaming SFTP transfer bounds', () => {
  it('reads at most maxEntries plus one through a directory handle and closes it', async () => {
    let reads = 0;
    let closed = false;
    const entry = (filename: string) => ({
      filename,
      attrs: { size: 1, mode: 0o100644, mtime: 1, atime: 1 },
    });
    const batches = [[entry('one')], [entry('two')], [entry('three')], [entry('four')]];
    const client = clientWith({
      opendir: (_path: string, callback: any) => callback(undefined, Buffer.from('handle')),
      readdir: (_handle: Buffer, callback: any) => callback(undefined, batches[reads++]),
      close: (_handle: Buffer, callback: any) => { closed = true; callback(); },
    });
    const result = await client.list('/remote', 2, { maxBytes: 10_000, timeoutMs: 1_000 });
    expect(result.entries.map((item) => item.path)).toEqual(['/remote/one', '/remote/two']);
    expect(result.truncated).toBe(true);
    expect(reads).toBe(3);
    expect(closed).toBe(true);
  });

  it('returns the bytes actually accepted by the upload stream', async () => {
    const chunks: Buffer[] = [];
    let openedPath = '';
    let openedMode = 0;
    let linkedFrom = '';
    const client = clientWith({
      createWriteStream: (path: string, options: { mode: number }) => {
        openedPath = path;
        openedMode = options.mode;
        return new Writable({
        write(chunk, _encoding, callback) { chunks.push(Buffer.from(chunk)); callback(); },
        });
      },
      ext_openssh_hardlink: (source: string, destination: string, callback: any) => {
        linkedFrom = source;
        expect(destination).toBe('/remote');
        callback();
      },
    });
    const bytes = await client.uploadFile(Readable.from(Buffer.from('actual')), '/remote', {
      maxBytes: 100,
      timeoutMs: 1_000,
    });
    expect(bytes).toBe(6);
    expect(Buffer.concat(chunks).toString()).toBe('actual');
    expect(openedPath).toMatch(/^\/\.ssh-mcp-upload-.*\.part$/);
    expect(openedMode).toBe(0o600);
    expect(linkedFrom).toBe(openedPath);
  });

  it('uses POSIX rename only when remote overwrite is explicit', async () => {
    let renamed = false;
    let linked = false;
    const client = clientWith({
      createWriteStream: () => new Writable({ write(_chunk, _encoding, callback) { callback(); } }),
      ext_openssh_rename: (_source: string, _destination: string, callback: any) => {
        renamed = true;
        callback();
      },
      ext_openssh_hardlink: () => { linked = true; },
    });
    await client.uploadFile(Readable.from('data'), '/remote', {
      maxBytes: 100,
      timeoutMs: 1_000,
      overwrite: true,
    });
    expect(renamed).toBe(true);
    expect(linked).toBe(false);
  });

  it('fails closed when atomic no-overwrite publishing is unsupported', async () => {
    const unsupported = Object.assign(new Error('unsupported'), { code: 8 });
    const client = clientWith({
      createWriteStream: () => new Writable({ write(_chunk, _encoding, callback) { callback(); } }),
      ext_openssh_hardlink: (_source: string, _destination: string, callback: any) => callback(unsupported),
    });
    await expect(client.uploadFile(Readable.from('data'), '/remote', {
      maxBytes: 100,
      timeoutMs: 1_000,
    })).rejects.toThrow(/cannot atomically publish/);
  });

  it('stops an upload that exceeds the configured cap', async () => {
    const client = clientWith({
      createWriteStream: () => new Writable({ write(_chunk, _encoding, callback) { callback(); } }),
    });
    await expect(client.uploadFile(Readable.from(Buffer.alloc(101)), '/remote', {
      maxBytes: 100,
      timeoutMs: 1_000,
    })).rejects.toThrow(/100 byte transfer limit/);
  });

  it('aborts a stalled transfer at its own timeout', async () => {
    const stalled = new Readable({ read() {} });
    const client = clientWith({
      createWriteStream: () => new Writable({ write(_chunk, _encoding, callback) { callback(); } }),
    });
    await expect(client.uploadFile(stalled, '/remote', {
      maxBytes: 100,
      timeoutMs: 20,
    })).rejects.toThrow(/timed out/);
    expect(stalled.destroyed).toBe(true);
  });

  it('honours an external abort signal', async () => {
    const controller = new AbortController();
    const stalled = new Readable({ read() {} });
    const client = clientWith({
      createWriteStream: () => new Writable({ write(_chunk, _encoding, callback) { callback(); } }),
    });
    const pending = client.uploadFile(stalled, '/remote', {
      maxBytes: 100,
      timeoutMs: 1_000,
      abortSignal: controller.signal,
    });
    controller.abort(new Error('caller cancelled'));
    await expect(pending).rejects.toThrow(/caller cancelled/);
  });

  it('refuses a known oversized download before opening its data stream', async () => {
    let opened = false;
    const client = clientWith({
      stat: (_path: string, callback: any) => callback(undefined, { size: 101 }),
      createReadStream: () => { opened = true; return Readable.from('data'); },
    });
    await expect(client.downloadFile('/remote', new Writable({ write(_c, _e, cb) { cb(); } }), {
      maxBytes: 100,
      timeoutMs: 1_000,
    })).rejects.toThrow(/transfer limit/);
    expect(opened).toBe(false);
  });

  it('finishes and closes a download source that reaches EOF without closing itself', async () => {
    const chunks: Buffer[] = [];
    const source = Readable.from('downloaded');
    const client = clientWith({
      stat: (_path: string, callback: any) => callback(undefined, { size: 10 }),
      createReadStream: () => source,
    });
    const bytes = await client.downloadFile('/remote', new Writable({
      write(chunk, _encoding, callback) { chunks.push(Buffer.from(chunk)); callback(); },
    }), { maxBytes: 100, timeoutMs: 1_000 });
    expect(bytes).toBe(10);
    expect(Buffer.concat(chunks).toString()).toBe('downloaded');
    expect(source.closed).toBe(true);
  });

  it('does not leak an unhandled rejection when the remote stream fails', async () => {
    const unhandled: unknown[] = [];
    let cleaned = '';
    const listener = (reason: unknown) => unhandled.push(reason);
    process.on('unhandledRejection', listener);
    try {
      const client = clientWith({
        createWriteStream: () => new Writable({
          write(_chunk, _encoding, callback) { callback(new Error('remote write failed')); },
        }),
        unlink: (path: string, callback: any) => { cleaned = path; callback(); },
      });
      await expect(client.uploadFile(Readable.from('data'), '/remote', {
        maxBytes: 100,
        timeoutMs: 1_000,
      })).rejects.toThrow(/remote write failed/);
      await new Promise((resolve) => setTimeout(resolve, 10));
      expect(unhandled).toEqual([]);
      expect(cleaned).toMatch(/\.part$/);
    } finally {
      process.removeListener('unhandledRejection', listener);
    }
  });

  it('times out a stalled download stat and directory read', async () => {
    const stalled = clientWith({
      stat: () => {},
      opendir: (_path: string, callback: any) => callback(undefined, Buffer.from('handle')),
      readdir: () => {},
      close: (_handle: Buffer, callback: any) => callback(),
    });
    await expect(stalled.downloadFile('/remote', new Writable({ write(_c, _e, cb) { cb(); } }), {
      maxBytes: 100,
      timeoutMs: 20,
    })).rejects.toThrow(/timed out/);
    await expect(stalled.list('/remote', 10, { maxBytes: 1_000, timeoutMs: 20 })).rejects.toThrow(/timed out/);
  });

  it('refuses an existing remote upload target unless overwrite is explicit', async () => {
    let opened = false;
    const client = clientWith({
      stat: (_path: string, callback: any) => callback(undefined, { size: 1 }),
      createWriteStream: () => { opened = true; return new Writable(); },
    });
    await expect(client.uploadFile(Readable.from('data'), '/remote', {
      maxBytes: 100,
      timeoutMs: 1_000,
      overwrite: false,
    })).rejects.toThrow(/overwrite an existing remote file/);
    expect(opened).toBe(false);
  });

  it('bounds raw directory metadata before rendering', async () => {
    let closed = false;
    const client = clientWith({
      opendir: (_path: string, callback: any) => callback(undefined, Buffer.from('handle')),
      readdir: (_handle: Buffer, callback: any) => callback(undefined, [{
        filename: 'x'.repeat(2_000),
        attrs: { size: 1, mode: 0o100644, mtime: 1, atime: 1 },
      }]),
      close: (_handle: Buffer, callback: any) => { closed = true; callback(); },
    });
    const result = await client.list('/remote', 10, { maxBytes: 100, timeoutMs: 1_000 });
    expect(result).toEqual({ entries: [], truncated: true });
    expect(closed).toBe(true);
  });
});
