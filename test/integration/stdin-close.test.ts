import { describe, it, expect } from 'vitest';
import { spawn } from 'child_process';
import { existsSync } from 'fs';
import { resolve } from 'path';
import { checkAllServers, allServersUp } from './fixtures.js';

// Issue #53: an MCP client that exits without signalling used to leave this
// process running with its SSH connections open, because the SDK's stdio
// transport listens only for 'data' and 'error' on stdin — never for EOF.
const repoRoot = resolve(import.meta.dirname, '../..');
const entry = resolve(repoRoot, 'build/index.js');

function runServer(): { child: ReturnType<typeof spawn>; stderr: () => string; exit: Promise<number | 'TIMEOUT'> } {
  // The suite runs under SSH_MCP_DISABLE_MAIN=1, which the child would inherit
  // — main() would never run and the server would never start.
  const { SSH_MCP_DISABLE_MAIN: _omit, ...cleanEnv } = process.env;

  const child = spawn('node', [entry, '--host=127.0.0.1', '--port=2222', '--user=admin'], {
    cwd: repoRoot,
    env: { ...cleanEnv, SSH_MCP_ADMIN_PASSWORD: 'secret', SSH_MCP_PASSWORD: 'secret' },
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  let err = '';
  child.stderr?.on('data', (d) => { err += d.toString(); });

  const exit = Promise.race<number | 'TIMEOUT'>([
    new Promise<number>((r) => child.on('exit', (code) => r(code ?? -1))),
    new Promise<'TIMEOUT'>((r) => setTimeout(() => r('TIMEOUT'), 8000)),
  ]);

  return { child, stderr: () => err, exit };
}

const serversUp = allServersUp(await checkAllServers());

describe.skipIf(!serversUp || !existsSync(entry))('stdio transport lifecycle', () => {
  it('exits when the client closes stdin', async () => {
    const { child, stderr, exit } = runServer();
    await new Promise((r) => setTimeout(r, 1500));
    expect(stderr()).toContain('running on stdio');

    child.stdin?.end();

    const result = await exit;
    if (result === 'TIMEOUT') child.kill('SIGKILL');
    // Without the EOF handler this hangs until the timeout — an orphaned
    // process holding open SSH connections.
    expect(result).toBe(0);
    expect(stderr()).toContain('Shutting down');
  }, 20000);

  it('exits on SIGTERM', async () => {
    const { child, exit } = runServer();
    await new Promise((r) => setTimeout(r, 1500));
    child.kill('SIGTERM');

    const result = await exit;
    if (result === 'TIMEOUT') child.kill('SIGKILL');
    expect(result).toBe(0);
  }, 20000);
});
