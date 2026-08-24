import { describe, it, expect } from 'vitest';
import { spawn } from 'child_process';
import { mkdtemp, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';

/**
 * An unconfigured server must still be able to say what it is.
 *
 * Measured before this change, against the published image and the built entry point
 * alike: `initialize` and `tools/list` drew **no JSON-RPC response at all** — the process
 * exited on the config check first, printing the config error to stderr. So every MCP
 * directory and every client "add this server" flow saw a crash rather than a tool list.
 * Glama's listing is the visible consequence: it reports the server as one that "cannot be
 * installed", and grades quality — which it computes from tool definitions — as ungraded.
 *
 * This drives the real binary over stdio rather than importing anything, because the thing
 * under test is what an outside harness gets, and the failure was in the process lifecycle
 * rather than in any function.
 */

/** Speak two JSON-RPC lines to `build/index.js` and collect whatever comes back. */
async function introspect(): Promise<{ stdout: string; stderr: string; code: number | null }> {
  const home = await mkdtemp(join(tmpdir(), 'ssh-mcp-introspect-'));
  try {
    const { SSH_MCP_DISABLE_MAIN: _omit, ...env } = process.env;
    const child = spawn('node', ['build/index.js'], {
      env: {
        ...(env as NodeJS.ProcessEnv),
        // Point every config lookup at an empty directory: this is the "nothing
        // configured anywhere" case, not a broken config.
        HOME: home,
        USERPROFILE: home,
        XDG_CONFIG_HOME: join(home, '.config'),
        APPDATA: home,
      },
    });

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });

    child.stdin.write(
      `${JSON.stringify({
        jsonrpc: '2.0', id: 1, method: 'initialize',
        params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'probe', version: '0' } },
      })}\n`,
    );
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} })}\n`);

    const code = await new Promise<number | null>((resolve) => {
      // The server holds stdio open, so it is stopped rather than waited for.
      const timer = setTimeout(() => { child.kill('SIGTERM'); }, 4000);
      child.on('close', (c) => { clearTimeout(timer); resolve(c); });
    });
    return { stdout, stderr, code };
  } finally {
    await rm(home, { recursive: true, force: true });
  }
}

describe('introspection without a config', () => {
  it('answers initialize and tools/list', async () => {
    const { stdout, stderr } = await introspect();
    const replies = stdout.split('\n').filter(Boolean).map((l) => JSON.parse(l));

    const init = replies.find((r) => r.id === 1);
    expect(init?.result?.serverInfo?.name, `no initialize reply. stderr: ${stderr}`).toBe('SSH MCP Server');

    const tools = replies.find((r) => r.id === 2);
    expect(tools?.result?.tools?.length, `no tools/list reply. stderr: ${stderr}`).toBeGreaterThan(0);
    // Every registered tool, not a reduced set: the definitions are static metadata, and
    // what the config decides is what they may reach.
    expect(tools.result.tools.map((t: { name: string }) => t.name)).toContain('run-command');
  }, 30000);

  it('says on stderr that it is unconfigured, naming the platform config path', async () => {
    // Starting quietly would be the real regression here: an operator who mistypes a flag
    // would get a server that looks healthy and fails once per call.
    const { stderr } = await introspect();
    expect(stderr).toMatch(/starting unconfigured/);
    expect(stderr).toMatch(/No config file found/);
  }, 30000);
});
