import { describe, it, expect } from 'vitest';
import { spawn } from 'child_process';
import { mkdtemp, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { SERVER_ENTRY, serverBuilt } from './harness.js';

/**
 * An unconfigured server must still be able to say what it is — and must still refuse to
 * do anything.
 *
 * Measured before this change, against the published image and the built entry point
 * alike: `initialize` and `tools/list` drew **no JSON-RPC response at all** — the process
 * exited on the config check first, printing the config error to stderr. So every MCP
 * directory and every client "add this server" flow saw a crash rather than a tool list.
 * Glama's listing is the visible consequence: it reports the server as one that "cannot be
 * installed" and leaves quality ungraded.
 *
 * This drives the real binary over stdio rather than importing anything, because the thing
 * under test is what an outside harness gets, and the failure was in the process lifecycle
 * rather than in any function. It uses the harness's entry point and build guard so a
 * missing build fails by name rather than as a mysterious missing reply.
 *
 * The refusal half is here rather than only in the unit tests for a reason found in
 * review: `getProfile` tested in isolation proves nothing about a tool call, and the one
 * tool that did not reach `getProfile` — `list-connections` — was answering an
 * unconfigured server with a blank success while three pieces of shipped prose claimed
 * every tool call was refused.
 */

/** The complete registered set. A reduced list would mean the config had leaked into the metadata. */
const TOOL_COUNT = 14;

interface Probe { stdout: string; stderr: string; replies: any[] }

/** Speak JSON-RPC lines to the built server with nothing configured anywhere, and collect the replies. */
async function introspect(extra: object[] = []): Promise<Probe> {
  const home = await mkdtemp(join(tmpdir(), 'ssh-mcp-introspect-'));
  try {
    // The suite runs under SSH_MCP_DISABLE_MAIN=1, which the child would inherit —
    // main() would never run and the server would never start.
    const { SSH_MCP_DISABLE_MAIN: _omit, ...env } = process.env;
    const child = spawn('node', [SERVER_ENTRY], {
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
    for (const req of extra) child.stdin.write(`${JSON.stringify(req)}\n`);

    await new Promise<number | null>((resolve) => {
      // The server holds stdio open, so it is stopped rather than waited for.
      const timer = setTimeout(() => { child.kill('SIGTERM'); }, 4000);
      child.on('close', (c) => { clearTimeout(timer); resolve(c); });
    });
    return { stdout, stderr, replies: stdout.split('\n').filter(Boolean).map((l) => JSON.parse(l)) };
  } finally {
    await rm(home, { recursive: true, force: true });
  }
}

/** A `tools/call` request for a tool that needs no live host to be refused. */
const call = (id: number, name: string, args: object = {}) =>
  ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });

describe.skipIf(!serverBuilt)('introspection without a config', () => {
  it('answers initialize and lists every tool', async () => {
    const { stderr, replies } = await introspect();

    const init = replies.find((r) => r.id === 1);
    expect(init?.result?.serverInfo?.name, `no initialize reply. stderr: ${stderr}`).toBe('SSH MCP Server');

    const tools = replies.find((r) => r.id === 2);
    // Every registered tool, not a reduced set: the definitions are static metadata, and
    // what the config decides is what they may reach. Pinned to the exact count, because
    // "more than zero" would not have caught a set that quietly shrank.
    expect(tools?.result?.tools, `no tools/list reply. stderr: ${stderr}`).toHaveLength(TOOL_COUNT);
    expect(tools.result.tools.map((t: { name: string }) => t.name)).toContain('run-command');
  }, 30000);

  it('refuses a real tool call, naming the platform config path', async () => {
    const { stderr, replies } = await introspect([call(3, 'run-command', { command: 'echo hi' })]);

    const refusal = replies.find((r) => r.id === 3);
    expect(refusal, `no tools/call reply. stderr: ${stderr}`).toBeDefined();
    expect(refusal.result?.isError).toBe(true);
    expect(JSON.stringify(refusal.result.content)).toMatch(/No config file found and missing required --host\/--user/);
  }, 30000);

  it('refuses list-connections too, rather than answering it blank', async () => {
    // The discovery tool, and the one an agent reaches for first — its own description
    // says "use this to discover available hosts before running commands". It reads
    // `listAllProfiles()` and so never touched `getProfile`, which is how it came to
    // return a zero-length success on a server that had nothing configured.
    const { stderr, replies } = await introspect([call(3, 'list-connections')]);

    const refusal = replies.find((r) => r.id === 3);
    expect(refusal, `no tools/call reply. stderr: ${stderr}`).toBeDefined();
    expect(refusal.result?.isError, `list-connections did not refuse: ${JSON.stringify(refusal.result)}`).toBe(true);
    expect(JSON.stringify(refusal.result.content)).toMatch(/No config file found/);
  }, 30000);

  it('refuses a tool call that names a profile with the same explanation', async () => {
    // A client with a profile name baked into its MCP config is a common setup, and that
    // request takes the named branch of `getProfile`. It used to answer `Profile "prod"
    // not found` — telling the operator they mistyped a name when they have no config at
    // all, and omitting the config path this change exists to deliver.
    const { replies } = await introspect([call(3, 'run-command', { command: 'echo hi', profile: 'prod' })]);

    const refusal = replies.find((r) => r.id === 3);
    expect(refusal.result?.isError).toBe(true);
    expect(JSON.stringify(refusal.result.content)).toMatch(/No config file found/);
    expect(JSON.stringify(refusal.result.content)).not.toMatch(/not found/);
  }, 30000);

  it('says on stderr that it is unconfigured, naming the platform config path', async () => {
    // Starting quietly would be the real regression here: an operator who mistypes a flag
    // would get a server that looks healthy and fails once per call.
    const { stderr } = await introspect();
    expect(stderr).toMatch(/starting unconfigured/);
    expect(stderr).toMatch(/No config file found/);
  }, 30000);
});
