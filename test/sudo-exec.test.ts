import { describe, it, expect, beforeAll } from 'vitest';
import { spawn } from 'child_process';
import { join } from 'path';

// Very small, focused tests for the elevated MCP tools. This file is intentionally
// small and straightforward (no heavy debug plumbing) — the integration surface
// is: start the MCP server in test mode, send an initialize request, then call
// a tool and assert the returned JSON-RPC response.

const testServerPath = join(process.cwd(), 'build', 'index.js');
const START_TIMEOUT = 10000;

beforeAll(() => {
  process.env.SSH_MCP_TEST = '1';
});

function responseText(res: any): string {
  return (
    res.error?.message ||
    res.result?.content?.[0]?.text ||
    JSON.stringify(res)
  ).toLowerCase();
}

function runMcpCommand(command: string, extraArgs: string[] = [], toolName = 'sudo-exec', description?: string): Promise<any> {
  const args = [
    testServerPath,
    '--host=127.0.0.1',
    '--port=2222',
    '--user=test',
    '--password=secret',
    '--timeout=60000',
    ...extraArgs,
  ];

  return new Promise((resolve, reject) => {
    const child = spawn('node', args, { stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, SSH_MCP_TEST: '1' } });
    let buffer = '';
    const startup = setTimeout(() => {
      child.kill();
      reject(new Error('Server start timeout'));
    }, START_TIMEOUT);

    const initMsg = { jsonrpc: '2.0', id: 0, method: 'initialize', params: { capabilities: {}, clientInfo: { name: 't', version: '1' }, protocolVersion: '0.1.0' } };
    const toolCall = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: toolName, arguments: { command, ...(description ? { description } : {}) } },
    };

    child.stdout.on('data', (d) => {
      buffer += d.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';
      for (const line of lines) {
        try {
          const msg = JSON.parse(line);
          if (msg.id === 0) {
            child.stdin.write(JSON.stringify(toolCall) + '\n');
          } else if (msg.id === 1) {
            clearTimeout(startup);
            resolve(msg);
            child.kill();
            return;
          }
        } catch (e) {
          // ignore non-json
        }
      }
    });

    child.stderr.on('data', () => { /* ignore */ });
    child.on('error', (err) => { clearTimeout(startup); reject(err); });

    // Give the server a moment to initialize before sending messages
    setTimeout(() => {
      child.stdin.write(JSON.stringify(initMsg) + '\n');
    }, 100);
  });
}

function listMcpTools(extraArgs: string[] = []): Promise<string[]> {
  const args = [
    testServerPath,
    '--host=127.0.0.1',
    '--port=2222',
    '--user=test',
    '--password=secret',
    '--timeout=60000',
    ...extraArgs,
  ];

  return new Promise((resolve, reject) => {
    const child = spawn('node', args, { stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, SSH_MCP_TEST: '1' } });
    let buffer = '';
    const startup = setTimeout(() => {
      child.kill();
      reject(new Error('Server start timeout'));
    }, START_TIMEOUT);

    const initMsg = { jsonrpc: '2.0', id: 0, method: 'initialize', params: { capabilities: {}, clientInfo: { name: 't', version: '1' }, protocolVersion: '0.1.0' } };
    const listTools = { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} };

    child.stdout.on('data', (d) => {
      buffer += d.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';
      for (const line of lines) {
        try {
          const msg = JSON.parse(line);
          if (msg.id === 0) {
            child.stdin.write(JSON.stringify(listTools) + '\n');
          } else if (msg.id === 1) {
            clearTimeout(startup);
            resolve((msg.result?.tools || []).map((tool: any) => tool.name));
            child.kill();
            return;
          }
        } catch (e) {
          // ignore non-json
        }
      }
    });

    child.stderr.on('data', () => { /* ignore */ });
    child.on('error', (err) => { clearTimeout(startup); reject(err); });

    setTimeout(() => {
      child.stdin.write(JSON.stringify(initMsg) + '\n');
    }, 100);
  });
}

// Helper that runs a command through the explicit su-exec tool.
function runSuMcpCommand(command: string, suPassword = 'secret', extraArgs: string[] = []): Promise<any> {
  return runMcpCommand(command, [`--suPassword=${suPassword}`, ...extraArgs], 'su-exec');
}

describe('sudo-exec tool authentication', () => {
  // Set up the su environment before running tests that need it
  beforeAll(async () => {
    // First make su setuid root
    const suSetup = await runMcpCommand('chmod u+s /bin/su', ['--sudoPassword=secret']);
    expect(suSetup.error).toBeUndefined();

    // Then set the root password to 'secret'
    const passwdSetup = await runMcpCommand('echo "secret" | passwd --stdin', ['--sudoPassword=secret']);
    expect(passwdSetup.error).toBeUndefined();
  });

  it('should execute commands with su elevation after sudo setup', async () => {
    // First verify we can use su now by checking if we can become root
    const whoami = await runMcpCommand('whoami && echo "secret" | su -c whoami', ['--sudoPassword=secret']);
    expect(whoami.error).toBeUndefined();
    const output = (whoami.result?.content?.[0]?.text || '').toLowerCase();
    expect(output).toContain('root');
    
    // Now try creating a root-owned directory
    const mkdir = await runMcpCommand('echo "secret" | su -c "mkdir -p /root/test_dir"', ['--sudoPassword=secret']);
    expect(mkdir.error).toBeUndefined();
    
    // Verify we can access it
    const ls = await runMcpCommand('ls -la /root/test_dir', ['--sudoPassword=secret']);
    expect(ls.error).toBeUndefined();
    expect(ls.result?.content?.[0]?.text).toBeTruthy();

    // Clean up
    const cleanup = await runMcpCommand('rm -rf /root/test_dir', ['--sudoPassword=secret']);
    expect(cleanup.error).toBeUndefined();
  }, 60000); // Increased timeout for su operations

  it('executes su when provided --suPassword', async () => {
    const res = await runSuMcpCommand('whoami', 'secret');
    expect(res.error).toBeUndefined();
    const out = responseText(res);
    expect(out).toContain('root');
  }, 60000);

  it('keeps plain exec non-elevated when --suPassword is configured', async () => {
    const res = await runMcpCommand('whoami', ['--suPassword=secret'], 'exec');
    expect(res.error).toBeUndefined();
    const out = responseText(res);
    expect(out).toContain('test');
    expect(out).not.toContain('root');
  }, 60000);

  it('keeps plain exec output intact when description contains shell-comment marker', async () => {
    const res = await runMcpCommand('printf "alpha\\nbeta\\n"', ['--suPassword=secret'], 'exec', 'description with # marker');
    expect(res.error).toBeUndefined();
    const out = responseText(res);
    expect(out).toContain('alpha');
    expect(out).toContain('beta');
    expect(out).not.toContain('description with');
  }, 60000);

  it('does not expose sudo-exec when sudo password is not configured', async () => {
    const res = await runMcpCommand('whoami');
    expect(responseText(res)).toMatch(/not found|unknown tool|not registered/);
  });

  it('reports empty command as invalid', async () => {
    const res = await runMcpCommand('', ['--sudoPassword=secret']);
    expect(responseText(res)).toContain('command cannot be empty');
  });

  it('rejects wrong sudo password', async () => {
    const res = await runMcpCommand('whoami', ['--sudoPassword=wrongpass']);
    // The sshd/sudo stack may return different messages across platforms; look for common indicator
    expect(responseText(res)).toMatch(/sorry|incorrect|authentication/);
  });

  it('executes with correct sudo password', async () => {
    const res = await runMcpCommand('id', ['--sudoPassword=secret']);
    expect(res.error).toBeUndefined();
    const out = responseText(res);
    expect(out).toContain('uid=0');
  });

  it('exposes elevated tools only when their password is configured', async () => {
    await expect(listMcpTools()).resolves.toEqual(['exec']);
    await expect(listMcpTools(['--suPassword=secret'])).resolves.toEqual(['exec', 'su-exec']);
    await expect(listMcpTools(['--sudoPassword=secret'])).resolves.toEqual(['exec', 'sudo-exec']);
    await expect(listMcpTools(['--suPassword=secret', '--sudoPassword=secret'])).resolves.toEqual(['exec', 'su-exec', 'sudo-exec']);
  });
});
