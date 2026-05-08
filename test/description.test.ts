import { describe, it, expect, beforeAll } from 'vitest';
import { spawn } from 'child_process';
import { join } from 'path';

const testServerPath = join(process.cwd(), 'build', 'index.js');
const START_TIMEOUT = 10000;

beforeAll(() => {
  process.env.SSH_MCP_TEST = '1';
});

function runMcpCommand(command: string, description?: string, extraArgs: string[] = [], toolName = 'exec'): Promise<any> {
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

    // Build the tool call with optional description
    const toolArguments: any = { command };
    if (description !== undefined) {
      toolArguments.description = description;
    }
    
    const initMsg = { jsonrpc: '2.0', id: 0, method: 'initialize', params: { capabilities: {}, clientInfo: { name: 't', version: '1' }, protocolVersion: '0.1.0' } };
    const toolCall = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: toolName, arguments: toolArguments } };

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

describe('command description functionality', () => {
  it('should execute commands without description (backward compatibility)', async () => {
    const res = await runMcpCommand('echo "test without description"');
    expect(res.error).toBeUndefined();
    expect(res.result?.content?.[0]?.text).toContain('test without description');
  });

  it('should accept a description without sending it to the remote shell', async () => {
    const res = await runMcpCommand('printf "command-only\\n"', 'SHOULD_NOT_APPEAR # description marker');
    expect(res.error).toBeUndefined();
    const output = res.result?.content?.[0]?.text || '';
    expect(output).toContain('command-only');
    expect(output).not.toContain('SHOULD_NOT_APPEAR');
    expect(output).not.toContain('description marker');
  });

  it('should handle descriptions with special characters', async () => {
    const res = await runMcpCommand('printf "special-description-ok\\n"', 'List all files # detailed format');
    expect(res.error).toBeUndefined();
    const output = res.result?.content?.[0]?.text || '';
    expect(output).toContain('special-description-ok');
    expect(output).not.toContain('List all files');
  });

  it('should not send descriptions through sudo-exec', async () => {
    const res = await runMcpCommand('printf "sudo-command-only\\n"', 'SHOULD_NOT_APPEAR_SUDO', ['--sudoPassword=secret'], 'sudo-exec');
    expect(res.error).toBeUndefined();
    const output = res.result?.content?.[0]?.text || '';
    expect(output).toContain('sudo-command-only');
    expect(output).not.toContain('SHOULD_NOT_APPEAR_SUDO');
  });

  it('should not send descriptions through su-exec', async () => {
    const res = await runMcpCommand('printf "su-command-only\\n"', 'SHOULD_NOT_APPEAR_SU', ['--suPassword=secret'], 'su-exec');
    expect(res.error).toBeUndefined();
    const output = res.result?.content?.[0]?.text || '';
    expect(output).toContain('su-command-only');
    expect(output).not.toContain('SHOULD_NOT_APPEAR_SU');
  });

  it('should allow su-exec commands that contain shell comments', async () => {
    const command = 'printf "before\\n"\n# shell comment inside the command\nprintf "after\\n"';
    const res = await runMcpCommand(command, 'client-side description with # marker', ['--suPassword=secret'], 'su-exec');
    expect(res.error).toBeUndefined();
    const output = res.result?.content?.[0]?.text || '';
    expect(output).toContain('before');
    expect(output).toContain('after');
    expect(output).not.toContain('shell comment inside');
    expect(output).not.toContain('client-side description');
  });

  it('should handle empty description parameter', async () => {
    const res = await runMcpCommand('pwd', '');
    expect(res.error).toBeUndefined();
    expect(res.result?.content?.[0]?.text).toBeTruthy();
  });
});
