import { describe, it, expect } from 'vitest';
import { spawn } from 'child_process';
import { join } from 'path';

describe('maxChars CLI configuration', () => {
  const testServerPath = join(process.cwd(), 'build', 'index.js');

  function responseText(response: any): string {
    return (
      response.error?.message ||
      response.result?.content?.[0]?.text ||
      JSON.stringify(response)
    );
  }

  function runExec(command: string, extraArgs: string[] = []): Promise<any> {
    const args = [
      testServerPath,
      '--host=127.0.0.1',
      '--port=2222',
      '--user=test',
      '--password=secret',
      '--timeout=5000',
      ...extraArgs,
    ];

    return new Promise((resolve, reject) => {
      const child = spawn('node', args, { stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, SSH_MCP_TEST: '1' } });
      let buffer = '';
      const startup = setTimeout(() => {
        child.kill();
        reject(new Error('Server start timeout'));
      }, 10000);

      const initMsg = { jsonrpc: '2.0', id: 0, method: 'initialize', params: { capabilities: {}, clientInfo: { name: 't', version: '1' }, protocolVersion: '0.1.0' } };
      const toolCall = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'exec', arguments: { command } } };

      child.stdout.on('data', (data) => {
        buffer += data.toString();
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

      setTimeout(() => {
        child.stdin.write(JSON.stringify(initMsg) + '\n');
      }, 100);
    });
  }

  describe('default behavior (1000 chars)', () => {
    it('should reject commands over 1000 characters by default', async () => {
      const longCommand = 'echo ' + 'x'.repeat(1000);
      const response = await runExec(longCommand);

      expect(responseText(response)).toContain('Command is too long (max 1000 characters)');
    });
  });

  describe('custom maxChars limit', () => {
    it('should respect custom positive limit', async () => {
      const longCommand = 'echo ' + 'x'.repeat(50);
      const response = await runExec(longCommand, ['--maxChars=50']);

      expect(responseText(response)).toContain('Command is too long (max 50 characters)');
    });
  });

  describe('no-limit mode', () => {
    it('should allow unlimited characters with maxChars=none', async () => {
      const veryLongCommand = 'echo ' + 'x'.repeat(10000);
      const response = await runExec(veryLongCommand, ['--maxChars=none']);

      expect(responseText(response)).not.toContain('Command is too long');
    });

    it('should allow unlimited characters with maxChars=0', async () => {
      const veryLongCommand = 'echo ' + 'x'.repeat(10000);
      const response = await runExec(veryLongCommand, ['--maxChars=0']);

      expect(responseText(response)).not.toContain('Command is too long');
    });
  });

  describe('invalid maxChars values', () => {
    it('should fall back to default for invalid string values', async () => {
      const longCommand = 'echo ' + 'x'.repeat(1000);
      const response = await runExec(longCommand, ['--maxChars=invalid']);

      expect(responseText(response)).toContain('Command is too long (max 1000 characters)');
    });
  });
});
