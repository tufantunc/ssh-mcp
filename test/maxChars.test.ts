import { describe, it, expect } from 'vitest';
import { spawn } from 'child_process';
import { join } from 'path';

describe('maxChars CLI configuration', () => {
  const testServerPath = join(process.cwd(), 'build', 'index.js');
  
  describe('default behavior (1000 chars)', () => {
    it('should reject commands over 1000 characters by default', () => {
      const longCommand = 'echo ' + 'x'.repeat(1000);
      const args = [
        '--host=127.0.0.1',
        '--user=test',
        '--password=secret',
        '--timeout=5000'
      ];
      
      const child = spawn('node', [testServerPath, ...args], {
        stdio: ['pipe', 'pipe', 'pipe']
      });
      
      // Send a tool call with a long command
      const toolCall = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'exec',
          arguments: {
            command: longCommand
          }
        }
      };
      
      child.stdin.write(JSON.stringify(toolCall) + '\n');
      
      let output = '';
      child.stdout.on('data', (data) => {
        output += data.toString();
      });
      
      child.on('close', () => {
        const response = JSON.parse(output);
        expect(response.error.message).toContain('Command is too long (max 1000 characters)');
      });
      
      child.stdin.end();
    });
  });

  describe('custom maxChars limit', () => {
    it('should respect custom positive limit', () => {
      const longCommand = 'echo ' + 'x'.repeat(50);
      const args = [
        '--host=127.0.0.1',
        '--user=test',
        '--password=secret',
        '--timeout=5000',
        '--maxChars=50'
      ];
      
      const child = spawn('node', [testServerPath, ...args], {
        stdio: ['pipe', 'pipe', 'pipe']
      });
      
      const toolCall = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'exec',
          arguments: {
            command: longCommand
          }
        }
      };
      
      child.stdin.write(JSON.stringify(toolCall) + '\n');
      
      let output = '';
      child.stdout.on('data', (data) => {
        output += data.toString();
      });
      
      child.on('close', () => {
        const response = JSON.parse(output);
        expect(response.error.message).toContain('Command is too long (max 50 characters)');
      });
      
      child.stdin.end();
    });
  });

  describe('no-limit mode', () => {
    it('should allow unlimited characters with maxChars=none', () => {
      const veryLongCommand = 'echo ' + 'x'.repeat(10000);
      const args = [
        '--host=127.0.0.1',
        '--user=test',
        '--password=secret',
        '--timeout=5000',
        '--maxChars=none'
      ];
      
      const child = spawn('node', [testServerPath, ...args], {
        stdio: ['pipe', 'pipe', 'pipe']
      });
      
      const toolCall = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'exec',
          arguments: {
            command: veryLongCommand
          }
        }
      };
      
      child.stdin.write(JSON.stringify(toolCall) + '\n');
      
      let output = '';
      child.stdout.on('data', (data) => {
        output += data.toString();
      });
      
      child.on('close', () => {
        const response = JSON.parse(output);
        // Should not have a length error - might have SSH connection error instead
        expect(response.error.message).not.toContain('Command is too long');
      });
      
      child.stdin.end();
    });

    it('should allow unlimited characters with maxChars=0', () => {
      const veryLongCommand = 'echo ' + 'x'.repeat(10000);
      const args = [
        '--host=127.0.0.1',
        '--user=test',
        '--password=secret',
        '--timeout=5000',
        '--maxChars=0'
      ];
      
      const child = spawn('node', [testServerPath, ...args], {
        stdio: ['pipe', 'pipe', 'pipe']
      });
      
      const toolCall = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'exec',
          arguments: {
            command: veryLongCommand
          }
        }
      };
      
      child.stdin.write(JSON.stringify(toolCall) + '\n');
      
      let output = '';
      child.stdout.on('data', (data) => {
        output += data.toString();
      });
      
      child.on('close', () => {
        const response = JSON.parse(output);
        // Should not have a length error - might have SSH connection error instead
        expect(response.error.message).not.toContain('Command is too long');
      });
      
      child.stdin.end();
    });
  });

  describe('invalid maxChars values', () => {
    it('should fall back to default for invalid string values', () => {
      const longCommand = 'echo ' + 'x'.repeat(1000);
      const args = [
        '--host=127.0.0.1',
        '--user=test',
        '--password=secret',
        '--timeout=5000',
        '--maxChars=invalid'
      ];
      
      const child = spawn('node', [testServerPath, ...args], {
        stdio: ['pipe', 'pipe', 'pipe']
      });
      
      const toolCall = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'exec',
          arguments: {
            command: longCommand
          }
        }
      };
      
      child.stdin.write(JSON.stringify(toolCall) + '\n');
      
      let output = '';
      child.stdout.on('data', (data) => {
        output += data.toString();
      });
      
      child.on('close', () => {
        const response = JSON.parse(output);
        expect(response.error.message).toContain('Command is too long (max 1000 characters)');
      });
      
      child.stdin.end();
    });
  });
});
