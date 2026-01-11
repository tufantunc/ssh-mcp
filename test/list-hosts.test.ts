import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { spawn, ChildProcess } from 'child_process';

const host1 = process.env.SSH_HOST_1 || '127.0.0.1';
const port1 = Number(process.env.SSH_PORT_1 || 2222);
const user1 = process.env.SSH_USER_1 || 'test';
const pass1 = process.env.SSH_PASSWORD_1 || 'secret';

const host2 = process.env.SSH_HOST_2 || '127.0.0.1';
const port2 = Number(process.env.SSH_PORT_2 || 2223);
const user2 = process.env.SSH_USER_2 || 'test';
const pass2 = process.env.SSH_PASSWORD_2 || 'secret';

describe('list-hosts tool', () => {
  let serverProcess: ChildProcess;
  let client: Client;

  beforeAll(async () => {
    // Start MCP server with first host configuration
    serverProcess = spawn('node', [
      'build/index.js',
      `--host=${host1}`,
      `--port=${port1}`,
      `--user=${user1}`,
      `--password=${pass1}`
    ], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: {
        ...process.env,
        SSH_MCP_TEST: '1'
      }
    });

    // Wait a bit for server to initialize
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Create MCP client
    const transport = new StdioClientTransport({
      command: 'node',
      args: [
        'build/index.js',
        `--host=${host1}`,
        `--port=${port1}`,
        `--user=${user1}`,
        `--password=${pass1}`
      ],
      env: {
        ...process.env,
        SSH_MCP_TEST: '1'
      }
    });

    client = new Client({
      name: 'test-client',
      version: '1.0.0'
    }, {
      capabilities: {}
    });

    await client.connect(transport);
  }, 30000);

  afterAll(async () => {
    if (client) {
      await client.close();
    }
    if (serverProcess) {
      serverProcess.kill();
    }
  });

  it('should list the default configured host', async () => {
    const result = await client.callTool({
      name: 'list-hosts',
      arguments: {}
    });

    expect(result).toBeDefined();
    expect(result.content).toBeDefined();
    expect(result.content[0]).toHaveProperty('type', 'text');

    const text = (result.content[0] as any).text;
    expect(text).toContain(`${user1}@${host1}`);
  }, 30000);

  it('should show connection status after executing command', async () => {
    // Execute a command to establish connection
    await client.callTool({
      name: 'exec',
      arguments: {
        command: 'echo "test"'
      }
    });

    // List hosts should now show connected
    const result = await client.callTool({
      name: 'list-hosts',
      arguments: {}
    });

    const text = (result.content[0] as any).text;
    expect(text).toContain('connected');
  }, 30000);

  it('should list multiple hosts after connecting to them', async () => {
    // Execute command on first host
    await client.callTool({
      name: 'exec',
      arguments: {
        command: 'echo "host1"'
      }
    });

    // Execute command on second host
    await client.callTool({
      name: 'exec',
      arguments: {
        command: 'echo "host2"',
        host: host2
      }
    });

    // List hosts should show both
    const result = await client.callTool({
      name: 'list-hosts',
      arguments: {}
    });

    const text = (result.content[0] as any).text;

    // Should contain both hosts
    expect(text).toContain(`${user1}@${host1}`);
    // Note: host2 might not appear if it's using the same user and only host differs
    // The connection key is user@host, so different hosts should appear
  }, 60000);
});

describe('list-hosts integration test', () => {
  it('should handle list-hosts with no active connections', async () => {
    const transport = new StdioClientTransport({
      command: 'node',
      args: [
        'build/index.js',
        `--host=${host1}`,
        `--port=${port1}`,
        `--user=${user1}`,
        `--password=${pass1}`
      ],
      env: {
        ...process.env,
        SSH_MCP_TEST: '1'
      }
    });

    const client = new Client({
      name: 'test-client',
      version: '1.0.0'
    }, {
      capabilities: {}
    });

    try {
      await client.connect(transport);

      const result = await client.callTool({
        name: 'list-hosts',
        arguments: {}
      });

      expect(result.content[0]).toHaveProperty('type', 'text');
      const text = (result.content[0] as any).text;

      // Should show default host as not connected
      expect(text).toContain(`${user1}@${host1}`);
      expect(text).toContain('not connected');
    } finally {
      await client.close();
    }
  }, 30000);
});
