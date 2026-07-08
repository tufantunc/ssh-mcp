import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { SSHConnectionManager, execSshCommandWithConnection } from '../src/index';
import { Client as SSHClient } from 'ssh2';

const host = process.env.SSH_HOST || '127.0.0.1';
const port = Number(process.env.SSH_PORT || 2222);
const username = process.env.SSH_USER || 'test';
const password = process.env.SSH_PASSWORD || 'secret';

describe('SSHConnectionManager', () => {
  describe('Unit Tests (without live SSH)', () => {
    let manager: SSHConnectionManager;
    const mockConfig = { host: '127.0.0.1', port: 22, username: 'test', password: 'test' };

    beforeEach(() => {
      manager = new SSHConnectionManager(mockConfig);
    });

    afterEach(() => {
      if (manager) {
        manager.close();
      }
    });

    it('should initialize with null connection', () => {
      expect(manager.isConnected()).toBe(false);
    });

    it('should handle getConnection when not connected', () => {
      expect(() => manager.getConnection()).toThrow('SSH connection not established');
    });

    it('should handle close when not connected', () => {
      expect(() => manager.close()).not.toThrow();
    });
  });

  describe('Integration Tests (with live SSH server)', () => {
    let manager: SSHConnectionManager;
    const sshConfig = { host, port, username, password };

    beforeEach(() => {
      manager = new SSHConnectionManager(sshConfig);
    });

    afterEach(() => {
      if (manager) {
        manager.close();
      }
    });

    it('should establish connection on first connect', async () => {
      await manager.connect();
      expect(manager.isConnected()).toBe(true);
    }, 30000);

    it('should not create new connection if already connected', async () => {
      await manager.connect();
      const firstConnected = manager.isConnected();
      
      // Call connect again
      await manager.connect();
      expect(manager.isConnected()).toBe(true);
      expect(firstConnected).toBe(true);
    }, 30000);

    it('should reconnect if connection is lost', async () => {
      await manager.connect();
      expect(manager.isConnected()).toBe(true);
      
      // Close the connection manually
      manager.close();
      expect(manager.isConnected()).toBe(false);
      
      // Wait a bit for connection to fully close
      await new Promise(resolve => setTimeout(resolve, 100));
      
      // Ensure connected should reconnect
      await manager.ensureConnected();
      expect(manager.isConnected()).toBe(true);
    }, 60000);

    it('should handle concurrent connection attempts', async () => {
      // Start multiple connection attempts simultaneously
      const connectionPromises = [
        manager.ensureConnected(),
        manager.ensureConnected(),
        manager.ensureConnected(),
      ];
      
      await Promise.all(connectionPromises);
      expect(manager.isConnected()).toBe(true);
    }, 30000);

    it('should execute command after connection', async () => {
      await manager.connect();
      const result = await execSshCommandWithConnection(manager, 'echo "test"');
      
      expect(result.content).toBeDefined();
      expect(result.content[0]).toHaveProperty('type', 'text');
      expect(result.content[0]).toHaveProperty('text');
      expect((result.content[0] as any).text).toContain('test');
    }, 30000);

    it('should reuse connection for multiple commands', async () => {
      await manager.connect();
      
      const result1 = await execSshCommandWithConnection(manager, 'echo "first"');
      const result2 = await execSshCommandWithConnection(manager, 'echo "second"');
      const result3 = await execSshCommandWithConnection(manager, 'echo "third"');
      
      expect((result1.content[0] as any).text).toContain('first');
      expect((result2.content[0] as any).text).toContain('second');
      expect((result3.content[0] as any).text).toContain('third');
      
      // Connection should still be active after all commands
      expect(manager.isConnected()).toBe(true);
    }, 30000);

    it('should execute multiple commands concurrently', async () => {
      await manager.connect();
      
      const commands = [
        execSshCommandWithConnection(manager, 'echo "cmd1"'),
        execSshCommandWithConnection(manager, 'echo "cmd2"'),
        execSshCommandWithConnection(manager, 'echo "cmd3"'),
        execSshCommandWithConnection(manager, 'echo "cmd4"'),
        execSshCommandWithConnection(manager, 'echo "cmd5"'),
      ];
      
      const results = await Promise.all(commands);
      
      expect(results).toHaveLength(5);
      results.forEach((result, index) => {
        expect(result.content[0]).toHaveProperty('type', 'text');
        expect((result.content[0] as any).text).toContain(`cmd${index + 1}`);
      });
      
      // Connection should still be active
      expect(manager.isConnected()).toBe(true);
    }, 30000);

    it('should handle command with stderr', async () => {
      await manager.connect();
      
      // This command writes to stderr
      await expect(
        execSshCommandWithConnection(manager, 'echo "error" >&2 && exit 1')
      ).rejects.toThrow();
    }, 30000);

    it('should close connection properly', async () => {
      await manager.connect();
      expect(manager.isConnected()).toBe(true);
      
      manager.close();
      expect(manager.isConnected()).toBe(false);
    }, 30000);

    it('should handle ensureConnected with multiple calls', async () => {
      // First ensure connected
      await manager.ensureConnected();
      expect(manager.isConnected()).toBe(true);
      
      // Second ensure connected should not reconnect
      await manager.ensureConnected();
      expect(manager.isConnected()).toBe(true);
      
      // Close and ensure again
      manager.close();
      
      // Wait a bit for connection to fully close
      await new Promise(resolve => setTimeout(resolve, 100));
      
      await manager.ensureConnected();
      expect(manager.isConnected()).toBe(true);
    }, 60000);

    it('should handle long-running commands', async () => {
      await manager.connect();
      
      // Command that takes 2 seconds
      const result = await execSshCommandWithConnection(manager, 'sleep 2 && echo "done"');
      
      expect((result.content[0] as any).text).toContain('done');
      expect(manager.isConnected()).toBe(true);
    }, 30000);

    it('should execute commands in sequence maintaining order', async () => {
      await manager.connect();
      
      // Create a temp file, write to it, then read it
      await execSshCommandWithConnection(manager, 'echo "line1" > /tmp/test_ssh_mcp_seq.txt');
      await execSshCommandWithConnection(manager, 'echo "line2" >> /tmp/test_ssh_mcp_seq.txt');
      await execSshCommandWithConnection(manager, 'echo "line3" >> /tmp/test_ssh_mcp_seq.txt');
      
      const result = await execSshCommandWithConnection(manager, 'cat /tmp/test_ssh_mcp_seq.txt');
      const output = (result.content[0] as any).text;
      
      expect(output).toContain('line1');
      expect(output).toContain('line2');
      expect(output).toContain('line3');
      
      // Cleanup
      await execSshCommandWithConnection(manager, 'rm /tmp/test_ssh_mcp_seq.txt');
    }, 30000);

    it('should handle rapid sequential commands', async () => {
      await manager.connect();
      
      // Execute 10 rapid commands
      for (let i = 0; i < 10; i++) {
        const result = await execSshCommandWithConnection(manager, `echo "command ${i}"`);
        expect((result.content[0] as any).text).toContain(`command ${i}`);
      }
      
      expect(manager.isConnected()).toBe(true);
    }, 30000);

    it('should maintain connection through different command types', async () => {
      await manager.connect();
      
      // Different types of commands
      await execSshCommandWithConnection(manager, 'pwd');
      await execSshCommandWithConnection(manager, 'ls -la /tmp');
      await execSshCommandWithConnection(manager, 'whoami');
      await execSshCommandWithConnection(manager, 'date');
      await execSshCommandWithConnection(manager, 'echo $HOME');
      
      expect(manager.isConnected()).toBe(true);
    }, 30000);

    it('should handle command with large output', async () => {
      await manager.connect();
      
      // Generate large output (500 lines)
      const result = await execSshCommandWithConnection(
        manager, 
        'for i in {1..500}; do echo "Line $i"; done'
      );
      
      const output = (result.content[0] as any).text;
      expect(output.split('\n').length).toBeGreaterThan(400);
      expect(manager.isConnected()).toBe(true);
    }, 30000);

    it('should handle environment variables in commands', async () => {
      await manager.connect();
      
      const result = await execSshCommandWithConnection(
        manager,
        'TEST_VAR="hello world" && echo $TEST_VAR'
      );
      
      expect((result.content[0] as any).text).toContain('hello');
    }, 30000);

    it('should handle piped commands', async () => {
      await manager.connect();
      
      const result = await execSshCommandWithConnection(
        manager,
        'echo "line1\nline2\nline3" | grep line2'
      );
      
      expect((result.content[0] as any).text).toContain('line2');
    }, 30000);

    it('should handle commands with special characters', async () => {
      await manager.connect();
      
      const result = await execSshCommandWithConnection(
        manager,
        'echo "Hello! @#$%^&*()_+-=[]{}|;:,.<>?"'
      );
      
      expect((result.content[0] as any).text).toContain('Hello!');
    }, 30000);
  });

  describe('Connection Lifecycle', () => {
    it('should handle multiple connection managers independently', async () => {
      const manager1 = new SSHConnectionManager({ host, port, username, password });
      const manager2 = new SSHConnectionManager({ host, port, username, password });
      
      try {
        await manager1.connect();
        await manager2.connect();
        
        expect(manager1.isConnected()).toBe(true);
        expect(manager2.isConnected()).toBe(true);
        
        const result1 = await execSshCommandWithConnection(manager1, 'echo "manager1"');
        const result2 = await execSshCommandWithConnection(manager2, 'echo "manager2"');
        
        expect((result1.content[0] as any).text).toContain('manager1');
        expect((result2.content[0] as any).text).toContain('manager2');
      } finally {
        manager1.close();
        manager2.close();
      }
    }, 60000);

    it('should properly clean up after close', async () => {
      const manager = new SSHConnectionManager({ host, port, username, password });
      
      await manager.connect();
      expect(manager.isConnected()).toBe(true);
      
      manager.close();
      expect(manager.isConnected()).toBe(false);
      
      // Should not be able to execute commands after close
      expect(() => manager.getConnection()).toThrow();
    }, 30000);
  });

  describe('Error Handling', () => {
    it('should handle invalid connection config', async () => {
      const invalidManager = new SSHConnectionManager({
        host: 'invalid-host-that-does-not-exist-12345.com',
        port: 22,
        username: 'test',
        password: 'test'
      });
      
      try {
        await expect(invalidManager.connect()).rejects.toThrow();
      } finally {
        invalidManager.close();
      }
    }, 40000);

    it('should handle connection timeout', async () => {
      // Use a non-routable IP to trigger timeout
      const timeoutManager = new SSHConnectionManager({
        host: '192.0.2.1', // TEST-NET-1, non-routable
        port: 22,
        username: 'test',
        password: 'test'
      });
      
      try {
        await expect(timeoutManager.connect()).rejects.toThrow();
      } finally {
        timeoutManager.close();
      }
    }, 40000);

    it('should handle command execution errors gracefully', async () => {
      const manager = new SSHConnectionManager({ host, port, username, password });
      
      try {
        await manager.connect();
        
        // Execute invalid command
        await expect(
          execSshCommandWithConnection(manager, 'this-command-does-not-exist-12345')
        ).rejects.toThrow();
        
        // Connection should still be alive for next command
        expect(manager.isConnected()).toBe(true);
        
        // Should be able to execute valid command after error
        const result = await execSshCommandWithConnection(manager, 'echo "recovery"');
        expect((result.content[0] as any).text).toContain('recovery');
      } finally {
        manager.close();
      }
    }, 30000);
  });
});

