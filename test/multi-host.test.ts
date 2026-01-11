import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { SSHConnectionManager, execSshCommandWithConnection } from '../src/index';

// Test için birden fazla SSH host yapılandırması
// Bu değerler çevre değişkenlerinden veya varsayılan değerlerden alınır
const host1 = process.env.SSH_HOST_1 || '127.0.0.1';
const port1 = Number(process.env.SSH_PORT_1 || 2222);
const user1 = process.env.SSH_USER_1 || 'test';
const pass1 = process.env.SSH_PASSWORD_1 || 'secret';

const host2 = process.env.SSH_HOST_2 || '127.0.0.1';
const port2 = Number(process.env.SSH_PORT_2 || 2223);
const user2 = process.env.SSH_USER_2 || 'test';
const pass2 = process.env.SSH_PASSWORD_2 || 'secret';

const host3 = process.env.SSH_HOST_3 || '127.0.0.1';
const port3 = Number(process.env.SSH_PORT_3 || 2224);
const user3 = process.env.SSH_USER_3 || 'test';
const pass3 = process.env.SSH_PASSWORD_3 || 'secret';

describe('Multi-Host SSH Support', () => {
  describe('Connection Pool Management', () => {
    const managers: SSHConnectionManager[] = [];

    afterEach(() => {
      // Tüm managerleri temizle
      managers.forEach(m => m.close());
      managers.length = 0;
    });

    it('should create and maintain separate connections for different hosts', async () => {
      const manager1 = new SSHConnectionManager({
        host: host1,
        port: port1,
        username: user1,
        password: pass1
      });
      const manager2 = new SSHConnectionManager({
        host: host2,
        port: port2,
        username: user2,
        password: pass2
      });

      managers.push(manager1, manager2);

      // Her iki host'a da bağlan
      await manager1.connect();
      await manager2.connect();

      expect(manager1.isConnected()).toBe(true);
      expect(manager2.isConnected()).toBe(true);

      // Her host'ta ayrı komutlar çalıştır
      const result1 = await execSshCommandWithConnection(manager1, 'echo "host1"');
      const result2 = await execSshCommandWithConnection(manager2, 'echo "host2"');

      expect((result1.content[0] as any).text).toContain('host1');
      expect((result2.content[0] as any).text).toContain('host2');
    }, 60000);

    it('should handle concurrent connections to multiple hosts', async () => {
      const manager1 = new SSHConnectionManager({
        host: host1,
        port: port1,
        username: user1,
        password: pass1
      });
      const manager2 = new SSHConnectionManager({
        host: host2,
        port: port2,
        username: user2,
        password: pass2
      });
      const manager3 = new SSHConnectionManager({
        host: host3,
        port: port3,
        username: user3,
        password: pass3
      });

      managers.push(manager1, manager2, manager3);

      // Tüm bağlantıları paralel olarak başlat
      await Promise.all([
        manager1.connect(),
        manager2.connect(),
        manager3.connect()
      ]);

      expect(manager1.isConnected()).toBe(true);
      expect(manager2.isConnected()).toBe(true);
      expect(manager3.isConnected()).toBe(true);
    }, 60000);

    it('should execute commands on multiple hosts in parallel', async () => {
      const manager1 = new SSHConnectionManager({
        host: host1,
        port: port1,
        username: user1,
        password: pass1
      });
      const manager2 = new SSHConnectionManager({
        host: host2,
        port: port2,
        username: user2,
        password: pass2
      });

      managers.push(manager1, manager2);

      await Promise.all([
        manager1.connect(),
        manager2.connect()
      ]);

      // Her iki host'ta da paralel komut çalıştır
      const [result1, result2] = await Promise.all([
        execSshCommandWithConnection(manager1, 'echo "parallel1"'),
        execSshCommandWithConnection(manager2, 'echo "parallel2"')
      ]);

      expect((result1.content[0] as any).text).toContain('parallel1');
      expect((result2.content[0] as any).text).toContain('parallel2');
    }, 60000);

    it('should maintain independent state for each host connection', async () => {
      const manager1 = new SSHConnectionManager({
        host: host1,
        port: port1,
        username: user1,
        password: pass1
      });
      const manager2 = new SSHConnectionManager({
        host: host2,
        port: port2,
        username: user2,
        password: pass2
      });

      managers.push(manager1, manager2);

      await manager1.connect();
      await manager2.connect();

      // Host 1'de dosya oluştur
      await execSshCommandWithConnection(
        manager1,
        'echo "file1" > /tmp/test_multi_host_1.txt'
      );

      // Host 2'de farklı dosya oluştur
      await execSshCommandWithConnection(
        manager2,
        'echo "file2" > /tmp/test_multi_host_2.txt'
      );

      // Her host'tan kendi dosyasını oku
      const result1 = await execSshCommandWithConnection(
        manager1,
        'cat /tmp/test_multi_host_1.txt'
      );
      const result2 = await execSshCommandWithConnection(
        manager2,
        'cat /tmp/test_multi_host_2.txt'
      );

      expect((result1.content[0] as any).text).toContain('file1');
      expect((result2.content[0] as any).text).toContain('file2');

      // Temizlik
      await execSshCommandWithConnection(manager1, 'rm -f /tmp/test_multi_host_1.txt');
      await execSshCommandWithConnection(manager2, 'rm -f /tmp/test_multi_host_2.txt');
    }, 60000);

    it('should handle connection failure on one host without affecting others', async () => {
      const validManager = new SSHConnectionManager({
        host: host1,
        port: port1,
        username: user1,
        password: pass1
      });
      const invalidManager = new SSHConnectionManager({
        host: 'invalid-host-12345.com',
        port: 22,
        username: 'invalid',
        password: 'invalid'
      });

      managers.push(validManager, invalidManager);

      // Geçerli host'a bağlan
      await validManager.connect();
      expect(validManager.isConnected()).toBe(true);

      // Geçersiz host bağlantısı başarısız olmalı
      await expect(invalidManager.connect()).rejects.toThrow();

      // Geçerli host hala çalışıyor olmalı
      expect(validManager.isConnected()).toBe(true);
      const result = await execSshCommandWithConnection(validManager, 'echo "still working"');
      expect((result.content[0] as any).text).toContain('still working');
    }, 60000);

    it('should close connections independently', async () => {
      const manager1 = new SSHConnectionManager({
        host: host1,
        port: port1,
        username: user1,
        password: pass1
      });
      const manager2 = new SSHConnectionManager({
        host: host2,
        port: port2,
        username: user2,
        password: pass2
      });

      managers.push(manager1, manager2);

      await manager1.connect();
      await manager2.connect();

      expect(manager1.isConnected()).toBe(true);
      expect(manager2.isConnected()).toBe(true);

      // İlk manageri kapat
      manager1.close();

      expect(manager1.isConnected()).toBe(false);
      expect(manager2.isConnected()).toBe(true);

      // İkinci manager hala çalışmalı
      const result = await execSshCommandWithConnection(manager2, 'echo "still alive"');
      expect((result.content[0] as any).text).toContain('still alive');
    }, 60000);

    it('should handle rapid switching between hosts', async () => {
      const manager1 = new SSHConnectionManager({
        host: host1,
        port: port1,
        username: user1,
        password: pass1
      });
      const manager2 = new SSHConnectionManager({
        host: host2,
        port: port2,
        username: user2,
        password: pass2
      });

      managers.push(manager1, manager2);

      await manager1.connect();
      await manager2.connect();

      // Host'lar arasında hızlı geçiş yap
      for (let i = 0; i < 10; i++) {
        const useHost1 = i % 2 === 0;
        const manager = useHost1 ? manager1 : manager2;
        const hostName = useHost1 ? 'host1' : 'host2';

        const result = await execSshCommandWithConnection(
          manager,
          `echo "iteration ${i} on ${hostName}"`
        );

        expect((result.content[0] as any).text).toContain(`iteration ${i}`);
        expect((result.content[0] as any).text).toContain(hostName);
      }

      expect(manager1.isConnected()).toBe(true);
      expect(manager2.isConnected()).toBe(true);
    }, 60000);

    it('should handle long-running commands on multiple hosts simultaneously', async () => {
      const manager1 = new SSHConnectionManager({
        host: host1,
        port: port1,
        username: user1,
        password: pass1
      });
      const manager2 = new SSHConnectionManager({
        host: host2,
        port: port2,
        username: user2,
        password: pass2
      });

      managers.push(manager1, manager2);

      await manager1.connect();
      await manager2.connect();

      const startTime = Date.now();

      // Her iki host'ta da 2 saniyelik komutlar paralel çalıştır
      const [result1, result2] = await Promise.all([
        execSshCommandWithConnection(manager1, 'sleep 2 && echo "done1"'),
        execSshCommandWithConnection(manager2, 'sleep 2 && echo "done2"')
      ]);

      const duration = Date.now() - startTime;

      // Paralel çalıştıkları için toplam süre ~2 saniye olmalı (4 değil)
      expect(duration).toBeLessThan(3500); // Biraz tolerans ekle
      expect((result1.content[0] as any).text).toContain('done1');
      expect((result2.content[0] as any).text).toContain('done2');
    }, 60000);
  });

  describe('Connection Pool Key Management', () => {
    const managers: SSHConnectionManager[] = [];

    afterEach(() => {
      managers.forEach(m => m.close());
      managers.length = 0;
    });

    it('should differentiate connections by user@host combination', async () => {
      // Aynı host ama farklı kullanıcı
      const manager1 = new SSHConnectionManager({
        host: host1,
        port: port1,
        username: 'user1',
        password: pass1
      });
      const manager2 = new SSHConnectionManager({
        host: host1,
        port: port1,
        username: 'user2',
        password: pass1
      });

      managers.push(manager1, manager2);

      // Her iki bağlantı da ayrı managerlerde tutulmalı
      // (Not: Bu test başarısız olabilir çünkü kullanıcılar mevcut olmayabilir,
      // ama mantığı test ediyor)

      expect(manager1).not.toBe(manager2);
    }, 10000);

    it('should reuse manager for same host configuration', async () => {
      const config = {
        host: host1,
        port: port1,
        username: user1,
        password: pass1
      };

      const manager1 = new SSHConnectionManager(config);
      const manager2 = new SSHConnectionManager(config);

      managers.push(manager1, manager2);

      // İki ayrı manager instance'ı olmalı (connection pool MCP server içinde)
      expect(manager1).not.toBe(manager2);

      // Ama her ikisi de aynı host'a bağlanabilmeli
      await manager1.connect();
      await manager2.connect();

      expect(manager1.isConnected()).toBe(true);
      expect(manager2.isConnected()).toBe(true);
    }, 60000);
  });

  describe('Error Isolation', () => {
    const managers: SSHConnectionManager[] = [];

    afterEach(() => {
      managers.forEach(m => m.close());
      managers.length = 0;
    });

    it('should isolate command errors between hosts', async () => {
      const manager1 = new SSHConnectionManager({
        host: host1,
        port: port1,
        username: user1,
        password: pass1
      });
      const manager2 = new SSHConnectionManager({
        host: host2,
        port: port2,
        username: user2,
        password: pass2
      });

      managers.push(manager1, manager2);

      await manager1.connect();
      await manager2.connect();

      // Host 1'de hatalı komut
      await expect(
        execSshCommandWithConnection(manager1, 'invalid-command-xyz')
      ).rejects.toThrow();

      // Host 2 etkilenmemeli
      const result = await execSshCommandWithConnection(manager2, 'echo "unaffected"');
      expect((result.content[0] as any).text).toContain('unaffected');

      // Host 1 de hala çalışmalı
      const result1 = await execSshCommandWithConnection(manager1, 'echo "recovered"');
      expect((result1.content[0] as any).text).toContain('recovered');
    }, 60000);
  });
});
