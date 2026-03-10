import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { SSHConnectionManager } from '../src/index';

const host = process.env.SSH_HOST || '127.0.0.1';
const port = Number(process.env.SSH_PORT || 2222);
const username = process.env.SSH_USER || 'test';
const password = process.env.SSH_PASSWORD || 'secret';

describe('SFTP File Transfer', () => {
  let manager: SSHConnectionManager;

  beforeEach(async () => {
    manager = new SSHConnectionManager({ host, port, username, password });
    await manager.connect();
  });

  afterEach(() => {
    manager.close();
  });

  describe('getSftp()', () => {
    it('should return an SFTP session', async () => {
      const sftp = await manager.getSftp();
      expect(sftp).toBeDefined();
      sftp.end();
    }, 30000);

    it('should throw if not connected', () => {
      manager.close();
      expect(() => manager.getSftp()).toThrow();
    }, 10000);

    it('should provide multiple independent SFTP sessions', async () => {
      const sftp1 = await manager.getSftp();
      const sftp2 = await manager.getSftp();
      expect(sftp1).toBeDefined();
      expect(sftp2).toBeDefined();
      expect(sftp1).not.toBe(sftp2);
      sftp1.end();
      sftp2.end();
    }, 30000);
  });

  describe('Upload (writeFile)', () => {
    it('should upload a text file', async () => {
      const sftp = await manager.getSftp();
      const remotePath = '/tmp/test_sftp_upload.txt';
      const content = 'Hello from SFTP test!';

      await new Promise<void>((resolve, reject) => {
        sftp.writeFile(remotePath, Buffer.from(content, 'utf8'), (err) => {
          if (err) reject(err);
          else resolve();
        });
      });

      // Verify by reading it back
      const data = await new Promise<Buffer>((resolve, reject) => {
        sftp.readFile(remotePath, (err, buf) => {
          if (err) reject(err);
          else resolve(buf);
        });
      });

      expect(data.toString('utf8')).toBe(content);

      // Cleanup
      await new Promise<void>((resolve, reject) => {
        sftp.unlink(remotePath, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
      sftp.end();
    }, 30000);

    it('should upload a binary file (base64 round-trip)', async () => {
      const sftp = await manager.getSftp();
      const remotePath = '/tmp/test_sftp_binary.bin';
      // Create binary content with bytes 0-255
      const binaryBuffer = Buffer.alloc(256);
      for (let i = 0; i < 256; i++) binaryBuffer[i] = i;

      await new Promise<void>((resolve, reject) => {
        sftp.writeFile(remotePath, binaryBuffer, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });

      const data = await new Promise<Buffer>((resolve, reject) => {
        sftp.readFile(remotePath, (err, buf) => {
          if (err) reject(err);
          else resolve(buf);
        });
      });

      expect(data.toString('base64')).toBe(binaryBuffer.toString('base64'));

      await new Promise<void>((resolve, reject) => {
        sftp.unlink(remotePath, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
      sftp.end();
    }, 30000);

    it('should overwrite an existing file', async () => {
      const sftp = await manager.getSftp();
      const remotePath = '/tmp/test_sftp_overwrite.txt';

      // Write initial content
      await new Promise<void>((resolve, reject) => {
        sftp.writeFile(remotePath, Buffer.from('original'), (err) => {
          if (err) reject(err);
          else resolve();
        });
      });

      // Overwrite
      await new Promise<void>((resolve, reject) => {
        sftp.writeFile(remotePath, Buffer.from('overwritten'), (err) => {
          if (err) reject(err);
          else resolve();
        });
      });

      const data = await new Promise<Buffer>((resolve, reject) => {
        sftp.readFile(remotePath, (err, buf) => {
          if (err) reject(err);
          else resolve(buf);
        });
      });

      expect(data.toString('utf8')).toBe('overwritten');

      await new Promise<void>((resolve, reject) => {
        sftp.unlink(remotePath, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
      sftp.end();
    }, 30000);

    it('should upload an empty file', async () => {
      const sftp = await manager.getSftp();
      const remotePath = '/tmp/test_sftp_empty.txt';

      await new Promise<void>((resolve, reject) => {
        sftp.writeFile(remotePath, Buffer.alloc(0), (err) => {
          if (err) reject(err);
          else resolve();
        });
      });

      const data = await new Promise<Buffer>((resolve, reject) => {
        sftp.readFile(remotePath, (err, buf) => {
          if (err) reject(err);
          else resolve(buf);
        });
      });

      expect(data.length).toBe(0);

      await new Promise<void>((resolve, reject) => {
        sftp.unlink(remotePath, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
      sftp.end();
    }, 30000);

    it('should fail to upload to a non-existent directory', async () => {
      const sftp = await manager.getSftp();
      const remotePath = '/nonexistent/dir/file.txt';

      await expect(
        new Promise<void>((resolve, reject) => {
          sftp.writeFile(remotePath, Buffer.from('data'), (err) => {
            if (err) reject(err);
            else resolve();
          });
        })
      ).rejects.toThrow();

      sftp.end();
    }, 30000);
  });

  describe('Download (readFile)', () => {
    it('should download an existing file', async () => {
      const sftp = await manager.getSftp();
      const remotePath = '/tmp/test_sftp_download.txt';
      const content = 'Download test content';

      // Create file first
      await new Promise<void>((resolve, reject) => {
        sftp.writeFile(remotePath, Buffer.from(content, 'utf8'), (err) => {
          if (err) reject(err);
          else resolve();
        });
      });

      // Download it
      const data = await new Promise<Buffer>((resolve, reject) => {
        sftp.readFile(remotePath, (err, buf) => {
          if (err) reject(err);
          else resolve(buf);
        });
      });

      expect(data.toString('utf8')).toBe(content);

      // Cleanup
      await new Promise<void>((resolve, reject) => {
        sftp.unlink(remotePath, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
      sftp.end();
    }, 30000);

    it('should fail to download a non-existent file', async () => {
      const sftp = await manager.getSftp();

      await expect(
        new Promise<Buffer>((resolve, reject) => {
          sftp.readFile('/tmp/this_file_does_not_exist_12345.txt', (err, buf) => {
            if (err) reject(err);
            else resolve(buf);
          });
        })
      ).rejects.toThrow();

      sftp.end();
    }, 30000);

    it('should download a file with special characters in content', async () => {
      const sftp = await manager.getSftp();
      const remotePath = '/tmp/test_sftp_special.txt';
      const content = 'Špeciálne znaky: č, ď, ľ, ĺ, ň, ŕ, š, ť, ž\nNewline\tTab';

      await new Promise<void>((resolve, reject) => {
        sftp.writeFile(remotePath, Buffer.from(content, 'utf8'), (err) => {
          if (err) reject(err);
          else resolve();
        });
      });

      const data = await new Promise<Buffer>((resolve, reject) => {
        sftp.readFile(remotePath, (err, buf) => {
          if (err) reject(err);
          else resolve(buf);
        });
      });

      expect(data.toString('utf8')).toBe(content);

      await new Promise<void>((resolve, reject) => {
        sftp.unlink(remotePath, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
      sftp.end();
    }, 30000);
  });

  describe('Upload then Download round-trip', () => {
    it('should preserve content through upload and download', async () => {
      const sftp = await manager.getSftp();
      const remotePath = '/tmp/test_sftp_roundtrip.txt';
      const content = 'Line 1\nLine 2\nLine 3\n';

      // Upload
      await new Promise<void>((resolve, reject) => {
        sftp.writeFile(remotePath, Buffer.from(content, 'utf8'), (err) => {
          if (err) reject(err);
          else resolve();
        });
      });

      // Download with a fresh SFTP session
      const sftp2 = await manager.getSftp();
      const data = await new Promise<Buffer>((resolve, reject) => {
        sftp2.readFile(remotePath, (err, buf) => {
          if (err) reject(err);
          else resolve(buf);
        });
      });

      expect(data.toString('utf8')).toBe(content);

      // Cleanup
      await new Promise<void>((resolve, reject) => {
        sftp.unlink(remotePath, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
      sftp.end();
      sftp2.end();
    }, 30000);

    it('should handle large file transfer', async () => {
      const sftp = await manager.getSftp();
      const remotePath = '/tmp/test_sftp_large.txt';
      // ~100KB of content
      const content = 'x'.repeat(100 * 1024);

      await new Promise<void>((resolve, reject) => {
        sftp.writeFile(remotePath, Buffer.from(content, 'utf8'), (err) => {
          if (err) reject(err);
          else resolve();
        });
      });

      const data = await new Promise<Buffer>((resolve, reject) => {
        sftp.readFile(remotePath, (err, buf) => {
          if (err) reject(err);
          else resolve(buf);
        });
      });

      expect(data.toString('utf8')).toBe(content);
      expect(data.length).toBe(100 * 1024);

      await new Promise<void>((resolve, reject) => {
        sftp.unlink(remotePath, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
      sftp.end();
    }, 60000);
  });
});
