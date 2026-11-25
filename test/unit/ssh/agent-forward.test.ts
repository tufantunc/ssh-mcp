import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'events';
import type { Profile } from '../../../src/types.js';
import { makeProfile } from '../../fixtures/profile.js';
import { completedChannel } from '../../helpers/fake-channel.js';

/**
 * Agent forwarding is two flags in ssh2: one on connect(), which permits it,
 * and one on each channel, which requests it. A profile that does not ask
 * sets neither. An agent handshake also waits long enough for a FIDO touch.
 */

let connectConfigs: Array<Record<string, unknown>>;
let execOpts: Array<Record<string, unknown> | undefined>;

beforeEach(() => {
  connectConfigs = [];
  execOpts = [];
  vi.resetModules();
  vi.doMock('ssh2', () => {
    class FakeClient extends EventEmitter {
      connect(config: Record<string, unknown>) {
        connectConfigs.push(config);
        setTimeout(() => this.emit('ready'), 0);
        return this;
      }
      exec(
        _cmd: string,
        optsOrCb: Record<string, unknown> | ((err: Error | undefined, stream: unknown) => void),
        maybeCb?: (err: Error | undefined, stream: unknown) => void,
      ) {
        const cb = typeof optsOrCb === 'function' ? optsOrCb : maybeCb!;
        execOpts.push(typeof optsOrCb === 'function' ? undefined : optsOrCb);
        setTimeout(() => cb(undefined, completedChannel()), 0);
      }
      end() { /* nothing to tear down */ }
    }
    return { Client: FakeClient, default: { Client: FakeClient } };
  });
});

afterEach(() => {
  vi.doUnmock('ssh2');
  vi.resetModules();
});

async function open(profile: Profile, agentSocket?: string) {
  const { SSHConnection } = await import('../../../src/ssh/connection.js');
  const conn = new SSHConnection(
    profile,
    agentSocket ? { agentSocket } : { password: 'x' },
    new Map(),
    'insecure',
  );
  await conn.exec('id -un', { timeoutMs: 30_000 });
}

describe('forwardAgent', () => {
  it('does not forward the agent unless the profile asks', async () => {
    await open(makeProfile({ auth: 'agent' }), '/tmp/agent.sock');
    expect(connectConfigs[0]?.agent).toBe('/tmp/agent.sock');
    expect(connectConfigs[0]?.agentForward).toBeUndefined();
    expect(connectConfigs[0]?.readyTimeout).toBe(60_000);
    expect(execOpts[0]?.agentForward).toBeUndefined();
  });

  it('forwards the agent on the connection and on the command channel', async () => {
    await open(makeProfile({ auth: 'agent', forwardAgent: true }), '/tmp/agent.sock');
    expect(connectConfigs[0]?.agentForward).toBe(true);
    expect(execOpts[0]?.agentForward).toBe(true);
  });

  it('keeps the shorter handshake bound when no agent is used', async () => {
    await open(makeProfile());
    expect(connectConfigs[0]?.readyTimeout).toBe(20_000);
    expect(connectConfigs[0]?.agentForward).toBeUndefined();
  });
});
