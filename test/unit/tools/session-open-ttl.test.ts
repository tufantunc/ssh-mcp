import { describe, it, expect } from 'vitest';
import { createHarness, textOf } from './harness.js';

/**
 * `open-session` carries a per-call `ttlMs`.
 *
 * SessionManager.open() already honoured `opts.ttlMs`, but the tool schema never
 * exposed it, so the layer that hands a command over was the only one that could
 * not ask for a session longer-lived than the profile's idle timeout. A job that
 * runs for hours — or days — had to change a global setting instead.
 */

describe('open-session ttlMs', () => {
  it('forwards an explicit ttlMs to the connection', async () => {
    const h = await createHarness();
    try {
      await h.client.callTool({
        name: 'open-session',
        arguments: { name: 'long-job', type: 'background', command: 'sleep 100', ttlMs: 0 },
      });

      expect(h.openSessionCalls).toHaveLength(1);
      expect(h.openSessionCalls[0]).toMatchObject({ name: 'long-job', type: 'background', ttlMs: 0 });
    } finally {
      await h.close();
    }
  });

  it('leaves ttlMs undefined when the caller did not ask, so the profile default applies', async () => {
    const h = await createHarness();
    try {
      await h.client.callTool({
        name: 'open-session',
        arguments: { name: 'default-job', type: 'background', command: 'sleep 100' },
      });

      expect(h.openSessionCalls[0].ttlMs).toBeUndefined();
    } finally {
      await h.close();
    }
  });

  it('rejects a negative ttlMs instead of passing it on', async () => {
    const h = await createHarness();
    try {
      const res: any = await h.client.callTool({
        name: 'open-session',
        arguments: { name: 'bad', type: 'background', command: 'sleep 1', ttlMs: -1 },
      });

      expect(res.isError).toBe(true);
      expect(h.openSessionCalls).toHaveLength(0);
    } finally {
      await h.close();
    }
  });

  it('still reports the opened session', async () => {
    const h = await createHarness();
    try {
      const res: any = await h.client.callTool({
        name: 'open-session',
        arguments: { name: 'ttl-job', type: 'background', command: 'sleep 100', ttlMs: 3_600_000 },
      });

      expect(textOf(res)).toContain('ttl-job');
    } finally {
      await h.close();
    }
  });
});
