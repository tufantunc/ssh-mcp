import { describe, it, expect } from 'vitest';
import { createHarness, textOf } from './harness.js';

/**
 * `open-session` carries a per-call `ttlMs`.
 *
 * SessionManager.open() already honoured `opts.ttlMs`, but the tool schema never
 * exposed it, so the layer that hands a command over was the only one that could
 * not ask for a session longer-lived than the profile's idle timeout. A job that
 * runs for hours — or days — had to change a global setting instead. How far a call
 * may go is SessionManager.open()'s to decide; see test/unit/ssh/session-ttl-zero.test.ts.
 */

describe('open-session ttlMs', () => {
  it('forwards an explicit ttlMs to the connection', async () => {
    const h = await createHarness();
    try {
      await h.client.callTool({
        name: 'open-session',
        arguments: { name: 'long-job', type: 'background', command: 'sleep 100', ttlMs: 1_800_000 },
      });

      expect(h.openSessionCalls).toHaveLength(1);
      expect(h.openSessionCalls[0]).toMatchObject({ name: 'long-job', type: 'background', ttlMs: 1_800_000 });
    } finally {
      await h.close();
    }
  });

  it('forwards ttlMs for an interactive session too', async () => {
    const h = await createHarness();
    try {
      await h.client.callTool({ name: 'open-session', arguments: { name: 'sh', type: 'interactive', ttlMs: 30_000 } });
      expect(h.openSessionCalls[0]).toMatchObject({ name: 'sh', type: 'interactive', ttlMs: 30_000 });
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

  it.each([-1, 0])('rejects ttlMs %d at the tool boundary instead of passing it on', async (ttlMs) => {
    // 0 is "no idle limit", which only the operator can set, in the profile.
    const h = await createHarness();
    try {
      const res: any = await h.client.callTool({
        name: 'open-session',
        arguments: { name: 'bad', type: 'background', command: 'sleep 1', ttlMs },
      });

      expect(res.isError).toBe(true);
      expect(textOf(res), 'refused for a reason other than ttlMs').toMatch(/ttlMs/);
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
