import { describe, it, expect } from 'vitest';
import { callbackBeforeDeadline } from '../../../src/ssh/sftp.js';

/**
 * The per-step bound is what stops one SFTP metadata round-trip hanging a whole
 * tool call. It cannot be pinned through a real transfer: against a container on
 * loopback a stat finishes inside a 1ms bound, so the copy's own stall wins the
 * race and this branch never runs. Here the callback is under test control, so
 * "never answers" is exact rather than hoped for.
 */
describe('callbackBeforeDeadline', () => {
  it('rejects when the operation never calls back', async () => {
    const started = Date.now();
    await expect(
      callbackBeforeDeadline({ idleTimeoutMs: 50 }, 'SFTP probe', () => {
        /* deliberately never settles */
      }),
    ).rejects.toThrow(/SFTP probe timed out after 50ms/);
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it('resolves with the value when the operation answers in time', async () => {
    const value = await callbackBeforeDeadline<string>(
      { idleTimeoutMs: 1000 },
      'SFTP probe',
      (cb) => setTimeout(() => cb(undefined, 'answered'), 5),
    );
    expect(value).toBe('answered');
  });

  it('rejects with the operation error rather than the deadline', async () => {
    await expect(
      callbackBeforeDeadline({ idleTimeoutMs: 1000 }, 'SFTP probe', (cb) => {
        cb(new Error('remote said no'));
      }),
    ).rejects.toThrow(/remote said no/);
  });

  // The one that matters for uploadFile's ambiguous-publish handling: the bound
  // covers the wait, and a reply arriving afterwards is dropped rather than
  // flipping an already-rejected promise.
  it('ignores a reply that arrives after the bound expired', async () => {
    let late: ((err?: Error, value?: string) => void) | undefined;
    const pending = callbackBeforeDeadline<string>(
      { idleTimeoutMs: 30 },
      'SFTP probe',
      (cb) => { late = cb; },
    );
    await expect(pending).rejects.toThrow(/timed out after 30ms/);

    // Nothing observable happens, and in particular nothing throws.
    expect(() => late?.(undefined, 'too late')).not.toThrow();
  });

  it('rejects with the signal reason when aborted mid-wait', async () => {
    const controller = new AbortController();
    const reason = new Error('cancelled by caller');
    const pending = callbackBeforeDeadline(
      { idleTimeoutMs: 5000, abortSignal: controller.signal },
      'SFTP probe',
      () => { /* never settles */ },
    );
    controller.abort(reason);
    await expect(pending).rejects.toThrow(/cancelled by caller/);
  });

  it('refuses immediately when the signal is already aborted, without starting the work', async () => {
    const controller = new AbortController();
    controller.abort(new Error('cancelled before start'));
    let started = false;

    await expect(
      callbackBeforeDeadline(
        { idleTimeoutMs: 5000, abortSignal: controller.signal },
        'SFTP probe',
        () => { started = true; },
      ),
    ).rejects.toThrow(/cancelled before start/);
    expect(started).toBe(false);
  });

  // A bare abort() sets `reason` to an AbortError DOMException, and
  // `DOMException instanceof Error` is true in Node — so it passes through
  // rather than hitting the fallback, and the caller still gets a real error
  // with a legible message.
  it('passes through the AbortError a bare abort() produces', async () => {
    const controller = new AbortController();
    const pending = callbackBeforeDeadline(
      { idleTimeoutMs: 5000, abortSignal: controller.signal },
      'SFTP probe',
      () => { /* never settles */ },
    );
    controller.abort();
    await expect(pending).rejects.toThrow(/This operation was aborted/);
  });

  // The fallback exists for the case that is not an Error at all, which
  // abort() accepts and which would otherwise reject with a bare string.
  it('names the step when the signal reason is not an Error', async () => {
    const controller = new AbortController();
    const pending = callbackBeforeDeadline(
      { idleTimeoutMs: 5000, abortSignal: controller.signal },
      'SFTP probe',
      () => { /* never settles */ },
    );
    controller.abort('a bare string');
    await expect(pending).rejects.toThrow(/SFTP probe aborted/);
  });

  it('surfaces a synchronous throw from the operation as a rejection', async () => {
    await expect(
      callbackBeforeDeadline({ idleTimeoutMs: 1000 }, 'SFTP probe', () => {
        // This is how ssh2 reports an unadvertised extension.
        throw new Error('Server does not support this extended request');
      }),
    ).rejects.toThrow(/does not support this extended request/);
  });
});
