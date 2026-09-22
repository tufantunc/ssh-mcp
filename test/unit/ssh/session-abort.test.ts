import { describe, it, expect, vi, afterEach } from 'vitest';
import { EventEmitter } from 'events';
import type { ClientChannel } from 'ssh2';
import { InteractiveSession } from '../../../src/ssh/session.js';

/**
 * Cancelling a command that is running inside an interactive session.
 *
 * This path existed and worked; what it did not have was a test of its own. Its
 * coverage came from somewhere in the suite that reaches it only on some runs —
 * it is covered in CI and not covered by the same command locally — so the lines
 * moved in and out of the report depending on which run you looked at, and a
 * change that touched session *setup* could shift them without touching the
 * abort logic at all. That is what happened on #227: 31 lines here changed state
 * on a diff that does not modify this file.
 *
 * Driving `InteractiveSession` directly with a fake channel makes it
 * deterministic. No ssh2, no container, no race: the three behaviours below are
 * the contract, and they either hold or they do not.
 */

/** A channel that records what was written and answers only when told to. */
function fakeChannel() {
  const writes: string[] = [];
  const signals: string[] = [];
  const channel = Object.assign(new EventEmitter(), {
    writes,
    signals,
    /** Assigned below; declared here so the object carries its own type. */
    completeLastCommand: (_stdout: string, _exitCode?: number, _cwd?: string) => { /* replaced */ },
    write: vi.fn((chunk: unknown) => { writes.push(String(chunk)); return true; }),
    signal: vi.fn((name: string) => { signals.push(name); return true; }),
    end: vi.fn(),
    close: vi.fn(),
    stderr: new EventEmitter(),
  });
  /**
   * Answer the last command the way a shell would: the begin marker, the
   * output, then the trailer carrying `$?` and `$PWD`. The markers are built
   * from split literals in `run()`, so they are read back out of the written
   * line rather than guessed.
   */
  channel.completeLastCommand = (stdout: string, exitCode = 0, cwd = '/srv') => {
    const line = writes[writes.length - 1];
    const begin = /printf '%s%s\\n' '([^']+)' '([^']+)'/.exec(line);
    const end = /printf '%s%s__%s__%s\\n' '([^']+)' '([^']+)'/.exec(line);
    if (!begin || !end) throw new Error(`no markers in written line: ${line}`);
    channel.emit('data', Buffer.from(
      `${begin[1]}${begin[2]}\n${stdout}\n${end[1]}${end[2]}__${exitCode}__${cwd}\n`,
    ));
  };
  return channel;
}

function session() {
  const channel = fakeChannel();
  return {
    channel,
    sess: new InteractiveSession('id-1', 'work', 'prod', channel as unknown as ClientChannel, 60_000),
  };
}

afterEach(() => { vi.useRealTimers(); });

describe('cancelling a command in an interactive session', () => {
  it('refuses before sending anything when the signal is already aborted', async () => {
    // The branch that matters most: an abort that arrives before the run starts
    // must not reach the host at all. Asserting the rejection alone would pass
    // even if the command had been written to the channel first.
    const { sess, channel } = session();
    const controller = new AbortController();
    controller.abort();

    await expect(sess.run('rm -rf /tmp/x', 60_000, controller.signal))
      .rejects.toThrow('Command aborted before execution');
    expect(channel.writes, 'nothing may be sent to the host').toEqual([]);
  });

  it('interrupts a command that is already running, then escalates to TERM', async () => {
    vi.useFakeTimers();
    const { sess, channel } = session();
    const controller = new AbortController();

    const run = sess.run('sleep 300', 60_000, controller.signal);
    // The command is on the wire; the shell has answered nothing yet.
    expect(channel.writes).toHaveLength(1);
    expect(channel.writes[0]).toContain('sleep 300');

    controller.abort();
    await expect(run).rejects.toThrow('Command aborted');

    // ^C first, because a signal on the channel kills the shell rather than the
    // command running in it.
    expect(channel.writes[1], 'an interrupt is written to the running shell').toBe('\x03');
    expect(channel.signals, 'TERM must not be immediate').toEqual([]);

    vi.advanceTimersByTime(1000);
    expect(channel.signals, 'TERM follows if the interrupt did not take').toEqual(['TERM']);
  });

  it('detaches the abort listener when the command completes normally', async () => {
    // The leak this guards is specific: the listener's closure retains the run's
    // buffer, which is capped at 2MB, for the lifetime of the signal — and an
    // MCP request's signal can outlive many runs. Asserting on
    // removeEventListener rather than on a later abort being harmless, because a
    // later abort is harmless either way once `resolved` is set: that assertion
    // would pass with the detach deleted.
    const { sess, channel } = session();
    const controller = new AbortController();
    const detach = vi.spyOn(controller.signal, 'removeEventListener');

    const run = sess.run('echo hi', 60_000, controller.signal);
    channel.completeLastCommand('hi');

    const result = await run;
    expect(result.stdout).toBe('hi');
    expect(result.exitCode).toBe(0);
    expect(detach, 'the listener outlives the run without this').toHaveBeenCalledWith(
      'abort', expect.any(Function),
    );
  });

  it('times out a command that never finishes, then escalates to TERM', async () => {
    // Same environment-dependent coverage as the abort path, and the same fix:
    // the timeout handler is reached in CI and not by the same command locally,
    // because it needs a command that genuinely never returns. A fake channel
    // that simply never answers is deterministic. Note the escalation delay is
    // 500ms here and 1000ms on the abort path — pinning both stops one being
    // "corrected" to match the other.
    vi.useFakeTimers();
    const { sess, channel } = session();

    const run = sess.run('sleep 300', 1000);
    expect(channel.writes).toHaveLength(1);

    vi.advanceTimersByTime(1000);
    await expect(run).rejects.toThrow('Command timed out after 1000ms in session work');
    expect(channel.writes[1], 'an interrupt is written before any signal').toBe('\x03');
    expect(channel.signals).toEqual([]);

    vi.advanceTimersByTime(500);
    expect(channel.signals).toEqual(['TERM']);
  });

  it('runs without a signal at all, and leaves the abort path untouched', async () => {
    // The default path still works — `detachAbort` starts as a no-op and every
    // settle path calls it, so a wrong initialiser would throw here rather than
    // anywhere the abort tests look.
    const { sess, channel } = session();
    const run = sess.run('echo hi');
    channel.completeLastCommand('hi');
    await expect(run).resolves.toMatchObject({ stdout: 'hi', exitCode: 0 });
  });
});
