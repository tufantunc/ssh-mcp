import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { stopAndDescribe } from '../../../src/ssh/connection.js';
import { COULD_NOT_SIGNAL } from '../../../src/ssh/channel-signal.js';
import { fakeSsh2Channel, afterStdinClosed } from '../../helpers/fake-channel.js';
import { recordingTracer } from '../../helpers/spans.js';

/**
 * What a stopped exec records on its span. `ssh.unstopped` is the only durable record that
 * a timed-out or cancelled command could not even be signalled — the message is returned
 * to one caller, the span is what an operator can query — and no test read it: removing
 * both of its `setAttribute` calls kept the suite green.
 */

// The escalation ladder's later rungs are timers; nothing here waits for them.
beforeEach(() => { vi.useFakeTimers(); });
afterEach(() => { vi.useRealTimers(); });

function stop(reason: 'ssh.timedOut' | 'ssh.aborted', channel: Parameters<typeof stopAndDescribe>[2]) {
  const { tracer, spans } = recordingTracer();
  const message = stopAndDescribe(tracer.startSpan('ssh.exec'), reason, channel);
  return { message, attributes: spans[0].attributes };
}

describe('stopAndDescribe', () => {
  it('records a stop that was dispatched as not unstopped, and says nothing more', () => {
    const { message, attributes } = stop('ssh.timedOut', fakeSsh2Channel(afterStdinClosed()).channel);
    expect(attributes).toEqual({ 'ssh.timedOut': true, 'ssh.unstopped': false });
    expect(message).toBe('');
  });

  it('records a stop that could not be dispatched, and warns', () => {
    const { message, attributes } = stop('ssh.aborted', fakeSsh2Channel({ ...afterStdinClosed(), _client: undefined }).channel);
    expect(attributes).toEqual({ 'ssh.aborted': true, 'ssh.unstopped': true });
    expect(message).toBe(COULD_NOT_SIGNAL);
  });

  it('defers rather than claims a clean stop when the channel has not arrived', () => {
    // `ssh.unstopped: false` here would assert a clean stop this path cannot know about.
    const { message, attributes } = stop('ssh.timedOut', null);
    expect(attributes).toEqual({ 'ssh.timedOut': true, 'ssh.stopDeferred': true });
    expect(message).toBe('');
  });
});
