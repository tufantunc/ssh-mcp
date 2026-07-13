import { EventEmitter } from 'node:events';
import type { ServerResponse } from 'node:http';
import { describe, expect, it, vi } from 'vitest';

import { SseHub } from '../routes/sse.js';

function responseWithWrites(...results: boolean[]): ServerResponse {
  const events = new EventEmitter();
  return {
    writeHead: vi.fn(),
    write: vi.fn()
      .mockReturnValueOnce(results[0] ?? true)
      .mockReturnValueOnce(results[1] ?? true),
    end: vi.fn(),
    destroy: vi.fn(),
    on: events.on.bind(events),
  } as unknown as ServerResponse;
}

describe('SseHub backpressure', () => {
  it('drops a client when a broadcast write reports backpressure', () => {
    const hub = new SseHub();
    const response = responseWithWrites(true, false);

    hub.attach(response);
    expect(hub.size()).toBe(1);

    hub.broadcast('execution', { id: 'x' });

    expect(hub.size()).toBe(0);
    expect(response.destroy).toHaveBeenCalledTimes(1);
  });
});
