import type { ServerResponse } from 'node:http';
import type { ManualApprovalQueue, AuditTail, ModeController, ModeChangedEvent } from '../types.js';

export interface SseClient {
  res: ServerResponse;
  /** Heartbeat timer; cleared on disconnect. */
  timer: NodeJS.Timeout;
}

/**
 * SSE broadcaster. Keeps a list of active responses and forwards
 * pending-approval / execution / mode-changed events to all of them.
 *
 * Heartbeat comment lines every 25s keep idle clients warm through proxies.
 */
export class SseHub {
  private clients = new Set<SseClient>();
  private queueListenersEnq?: (...args: any[]) => void;
  private queueListenersRes?: (...args: any[]) => void;
  private auditListener?: (...args: any[]) => void;
  private modeListener?: (...args: any[]) => void;

  constructor(
    private readonly queue?: ManualApprovalQueue,
    private readonly audit?: AuditTail,
    private readonly modeController?: ModeController,
  ) {
    if (this.queue) {
      this.queueListenersEnq = (p: any) => this.broadcast('pending-approval', { action: 'enqueue', approval: p });
      this.queueListenersRes = (p: any, d: any) => this.broadcast('pending-approval', { action: 'resolve', approval: p, decision: d });
      this.queue.on('enqueue', this.queueListenersEnq as any);
      this.queue.on('resolve', this.queueListenersRes as any);
    }
    if (this.audit) {
      this.auditListener = (r: any) => this.broadcast('execution', r);
      this.audit.on('execution', this.auditListener as any);
    }
    if (this.modeController) {
      this.modeListener = (e: ModeChangedEvent) => this.broadcast('mode-changed', e);
      this.modeController.on('mode-changed', this.modeListener as any);
    }
  }

  private removeClient(client: SseClient): void {
    clearInterval(client.timer);
    this.clients.delete(client);
  }

  private dropClient(client: SseClient): void {
    if (!this.clients.has(client)) return;
    this.removeClient(client);
    try { client.res.destroy(); } catch { /* ignore */ }
  }

  private writeToClient(client: SseClient, data: string): boolean {
    try {
      if (client.res.write(data)) return true;
    } catch { /* drop below */ }
    this.dropClient(client);
    return false;
  }

  attach(res: ServerResponse): SseClient {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    let client!: SseClient;
    const timer = setInterval(() => {
      this.writeToClient(client, `: heartbeat\n\n`);
    }, 25000);
    // Don't block process exit on the heartbeat timer.
    if (typeof (timer as any).unref === 'function') (timer as any).unref();

    client = { res, timer };
    this.clients.add(client);

    const cleanup = () => {
      this.removeClient(client);
    };
    res.on('close', cleanup);
    res.on('error', cleanup);
    this.writeToClient(client, `: connected ${new Date().toISOString()}\n\n`);
    return client;
  }

  broadcast(event: string, payload: unknown): void {
    const data = `event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`;
    for (const c of this.clients) {
      this.writeToClient(c, data);
    }
  }

  size(): number {
    return this.clients.size;
  }

  closeAll(): void {
    for (const c of this.clients) {
      clearInterval(c.timer);
      try { c.res.end(); } catch { /* ignore */ }
    }
    this.clients.clear();
    if (this.queue && this.queue.off) {
      if (this.queueListenersEnq) this.queue.off('enqueue', this.queueListenersEnq);
      if (this.queueListenersRes) this.queue.off('resolve', this.queueListenersRes);
    }
    if (this.audit && this.audit.off && this.auditListener) {
      this.audit.off('execution', this.auditListener);
    }
    if (this.modeController && this.modeController.off && this.modeListener) {
      this.modeController.off('mode-changed', this.modeListener);
    }
  }
}
