import { createServer, type RequestListener, type Server } from 'node:http';
import { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { HttpCommandReviewer } from '../../../src/reviewer/http-client.js';

let server: Server | undefined;

async function listen(handler: RequestListener): Promise<string> {
  server = createServer(handler);
  await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

afterEach(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  server = undefined;
});

const input = {
  command: 'echo AKIAIOSFODNN7EXAMPLE',
  tool: 'run-command',
  commandClass: 'safe' as const,
  tier: 'prod',
  readOnly: false,
};

describe('HttpCommandReviewer', () => {
  it('sends only minimal context and redacts the command', async () => {
    let request: any;
    const url = await listen((req, res) => {
      let body = '';
      req.setEncoding('utf8');
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => {
        request = JSON.parse(body);
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({
          schemaVersion: 2,
          verdict: 'approve',
          risk: 'low',
          summary: 'No material risk found.',
          findings: [],
          model: 'fake-model',
          policyVersion: '2',
        }));
      });
    });

    const result = await new HttpCommandReviewer(url, 1_000).review(input);
    expect(result.status).toBe('completed');
    expect(request).toMatchObject({
      schemaVersion: 2,
      tool: 'run-command',
      commandClass: 'safe',
      context: { tier: 'prod', readOnly: false },
    });
    expect(request.command).toContain('[REDACTED:aws-access-key');
    expect(JSON.stringify(request)).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(request.host).toBeUndefined();
    expect(request.user).toBeUndefined();
  });

  it('maps malformed JSON to unavailable instead of throwing', async () => {
    const url = await listen((_req, res) => res.end('not-json'));
    const result = await new HttpCommandReviewer(url, 1_000).review(input);
    expect(result).toMatchObject({ status: 'unavailable', risk: 'unknown' });
  });

  it('rejects a structurally invalid review', async () => {
    const url = await listen((_req, res) => {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ schemaVersion: 2, verdict: 'approve', risk: 'safe', summary: 'wrong enum', findings: [] }));
    });
    const result = await new HttpCommandReviewer(url, 1_000).review(input);
    expect(result.status).toBe('unavailable');
  });

  it('rejects a contradictory verdict and risk', async () => {
    const url = await listen((_req, res) => {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({
        schemaVersion: 2, verdict: 'approve', risk: 'high', summary: 'contradiction',
        findings: [], model: 'fake-model', policyVersion: '2',
      }));
    });
    const result = await new HttpCommandReviewer(url, 1_000).review(input);
    expect(result).toMatchObject({ status: 'unavailable', verdict: 'escalate' });
  });

  it('bounds the response body', async () => {
    const url = await listen((_req, res) => res.end('x'.repeat(70_000)));
    const result = await new HttpCommandReviewer(url, 1_000).review(input);
    expect(result.status).toBe('unavailable');
    expect(result.summary).toMatch(/unavailable/i);
  });

  it('times out without retrying', async () => {
    let calls = 0;
    const url = await listen((_req, _res) => { calls++; });
    const result = await new HttpCommandReviewer(url, 25).review(input);
    expect(result.status).toBe('unavailable');
    expect(calls).toBe(1);
  });
});
