import { createServer, type Server } from 'node:http';
import { AddressInfo } from 'node:net';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createReviewerServer } from '../../src/reviewer/sidecar.js';
import { e2eAvailable, startE2E } from './harness.js';

const available = await e2eAvailable();
let servers: Server[] = [];
let e2e: Awaited<ReturnType<typeof startE2E>>;

async function listen(server: Server): Promise<string> {
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

describe.skipIf(!available)('reviewer process boundary', () => {
  beforeEach(async () => {
    const fakeModel = await listen(createServer((req, res) => {
      req.resume();
      req.on('end', () => {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ choices: [{ message: { content: JSON.stringify({
          verdict: 'approve',
          risk: 'low',
          summary: 'The operation is bounded and reversible.',
          findings: [],
        }) } }] }));
      });
    }));
    const reviewer = await listen(createReviewerServer({
      llmBaseUrl: `${fakeModel}/v1`,
      llmModel: 'fake-e2e-model',
      llmTimeoutMs: 1_000,
      port: 0,
    }));
    e2e = await startE2E({ args: [`--reviewerUrl=${reviewer}`, '--reviewerTimeoutMs=2000'] });
  });

  afterEach(async () => {
    await e2e?.cleanup();
    await Promise.all(servers.splice(0).reverse().map((server) =>
      new Promise<void>((resolve) => server.close(() => resolve())),
    ));
  });

  it('lets a model-approved safe write cross the process boundary without a human prompt', async () => {
    const marker = `/tmp/ssh-mcp-reviewer-e2e-${process.pid}`;
    await e2e.callTool('run-command', { command: `touch ${marker}` });
    expect(e2e.prompts).toHaveLength(0);
    await e2e.callTool('run-command', { command: `rm -f ${marker}` });
  });
});
