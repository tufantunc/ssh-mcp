import { describe, it, expect, vi } from 'vitest';
import { SmartApproval } from '../smart.js';
import { ApprovalContext, SmartApprovalOptions } from '../types.js';

const ctx: ApprovalContext = {
  profile: { id: 'prod', description: 'production host (read-only)' },
  tool: 'exec',
  command: 'ls /tmp',
  description: 'list temp',
};

function makeOkResponse(content: string) {
  const body = JSON.stringify({
    choices: [{ message: { content } }],
  });
  return Promise.resolve({
    ok: true,
    status: 200,
    text: () => Promise.resolve(body),
  });
}

function makeOpts(overrides: Partial<SmartApprovalOptions> = {}): SmartApprovalOptions {
  return {
    llm: {
      endpoint: 'https://example.invalid/v1/chat/completions',
      api_key: 'test-key',
      model: 'gpt-4o-mini',
      timeout_ms: 50,
    },
    fail_closed: true,
    ...overrides,
  };
}

describe('SmartApproval — happy paths', () => {
  it('allows when LLM returns {allow:true}', async () => {
    const fetchImpl = vi.fn(() =>
      makeOkResponse(JSON.stringify({ allow: true, reason: 'looks safe' })),
    );
    const s = new SmartApproval(makeOpts({ fetchImpl: fetchImpl as any }));
    const d = await s.decide(ctx);
    expect(d.decision).toBe('allow');
    expect(d.reason).toBe('looks safe');
    expect(d.decided_by).toBe('smart-llm');
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('denies when LLM returns {allow:false}', async () => {
    const fetchImpl = vi.fn(() =>
      makeOkResponse(JSON.stringify({ allow: false, reason: 'rm -rf detected' })),
    );
    const s = new SmartApproval(makeOpts({ fetchImpl: fetchImpl as any }));
    const d = await s.decide(ctx);
    expect(d.decision).toBe('deny');
    expect(d.reason).toBe('rm -rf detected');
  });

  it('tolerates fenced JSON inside content', async () => {
    const fenced = '```json\n{"allow": true, "reason": "ok"}\n```';
    const fetchImpl = vi.fn(() => makeOkResponse(fenced));
    const s = new SmartApproval(makeOpts({ fetchImpl: fetchImpl as any }));
    const d = await s.decide(ctx);
    expect(d.decision).toBe('allow');
  });

  it('sends Authorization header when api_key is set', async () => {
    const fetchImpl = vi.fn(() =>
      makeOkResponse(JSON.stringify({ allow: true, reason: 'ok' })),
    );
    const s = new SmartApproval(makeOpts({ fetchImpl: fetchImpl as any }));
    await s.decide(ctx);
    const call: any = (fetchImpl as any).mock.calls[0];
    expect(call[1].headers['Authorization']).toBe('Bearer test-key');
    expect(call[1].headers['Content-Type']).toBe('application/json');
  });

  it('redacts command and intent secrets before sending them to the external LLM', async () => {
    const fetchImpl = vi.fn(() =>
      makeOkResponse(JSON.stringify({ allow: true, reason: 'ok' })),
    );
    const command = [
      "curl -H 'Authorization: Bearer bearer-secret' https://example.invalid",
      'mysql -uroot -pdatabase-secret',
      'API_TOKEN=environment-secret deploy',
      'git clone https://alice:url-secret@example.invalid/repo.git',
    ].join(' && ');
    const s = new SmartApproval(makeOpts({ fetchImpl: fetchImpl as any }));

    await s.decide({ ...ctx, command, description: 'password intent-secret' });

    const call: any = (fetchImpl as any).mock.calls[0];
    const userPrompt = JSON.parse(call[1].body).messages
      .find((message: any) => message.role === 'user').content as string;
    expect(userPrompt).toContain('<redacted>');
    for (const secret of [
      'bearer-secret',
      'database-secret',
      'environment-secret',
      'url-secret',
      'intent-secret',
    ]) {
      expect(userPrompt).not.toContain(secret);
    }
    expect(command).toContain('database-secret');
  });
});

describe('SmartApproval — fail-closed (default)', () => {
  it('does not schedule an abort timer when no fetch implementation exists', async () => {
    vi.stubGlobal('fetch', undefined);
    const setTimeoutSpy = vi.spyOn(globalThis, 'setTimeout');
    try {
      const s = new SmartApproval(makeOpts());
      const d = await s.decide(ctx);
      expect(d.decision).toBe('deny');
      expect(d.decided_by).toBe('smart-llm:no-fetch');
      expect(setTimeoutSpy).not.toHaveBeenCalled();
    } finally {
      setTimeoutSpy.mockRestore();
      vi.unstubAllGlobals();
    }
  });

  it('denies on non-200 HTTP', async () => {
    const fetchImpl = vi.fn(() =>
      Promise.resolve({ ok: false, status: 500, text: () => Promise.resolve('') }),
    );
    const s = new SmartApproval(makeOpts({ fetchImpl: fetchImpl as any }));
    const d = await s.decide(ctx);
    expect(d.decision).toBe('deny');
    expect(d.reason).toMatch(/HTTP 500/);
    expect(d.decided_by).toBe('smart-llm:http-500');
  });

  it('denies on malformed JSON body', async () => {
    const fetchImpl = vi.fn(() =>
      Promise.resolve({
        ok: true,
        status: 200,
        text: () => Promise.resolve('not json at all'),
      }),
    );
    const s = new SmartApproval(makeOpts({ fetchImpl: fetchImpl as any }));
    const d = await s.decide(ctx);
    expect(d.decision).toBe('deny');
    expect(d.reason).toMatch(/malformed/);
  });

  it('denies when content is missing the JSON object', async () => {
    const fetchImpl = vi.fn(() => makeOkResponse('I refuse to respond as JSON.'));
    const s = new SmartApproval(makeOpts({ fetchImpl: fetchImpl as any }));
    const d = await s.decide(ctx);
    expect(d.decision).toBe('deny');
    expect(d.reason).toMatch(/no JSON object|malformed/);
  });

  it('denies when JSON lacks boolean `allow`', async () => {
    const fetchImpl = vi.fn(() =>
      makeOkResponse(JSON.stringify({ reason: 'oops, no allow field' })),
    );
    const s = new SmartApproval(makeOpts({ fetchImpl: fetchImpl as any }));
    const d = await s.decide(ctx);
    expect(d.decision).toBe('deny');
  });

  it('denies on timeout (AbortError)', async () => {
    const fetchImpl = vi.fn(
      (_url: string, init: any) =>
        new Promise((_resolve, reject) => {
          init.signal?.addEventListener('abort', () => {
            const err: any = new Error('aborted');
            err.name = 'AbortError';
            reject(err);
          });
        }),
    );
    const s = new SmartApproval(makeOpts({ fetchImpl: fetchImpl as any }));
    const d = await s.decide(ctx);
    expect(d.decision).toBe('deny');
    expect(d.reason).toMatch(/timed out/);
  });

  it('keeps the timeout armed while reading the response body', async () => {
    let signal: AbortSignal | undefined;
    const fetchImpl = vi.fn(
      (_url: string, init: any) => {
        signal = init.signal;
        return Promise.resolve({
          ok: true,
          status: 200,
          text: () => new Promise<string>((_resolve, reject) => {
            signal?.addEventListener('abort', () => {
              const err: any = new Error('aborted while reading body');
              err.name = 'AbortError';
              reject(err);
            });
          }),
        });
      },
    );
    const s = new SmartApproval(makeOpts({
      llm: {
        endpoint: 'https://example.invalid/v1/chat/completions',
        api_key: 'test-key',
        model: 'gpt-4o-mini',
        timeout_ms: 20,
      },
      fetchImpl: fetchImpl as any,
    }));

    const d = await s.decide(ctx);
    expect(d.decision).toBe('deny');
    expect(d.reason).toMatch(/timed out/);
    expect(d.decided_by).toBe('smart-llm:timeout');
  });

  it('denies on transport (network) error', async () => {
    const fetchImpl = vi.fn(() => Promise.reject(new Error('ECONNRESET')));
    const s = new SmartApproval(makeOpts({ fetchImpl: fetchImpl as any }));
    const d = await s.decide(ctx);
    expect(d.decision).toBe('deny');
    expect(d.reason).toMatch(/ECONNRESET/);
  });
});

describe('SmartApproval — fail-open (fail_closed=false)', () => {
  it('allows on non-200 with warning', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const fetchImpl = vi.fn(() =>
      Promise.resolve({ ok: false, status: 502, text: () => Promise.resolve('') }),
    );
    const s = new SmartApproval(makeOpts({ fail_closed: false, fetchImpl: fetchImpl as any }));
    const d = await s.decide(ctx);
    expect(d.decision).toBe('allow');
    expect(d.reason).toMatch(/fail_closed=false/);
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
  });

  it('allows on malformed JSON with warning', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const fetchImpl = vi.fn(() =>
      Promise.resolve({ ok: true, status: 200, text: () => Promise.resolve('garbage') }),
    );
    const s = new SmartApproval(makeOpts({ fail_closed: false, fetchImpl: fetchImpl as any }));
    const d = await s.decide(ctx);
    expect(d.decision).toBe('allow');
    warn.mockRestore();
  });

  it('allows on timeout with warning', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const fetchImpl = vi.fn(
      (_url: string, init: any) =>
        new Promise((_resolve, reject) => {
          init.signal?.addEventListener('abort', () => {
            const err: any = new Error('aborted');
            err.name = 'AbortError';
            reject(err);
          });
        }),
    );
    const s = new SmartApproval(makeOpts({ fail_closed: false, fetchImpl: fetchImpl as any }));
    const d = await s.decide(ctx);
    expect(d.decision).toBe('allow');
    expect(d.reason).toMatch(/timed out/);
    warn.mockRestore();
  });
});

describe('SmartApproval — constructor validation', () => {
  it('throws when endpoint missing', () => {
    expect(
      () =>
        new SmartApproval({
          llm: { endpoint: '', model: 'gpt-4o-mini' } as any,
        }),
    ).toThrow(/endpoint/);
  });

  it('throws when model missing', () => {
    expect(
      () =>
        new SmartApproval({
          llm: { endpoint: 'https://x', model: '' } as any,
        }),
    ).toThrow(/model/);
  });

  it('rejects providers whose request/response schema is not implemented', () => {
    expect(() => new SmartApproval(makeOpts({
      llm: {
        endpoint: 'https://anthropic.example/v1/messages',
        model: 'claude',
        provider: 'anthropic',
      },
    }))).toThrow(/provider "anthropic" is not supported/);
  });
});
