import { describe, it, expect, vi } from 'vitest';
import { SmartApproval } from '../smart.js';
import { redactApprovalText } from '../redactor.js';
import { ApprovalContext, SmartApprovalOptions } from '../types.js';

const ctx: ApprovalContext = {
  profile: { id: 'prod', description: 'production host (read-only)' },
  tool: 'exec',
  command: 'ls /tmp',
  description: 'list temp',
};

function makeRawResponse(raw: string) {
  const bytes = new TextEncoder().encode(raw);
  let delivered = false;
  return {
    ok: true,
    status: 200,
    headers: { get: (name: string) => name.toLowerCase() === 'content-length' ? String(bytes.byteLength) : null },
    body: {
      getReader: () => ({
        read: async () => {
          if (delivered) return { done: true as const, value: undefined };
          delivered = true;
          return { done: false as const, value: bytes };
        },
        cancel: async () => { delivered = true; },
      }),
    },
    text: vi.fn(() => Promise.resolve(raw)),
  };
}

function makeOkResponse(content: string) {
  const raw = JSON.stringify({
    choices: [{ message: { content } }],
  });
  return Promise.resolve(makeRawResponse(raw));
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

describe('redactApprovalText', () => {
  it('handles long non-URL context without quadratic URL matching', () => {
    const input = 'a'.repeat(40_000);
    const startedAt = performance.now();

    expect(redactApprovalText(input)).toBe(input);
    expect(performance.now() - startedAt).toBeLessThan(300);
  });
});

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

  it('redacts profile description secrets before sending them to the external LLM', async () => {
    const fetchImpl = vi.fn(() =>
      makeOkResponse(JSON.stringify({ allow: true, reason: 'ok' })),
    );
    const s = new SmartApproval(makeOpts({ fetchImpl: fetchImpl as any }));

    await s.decide({
      ...ctx,
      profile: { ...ctx.profile, description: 'production host password=profile-secret' },
    });

    const call: any = (fetchImpl as any).mock.calls[0];
    const userPrompt = JSON.parse(call[1].body).messages
      .find((message: any) => message.role === 'user').content as string;
    expect(userPrompt).toContain('Description: production host password=<redacted>');
    expect(userPrompt).not.toContain('profile-secret');
  });

  it('does not duplicate a description already appended to the command', async () => {
    const description = 'rotate logs safely';
    const fetchImpl = vi.fn(() =>
      makeOkResponse(JSON.stringify({ allow: true, reason: 'ok' })),
    );
    const s = new SmartApproval(makeOpts({ fetchImpl: fetchImpl as any }));

    await s.decide({
      ...ctx,
      command: `printf ok # ${description}`,
      description,
    });

    const call: any = (fetchImpl as any).mock.calls[0];
    const userPrompt = JSON.parse(call[1].body).messages
      .find((message: any) => message.role === 'user').content as string;
    expect(userPrompt.match(new RegExp(description, 'g'))).toHaveLength(1);
    expect(userPrompt).toContain(`Command:\nprintf ok\nCommand intent: ${description}`);
  });

  it('bounds every context field before sending the external LLM request', async () => {
    const maxFieldBytes = 16 * 1024;
    const boundedButTruncatedBytes = maxFieldBytes + 2048;
    const fetchImpl = vi.fn(() =>
      makeOkResponse(JSON.stringify({ allow: true, reason: 'ok' })),
    );
    const s = new SmartApproval(makeOpts({ fetchImpl: fetchImpl as any }));

    await s.decide({
      ...ctx,
      profile: {
        ...ctx.profile,
        description: `profile-start ${'p'.repeat(boundedButTruncatedBytes)} profile-tail`,
      },
      command: `command-start ${'c'.repeat(boundedButTruncatedBytes)} command-tail`,
      description: `intent-start ${'i'.repeat(boundedButTruncatedBytes)} intent-tail`,
    });

    const call: any = (fetchImpl as any).mock.calls[0];
    const userPrompt = JSON.parse(call[1].body).messages
      .find((message: any) => message.role === 'user').content as string;
    expect(Buffer.byteLength(userPrompt, 'utf8')).toBeLessThanOrEqual(maxFieldBytes * 3 + 512);
    expect((userPrompt.match(/<truncated>/g) ?? [])).toHaveLength(3);
    expect(userPrompt).not.toMatch(/profile-tail|command-tail|intent-tail/);
  });

  it('rejects oversized context before redaction or an external request', async () => {
    const fetchImpl = vi.fn(() =>
      makeOkResponse(JSON.stringify({ allow: true, reason: 'ok' })),
    );
    const s = new SmartApproval(makeOpts({ fetchImpl: fetchImpl as any }));

    const d = await s.decide({
      ...ctx,
      description: `intent-start ${'i'.repeat(2 * 1024 * 1024)} intent-tail`,
    });

    expect(d.decision).toBe('deny');
    expect(d.decided_by).toBe('smart-llm:context-too-large');
    expect(d.reason).toMatch(/context field.*limit/i);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('redacts standalone OpenAI API keys before sending them to the external LLM', async () => {
    const legacy = 'sk-' + 'A'.repeat(48);
    const project = 'sk-proj-' + 'B'.repeat(80);
    const fetchImpl = vi.fn(() =>
      makeOkResponse(JSON.stringify({ allow: true, reason: 'ok' })),
    );
    const s = new SmartApproval(makeOpts({ fetchImpl: fetchImpl as any }));

    await s.decide({
      ...ctx,
      command: `printf %s ${legacy}`,
      description: `rotate ${project}`,
    });

    const call: any = (fetchImpl as any).mock.calls[0];
    const userPrompt = JSON.parse(call[1].body).messages
      .find((message: any) => message.role === 'user').content as string;
    expect(userPrompt).not.toContain(legacy);
    expect(userPrompt).not.toContain(project);
    expect((userPrompt.match(/<redacted>/g) ?? []).length).toBe(2);
  });

  it('redacts compact JWTs with non-eyJ payload segments before sending them to the external LLM', async () => {
    const header = Buffer.from('{"alg":"HS256"}').toString('base64url');
    const payload = Buffer.from('{}').toString('base64url');
    const signature = 's'.repeat(43);
    const token = `${header}.${payload}.${signature}`;
    expect(header).toMatch(/^eyJ/);
    expect(payload).not.toMatch(/^eyJ/);
    expect(redactApprovalText(token)).toBe('<redacted>');

    const fetchImpl = vi.fn(() =>
      makeOkResponse(JSON.stringify({ allow: true, reason: 'ok' })),
    );
    const s = new SmartApproval(makeOpts({ fetchImpl: fetchImpl as any }));

    await s.decide({ ...ctx, command: `printf %s ${token}` });

    const call: any = (fetchImpl as any).mock.calls[0];
    const userPrompt = JSON.parse(call[1].body).messages
      .find((message: any) => message.role === 'user').content as string;
    expect(userPrompt).not.toContain(token);
    expect(userPrompt).not.toContain(signature);
    expect(userPrompt).toContain('Command:\nprintf %s <redacted>');
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
    const fetchImpl = vi.fn(() => Promise.resolve(makeRawResponse('not json at all')));
    const s = new SmartApproval(makeOpts({ fetchImpl: fetchImpl as any }));
    const d = await s.decide(ctx);
    expect(d.decision).toBe('deny');
    expect(d.reason).toMatch(/malformed/);
  });

  it('rejects a declared oversized response without buffering or parsing it', async () => {
    const response = makeRawResponse('x'.repeat(128 * 1024));
    const readerSpy = vi.spyOn(response.body, 'getReader');
    const fetchImpl = vi.fn(() => Promise.resolve(response));
    const s = new SmartApproval(makeOpts({ fetchImpl: fetchImpl as any }));

    const d = await s.decide(ctx);

    expect(d.decision).toBe('deny');
    expect(d.decided_by).toBe('smart-llm:response-too-large');
    expect(d.reason).toMatch(/response body.*limit/i);
    expect(readerSpy).not.toHaveBeenCalled();
    expect(response.text).not.toHaveBeenCalled();
  });

  it('cancels a chunked response as soon as its streamed bytes exceed the limit', async () => {
    const chunk = new Uint8Array(40 * 1024).fill(120);
    const cancel = vi.fn(async () => {});
    let reads = 0;
    const response = {
      ok: true,
      status: 200,
      headers: { get: () => null },
      body: {
        getReader: () => ({
          read: async () => reads++ < 2
            ? { done: false as const, value: chunk }
            : { done: true as const, value: undefined },
          cancel,
        }),
      },
      text: vi.fn(() => Promise.resolve('x'.repeat(80 * 1024))),
    };
    const fetchImpl = vi.fn(() => Promise.resolve(response));
    const s = new SmartApproval(makeOpts({ fetchImpl: fetchImpl as any }));

    const d = await s.decide(ctx);

    expect(d.decision).toBe('deny');
    expect(d.decided_by).toBe('smart-llm:response-too-large');
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(response.text).not.toHaveBeenCalled();
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
          headers: { get: () => null },
          body: {
            getReader: () => ({
              read: () => new Promise((_resolve, reject) => {
                signal?.addEventListener('abort', () => {
                  const err: any = new Error('aborted while reading body');
                  err.name = 'AbortError';
                  reject(err);
                });
              }),
              cancel: async () => {},
            }),
          },
          text: () => Promise.reject(new Error('streaming reader must be used')),
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
    const fetchImpl = vi.fn(() => Promise.resolve(makeRawResponse('garbage')));
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
