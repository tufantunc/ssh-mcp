import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { createServer, type Server } from 'http';
import { AddressInfo } from 'net';
import { PolicyEngine, DEFAULT_RULES } from '../../../src/policy/engine.js';
import type { Profile } from '../../../src/types.js';

/**
 * OPA is the second authorization layer, and none of it was covered.
 *
 * Two guarantees live here and neither is visible from the outside once it
 * breaks. The deny branch is a gate some operators deploy as their real
 * authorization boundary — if it stops denying, nothing says so. And the
 * fallback is deliberately fail-open, which is only defensible because it is
 * loud: an operator whose OPA is down keeps running commands OPA would have
 * refused, and the warning is their only signal.
 *
 * A real HTTP server rather than a stubbed fetch, so the error paths — a 500, a
 * refused connection — are the ones the code will actually meet.
 */
function makeProfile(overrides: Partial<Profile> = {}): Profile {
  return {
    name: 'dev', group: 'dev', host: 'localhost', port: 22, user: 'test',
    auth: 'agent', tty: false, timeout: 60000, maxChars: 5000,
    maxOutputBytes: 1048576, role: 'operator', readOnly: false,
    approvalPolicy: 'ask-destructive', cert: false,
    sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 60000,
    sessionBackgroundMaxMs: 3600000, commandQuotaPerDay: 0,
    ...overrides,
  };
}

describe('OPA evaluation', () => {
  let server: Server | undefined;
  let url: string;
  let requests: any[] = [];
  let errSpy: ReturnType<typeof vi.spyOn>;

  async function startOpa(
    handler: (req: any) => { status?: number; body?: unknown; delayMs?: number },
  ) {
    requests = [];
    server = createServer((req, res) => {
      let raw = '';
      req.on('data', (c) => (raw += c));
      req.on('end', () => {
        const parsed = raw ? JSON.parse(raw) : {};
        requests.push(parsed);
        const { status = 200, body = {}, delayMs = 0 } = handler(parsed);
        // `delayMs` stands in for a loaded sidecar: healthy, answering, just slow.
        const respond = () => {
          res.writeHead(status, { 'content-type': 'application/json' });
          res.end(JSON.stringify(body));
        };
        if (delayMs > 0) setTimeout(respond, delayMs).unref();
        else respond();
      });
    });
    await new Promise<void>((r) => server!.listen(0, '127.0.0.1', r));
    url = `http://127.0.0.1:${(server!.address() as AddressInfo).port}`;
  }

  beforeEach(() => {
    errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  // The parameter needs an annotation: `mock.calls` is typed loosely enough that
  // a bare `(c) => ...` is an implicit any under stricter compiler settings, and
  // it failed the build on the TypeScript bump rather than in the run that
  // introduced it.
  const warnings = (): string =>
    errSpy.mock.calls.map((c: unknown[]) => String(c[0])).join('\n');

  afterEach(async () => {
    vi.restoreAllMocks();
    if (server) await new Promise<void>((r) => server!.close(() => r()));
    server = undefined;
  });

  it('denies when OPA says no, even though the local policy allowed it', async () => {
    await startOpa(() => ({ body: { result: false } }));
    const engine = new PolicyEngine(DEFAULT_RULES);
    engine.setOpaUrl(url);

    const local = engine.evaluate('ls -la', makeProfile(), 'read-command');
    expect(local.decision).not.toBe('deny');

    const result = await engine.evaluateWithOpa('ls -la', makeProfile(), 'read-command');
    expect(result.decision).toBe('deny');
    expect(result.ruleId).toBe('opa');
  });

  it('keeps the local decision when OPA says yes', async () => {
    await startOpa(() => ({ body: { result: true } }));
    const engine = new PolicyEngine(DEFAULT_RULES);
    engine.setOpaUrl(url);

    const result = await engine.evaluateWithOpa('ls -la', makeProfile(), 'read-command');
    expect(result.decision).not.toBe('deny');
    expect(result.ruleId).not.toBe('opa');
  });

  // The request body is the whole basis on which an operator writes their rego.
  // If a field is dropped or renamed, their policy silently stops matching and
  // evaluates against undefined.
  it('sends the subject, action, resource and context the policy is written against', async () => {
    await startOpa(() => ({ body: { result: true } }));
    const engine = new PolicyEngine(DEFAULT_RULES);
    engine.setOpaUrl(url);

    await engine.evaluateWithOpa('rm -rf /tmp/build', makeProfile({ role: 'admin', name: 'prod' }), 'run-command');

    expect(requests).toHaveLength(1);
    const { input } = requests[0];
    expect(input.subject).toEqual({ role: 'admin', profile: 'prod' });
    expect(input.action).toEqual({ tool: 'run-command', commandClass: 'destructive' });
    expect(input.resource.binary).toBe('rm');
    expect(input.resource.host).toBe('localhost');
    expect(input.context).toEqual({ readOnly: false });
  });

  it('does not consult OPA when the local policy already denied', async () => {
    await startOpa(() => ({ body: { result: true } }));
    const engine = new PolicyEngine(DEFAULT_RULES);
    engine.setOpaUrl(url);

    // A forbidden command is denied locally; asking OPA could only overturn it.
    const result = await engine.evaluateWithOpa('rm -rf /', makeProfile(), 'run-command');
    expect(result.decision).toBe('deny');
    expect(requests).toHaveLength(0);
  });

  describe('when OPA is unavailable', () => {
    it('falls back to the local decision on an HTTP error, and says so', async () => {
      await startOpa(() => ({ status: 500, body: { error: 'boom' } }));
      const engine = new PolicyEngine(DEFAULT_RULES);
      engine.setOpaUrl(url);

      const result = await engine.evaluateWithOpa('ls -la', makeProfile(), 'read-command');
      expect(result.decision).not.toBe('deny');

      const warning = warnings();
      expect(warning).toContain('POLICY WARNING');
      // The consequence, not just the symptom: silence here is the whole risk.
      expect(warning).toMatch(/may now be allowed/);
    });

    it('falls back when nothing is listening, and says so', async () => {
      const engine = new PolicyEngine(DEFAULT_RULES);
      engine.setOpaUrl('http://127.0.0.1:1');

      const result = await engine.evaluateWithOpa('ls -la', makeProfile(), 'read-command');
      expect(result.decision).not.toBe('deny');
      expect(warnings()).toContain('POLICY WARNING');
    });

    // Throttled so a dead OPA cannot bury the log — but a throttle that never
    // reopens would silence the signal permanently, so both halves are checked.
    it('warns once per minute rather than on every command', async () => {
      const engine = new PolicyEngine(DEFAULT_RULES);
      engine.setOpaUrl('http://127.0.0.1:1');

      await engine.evaluateWithOpa('ls -la', makeProfile(), 'read-command');
      await engine.evaluateWithOpa('ls -la', makeProfile(), 'read-command');
      await engine.evaluateWithOpa('ls -la', makeProfile(), 'read-command');
      expect(errSpy).toHaveBeenCalledTimes(1);

      // shouldAdvanceTime keeps real timers running underneath, so the fetch to
      // a dead port still rejects while Date.now() jumps past the window.
      vi.useFakeTimers({ shouldAdvanceTime: true, now: Date.now() + 61_000 });
      try {
        await engine.evaluateWithOpa('ls -la', makeProfile(), 'read-command');
        expect(errSpy).toHaveBeenCalledTimes(2);
      } finally {
        vi.useRealTimers();
      }
    });
  });

  describe('when the operator chooses fail-closed', () => {
    it('refuses instead of falling back, on an HTTP error', async () => {
      await startOpa(() => ({ status: 500, body: { error: 'boom' } }));
      const engine = new PolicyEngine(DEFAULT_RULES);
      engine.setOpaUrl(url, true);

      const result = await engine.evaluateWithOpa('ls -la', makeProfile(), 'read-command');
      expect(result.decision).toBe('deny');
      // A distinct ruleId, so the audit record says the gate was down rather than
      // implying a policy actually refused this command.
      expect(result.ruleId).toBe('opa-unavailable');
      expect(result.reason).toMatch(/--opaFailClosed/);
    });

    it('refuses when nothing is listening', async () => {
      const engine = new PolicyEngine(DEFAULT_RULES);
      engine.setOpaUrl('http://127.0.0.1:1', true);

      const result = await engine.evaluateWithOpa('ls -la', makeProfile(), 'read-command');
      expect(result.decision).toBe('deny');
      expect(result.ruleId).toBe('opa-unavailable');
    });

    it('says what it is doing, not what the default does', async () => {
      const engine = new PolicyEngine(DEFAULT_RULES);
      engine.setOpaUrl('http://127.0.0.1:1', true);

      await engine.evaluateWithOpa('ls -la', makeProfile(), 'read-command');
      const warning = warnings();
      expect(warning).toContain('POLICY WARNING');
      expect(warning).toMatch(/Refusing every command/);
      // The fail-open sentence would be a lie in this mode.
      expect(warning).not.toMatch(/may now be allowed/);
    });

    it('leaves a healthy OPA alone', async () => {
      await startOpa(() => ({ body: { result: true } }));
      const engine = new PolicyEngine(DEFAULT_RULES);
      engine.setOpaUrl(url, true);

      const result = await engine.evaluateWithOpa('ls -la', makeProfile(), 'read-command');
      expect(result.decision).not.toBe('deny');
      expect(errSpy).not.toHaveBeenCalled();
    });

    it('treats a 200 that carries no decision as unavailable', async () => {
      // `{}` is what OPA answers for an undefined document — a misnamed package, an
      // unactivated bundle, or an `allow` rule written without `default allow := false`.
      // Reading that as consent meant the flag did not cover the way an OPA gate
      // actually goes down: six of seven response shapes allowed, with no warning.
      for (const body of [{}, { result: null }, { result: 'false' }, { result: { allow: false } }]) {
        await startOpa(() => ({ body }));
        const engine = new PolicyEngine(DEFAULT_RULES);
        engine.setOpaUrl(url, true);
        const result = await engine.evaluateWithOpa('ls -la', makeProfile(), 'read-command');
        expect(result.decision, JSON.stringify(body)).toBe('deny');
        expect(result.ruleId).toBe('opa-unavailable');
      }
    });

    it('keeps the sidecar URL out of what the client is told', async () => {
      await startOpa(() => ({ status: 500, body: { error: 'boom' } }));
      const engine = new PolicyEngine(DEFAULT_RULES);
      // Pointed at the server that was actually started. An earlier version handed the
      // engine a different, hardcoded URL with credentials in it — which `fetch` refuses
      // before opening a socket, so the request never reached the 500 and the non-2xx
      // route this test exists to cover was never taken.
      engine.setOpaUrl(url, true);

      const result = await engine.evaluateWithOpa('ls -la', makeProfile(), 'read-command');
      expect(requests).toHaveLength(1);
      // `reason` is rethrown as the tool's error text and written to the audit record.
      expect(result.reason).toBe('OPA evaluation unavailable and --opaFailClosed is set');
      // The operator still gets the diagnostic, on stderr, where it is useful.
      expect(warnings()).toMatch(/HTTP 500/);
      expect(warnings()).not.toContain(url);
    });

    it('reports a body with no decision as that, not as an internal error', async () => {
      // `null` is valid JSON, and reading `.result` off it threw — so the cause on stderr
      // read as a defect in this server rather than the condition it names.
      await startOpa(() => ({ body: null }));
      const engine = new PolicyEngine(DEFAULT_RULES);
      engine.setOpaUrl(url, true);

      const result = await engine.evaluateWithOpa('ls -la', makeProfile(), 'read-command');
      expect(result.decision).toBe('deny');
      expect(warnings()).toMatch(/no boolean/);
      expect(warnings()).not.toMatch(/Cannot read properties/);
    });

    it('keeps an explicit deny from a slow but healthy sidecar', async () => {
      // The budget is also the price of turning an OPA *deny* into an allow, because a
      // timeout falls back to the local decision. At two seconds a loaded sidecar crossed
      // it by accident and anyone who could add latency crossed it on purpose.
      await startOpa(() => ({ body: { result: false }, delayMs: 2_500 }));
      const engine = new PolicyEngine(DEFAULT_RULES);
      engine.setOpaUrl(url);

      const result = await engine.evaluateWithOpa('rm -rf /data', makeProfile(), 'run-command');
      expect(result.decision).toBe('deny');
      expect(result.ruleId).toBe('opa');
    }, 20_000);

    it('honours a budget the operator set lower', async () => {
      await startOpa(() => ({ body: { result: false }, delayMs: 2_000 }));
      const engine = new PolicyEngine(DEFAULT_RULES);
      engine.setOpaUrl(url, false, 1_000);

      const result = await engine.evaluateWithOpa('rm -rf /data', makeProfile(), 'run-command');
      // Their choice, and the warning says the gate was skipped.
      expect(result.decision).not.toBe('deny');
      expect(warnings()).toContain('POLICY WARNING');
    }, 20_000);


    it('gives up on a sidecar that never answers, rather than waiting on it', async () => {
      // A process that accepts the connection and never replies is the canonical
      // "unreachable". Without a bound on the request this ran to undici's five-minute
      // header timeout while every tool call waited behind it.
      const hung = createServer(() => { /* deliberately no response */ });
      await new Promise<void>((r) => hung.listen(0, '127.0.0.1', () => r()));
      const port = (hung.address() as AddressInfo).port;
      const engine = new PolicyEngine(DEFAULT_RULES);
      // An explicit budget rather than the default, so this test pins "it gives up" and
      // not whatever the default happens to be.
      engine.setOpaUrl(`http://127.0.0.1:${port}`, true, 1_000);

      const started = Date.now();
      const result = await engine.evaluateWithOpa('ls -la', makeProfile(), 'read-command');
      const elapsed = Date.now() - started;
      hung.close();

      expect(result.decision).toBe('deny');
      expect(result.ruleId).toBe('opa-unavailable');
      expect(elapsed).toBeGreaterThanOrEqual(900);
      expect(elapsed).toBeLessThan(5_000);
    }, 20_000);

    it('does not print the other mode\'s sentence after the mode changes', async () => {
      const engine = new PolicyEngine(DEFAULT_RULES);
      engine.setOpaUrl('http://127.0.0.1:1');
      await engine.evaluateWithOpa('ls -la', makeProfile(), 'read-command');
      expect(warnings()).toMatch(/may now be allowed/);

      // The throttle is one warning per minute, so without a reset the next warning is
      // suppressed and the fail-open sentence stands on the record while the engine
      // refuses everything.
      engine.setOpaUrl('http://127.0.0.1:1', true);
      const result = await engine.evaluateWithOpa('ls -la', makeProfile(), 'read-command');
      expect(result.decision).toBe('deny');
      expect(warnings()).toMatch(/Refusing every command/);
    });


  });


  it('skips OPA entirely when no URL is configured', async () => {
    const engine = new PolicyEngine(DEFAULT_RULES);
    const result = await engine.evaluateWithOpa('ls -la', makeProfile(), 'read-command');
    expect(result.decision).not.toBe('deny');
    expect(errSpy).not.toHaveBeenCalled();
  });
});
