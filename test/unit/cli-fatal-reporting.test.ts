import { describe, it, expect } from 'vitest';
import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import {
  reportFatal,
  OperatorError,
  ConfigNotFoundError,
  EXIT_OPERATOR_ERROR,
  EXIT_DEFECT,
  writeAllSync,
} from '../../src/errors.js';

/**
 * Two audiences, two formats. An operator who mistyped a flag needs the
 * sentence we wrote for them; whoever debugs a defect needs the stack. Printing
 * the Error object served the second and buried the first (#138).
 *
 * These assert on the shape of what is printed, because that *is* the fix —
 * a test that only checked "something was logged" would have passed before it.
 *
 * Imported from errors.ts rather than index.ts: reaching a five-line formatter
 * through the CLI entry point pulled in the MCP SDK, the connection registry and
 * the policy engine, and depended on SSH_MCP_DISABLE_MAIN being set so that
 * index.ts's module-level `main()` did not boot a server during a unit test.
 */
describe('reportFatal', () => {
  function capture(error: unknown): unknown[][] {
    const calls: unknown[][] = [];
    reportFatal(error, (...args) => calls.push(args));
    return calls;
  }

  const exitCode = (error: unknown): number => reportFatal(error, () => {});

  it('prints an operator error as its message alone', () => {
    const calls = capture(new OperatorError('Invalid --group=production. Expected one of: prod, staging, dev.'));
    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual(['Invalid --group=production. Expected one of: prod, staging, dev.']);
  });

  it('passes no Error object, so nothing can render a stack', () => {
    const calls = capture(new ConfigNotFoundError('/home/x/.config/ssh-mcp/config.toml'));
    // The old call was console.error('Fatal error:', error) — the second
    // argument is what produced the frames the reporter pasted.
    expect(calls[0].every((arg) => typeof arg === 'string')).toBe(true);
    expect(calls[0].join(' ')).not.toContain('Fatal error:');
  });

  it('covers subclasses, not just the base type', () => {
    // ConfigNotFoundError extends OperatorError; if the check were by name or
    // by an own property, the more specific type would fall to the crash path.
    const calls = capture(new ConfigNotFoundError('/nowhere/config.toml'));
    expect(calls[0]).toEqual([
      'No config file found at /nowhere/config.toml. Create one or use --config <path>. See documentation for the TOML schema.',
    ]);
  });

  it('keeps the Error object for a real defect', () => {
    const bug = new TypeError('cannot read properties of undefined');
    const calls = capture(bug);
    expect(calls[0][0]).toBe('Fatal error:');
    // The object, not its message — that is what carries the stack.
    expect(calls[0][1]).toBe(bug);
  });

  it('reports an operator error and a defect with different exit statuses', () => {
    // The distinction is only useful to a person if it is prose, and only useful
    // to a supervisor if it is a status code. Before, both were 1.
    expect(exitCode(new OperatorError('bad flag'))).toBe(EXIT_OPERATOR_ERROR);
    expect(exitCode(new ConfigNotFoundError('/nowhere'))).toBe(EXIT_OPERATOR_ERROR);
    expect(exitCode(new TypeError('ours'))).toBe(EXIT_DEFECT);
    expect(exitCode('not even an error')).toBe(EXIT_DEFECT);
    expect(EXIT_OPERATOR_ERROR).not.toBe(EXIT_DEFECT);
  });

  it('keeps a plain Error on the defect path too', () => {
    // Only OperatorError claims to be the operator's problem. An uncategorised
    // Error is ours until someone says otherwise, and gets the stack.
    const calls = capture(new Error('unexpected'));
    expect(calls[0][0]).toBe('Fatal error:');
  });
});

describe('reportFatal — the default sink', () => {
  /**
   * Every test above injects its own sink, so the default — a synchronous write to fd 2 —
   * ran under no test, and reverting it to `console.error` kept the suite green on every
   * platform. What it protects only shows across a process boundary: stderr is a pipe the
   * MCP client owns, Node writes to a pipe asynchronously on macOS, and `main()` calls
   * `process.exit` on the next line. So the child reports a message larger than a pipe
   * buffer and exits at once, and the parent counts what arrived.
   *
   * On Linux and Windows a pipe write is synchronous either way, so this discriminates
   * only on the macOS job — which is the platform the sink exists for.
   */
  const CHILD = fileURLToPath(new URL('./fixtures/report-fatal-child.mjs', import.meta.url));
  const SIZE = 200_000;

  function runChild(): Promise<{ stderr: string; code: number | null }> {
    return new Promise((resolve, reject) => {
      // `--experimental-transform-types` because errors.ts has parameter properties, which
      // type stripping alone refuses; `--no-warnings` keeps the flag's notice off the
      // stream being measured.
      const child = spawn(process.execPath, ['--experimental-transform-types', '--no-warnings', CHILD, String(SIZE)], {
        stdio: ['ignore', 'ignore', 'pipe'],
      });
      let stderr = '';
      child.stderr.setEncoding('utf8');
      child.stderr.on('data', (chunk: string) => { stderr += chunk; });
      child.on('error', reject);
      child.on('close', (code) => resolve({ stderr, code }));
    });
  }

  it('delivers the whole message before the process exits', async () => {
    const { stderr, code } = await runChild();
    expect(code).toBe(EXIT_OPERATOR_ERROR);
    expect(stderr.length, 'the message was cut off by the exit').toBe(SIZE + 1);
  });
});

describe('writeAllSync', () => {
  const eagain = () => Object.assign(new Error('EAGAIN'), { code: 'EAGAIN' });

  /** A writer that takes at most `chunk` bytes a call, recording what arrived. */
  function pipe(chunk: number, failures: Array<() => Error> = []) {
    const received: Buffer[] = [];
    const write = (_fd: number, buf: Buffer, offset: number): number => {
      const failure = failures.shift();
      if (failure) throw failure();
      const end = Math.min(buf.length, offset + chunk);
      received.push(buf.subarray(offset, end));
      return end - offset;
    };
    return { write, text: () => Buffer.concat(received).toString() };
  }

  it('keeps writing until a partial write has gone out in full', () => {
    // What a non-blocking pipe does on macOS: each call takes 65536 bytes and says so.
    const p = pipe(65_536);
    writeAllSync(2, 'x'.repeat(200_000), p.write);
    expect(p.text()).toHaveLength(200_000);
  });

  it('retries a full pipe rather than dropping the rest', () => {
    const p = pipe(4, [eagain, eagain]);
    writeAllSync(2, 'abcdefgh', p.write);
    expect(p.text()).toBe('abcdefgh');
  });

  it('gives up on a pipe that never drains, saying how much went out', () => {
    // A reader that stopped reading must not keep the process from exiting.
    let t = 0;
    let calls = 0;
    const write = (_fd: number, _buf: Buffer, offset: number): number => {
      // The loop is synchronous, so a missing deadline would hang the worker rather than
      // time the test out; this turns that into a failure.
      if (++calls > 100) throw new Error('still retrying after 100 attempts');
      if (offset >= 4) throw eagain();
      return 4;
    };
    const err = (() => {
      try { writeAllSync(2, 'abcdefgh', write, () => (t += 500)); } catch (e) { return e as Error & { written?: number }; }
      return null;
    })();
    expect(err?.message).toBe('EAGAIN');
    expect(err?.written).toBe(4);
  });

  it('does not retry anything but a full pipe', () => {
    const p = pipe(4, [() => Object.assign(new Error('EBADF'), { code: 'EBADF' })]);
    expect(() => writeAllSync(2, 'abcdefgh', p.write, () => 0)).toThrow('EBADF');
    expect(p.text()).toBe('');
  });
});
