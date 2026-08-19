import { describe, it, expect } from 'vitest';
import {
  reportFatal,
  OperatorError,
  ConfigNotFoundError,
  EXIT_OPERATOR_ERROR,
  EXIT_DEFECT,
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
