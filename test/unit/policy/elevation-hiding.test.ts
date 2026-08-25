import { describe, it, expect } from 'vitest';
import { classifyCommand, nestedCommands, isForbidden } from '../../../src/policy/classifier.js';

/**
 * Elevation the tokenizer could not see (GHSA-v8jh-gv7v-3gvq).
 *
 * `classifyCommand` decides two things at once: whether the caller's role may run
 * the command at all, and whether the human approval gate fires — only
 * `destructive` and `privileged` require approval. The elevation scan reached that
 * decision through `parseSegments`, which splits on `;`, `&`, `|` and newline and
 * then on whitespace, so it only ever saw the *outer* command. Anything that
 * carries a command inside itself — a substitution, a shell invoked with `-c` —
 * hid the elevation completely.
 *
 * `echo $(sudo id)` classified `safe`. Measured against the compiled-in default
 * rules, `safe` on the `prod` tier is granted to `operator` and `admin` alike,
 * while `privileged` is granted to *nobody* on that tier — not even `admin`. So
 * the bypass handed out exactly the one class the strictest row of the matrix
 * withholds, with no approval prompt, and the audit record said `safe`.
 *
 * The asymmetry that caused it is visible in the old behaviour:
 * `echo $(rm -rf /)` was correctly `destructive`, because the destructive scan
 * reads the raw command text, while the elevation scan read tokens.
 */

describe('elevation hidden inside a command substitution', () => {
  it.each([
    ['$(...)', 'echo $(sudo id)'],
    ['backticks', 'echo `sudo id`'],
    ['nested $(...)', 'echo $(echo $(sudo id))'],
    ['process substitution', 'cat <(sudo id)'],
    ['assignment', 'X=$(sudo id)'],
    ['quoted', 'echo "$(sudo id)"'],
    ['other elevation binaries', 'echo $(doas id)'],
    ['su with -c', 'echo $(su -c id)'],
    ['pkexec', 'echo $(pkexec id)'],
    ['deep inside a pipeline', 'ls | grep x; echo $(sudo id)'],
  ])('%s is privileged, not safe', (_label, command) => {
    expect(classifyCommand(command).class).toBe('privileged');
  });

  it('names the elevated binary rather than the outer one', () => {
    // The audit record and the refusal message both read this field, so pointing
    // it at `echo` would describe the wrong command as the one running as root.
    expect(classifyCommand('echo $(sudo id)').binary).toBe('id');
  });
});

describe('elevation hidden behind a shell wrapper', () => {
  // Not in the reported advisory, found while mapping its surface: these carry no
  // substitution at all, so a fix that only parsed `$(...)` would have left them.
  it.each([
    ['sh -c', 'sh -c "sudo id"'],
    ['bash -c', 'bash -c "sudo id"'],
    ["single quotes", "sh -c 'sudo id'"],
    ['dash -c', 'dash -c "sudo id"'],
    ['zsh -c', 'zsh -c "sudo id"'],
    ['flags before -c', 'bash -x -c "sudo id"'],
    ['substitution inside the wrapper', 'sh -c "echo $(sudo id)"'],
  ])('%s is privileged, not safe', (_label, command) => {
    expect(classifyCommand(command).class).toBe('privileged');
  });
});

describe('what the fix must not break', () => {
  it('leaves substitutions with no elevation where they were', () => {
    // These were `safe` before the fix — demoted from read-only by the shell
    // metacharacter gate — and must stay there. Promoting every substitution
    // would make the approval prompt fire on `echo $(date)`, which trains
    // operators to click through it.
    expect(classifyCommand('echo $(date)').class).toBe('safe');
    expect(classifyCommand('echo $(hostname)').class).toBe('safe');
    expect(classifyCommand('echo $((1 + 1))').class).toBe('safe');
  });

  it('still classifies plain commands as before', () => {
    expect(classifyCommand('ls -la').class).toBe('read-only');
    expect(classifyCommand('sudo id').class).toBe('privileged');
    expect(classifyCommand('rm -rf /tmp/x').class).toBe('destructive');
    expect(classifyCommand('echo hi').class).toBe('read-only');
  });

  it('carries the inner class up when it is destructive rather than privileged', () => {
    // The same hole, one class down: a destructive command hidden in a
    // substitution skipped the approval gate exactly as an elevated one did.
    expect(classifyCommand('echo $(rm -rf /var)').class).toBe('destructive');
    expect(classifyCommand('sh -c "rm -rf /var"').class).toBe('destructive');
  });

  it('does not treat arithmetic expansion as a command', () => {
    // `$((...))` is arithmetic; `$(...)` is a command. Pinned directly on the
    // extractor because the two are one character apart and the difference is
    // invisible in the resulting class — measured: with or without this
    // distinction every arithmetic expression tried still classified `safe`. What
    // it protects is the extractor's contract, so a later reader is not told that
    // `(1 + 1)` is a command someone ran.
    expect(nestedCommands('echo $((1 + 1))')).toEqual([]);
    expect(nestedCommands('echo $(id -u)')).toEqual(['id -u']);
    // A real substitution inside arithmetic is still a real substitution.
    expect(nestedCommands('echo $(( $(id -u) + 1 ))')).toEqual(['id -u']);
  });

  it('terminates on pathological nesting rather than hanging', () => {
    const deep = `echo ${'$('.repeat(200)}sudo id${')'.repeat(200)}`;
    const started = Date.now();
    const result = classifyCommand(deep);
    expect(Date.now() - started).toBeLessThan(1000);
    // Whatever it decides, it must not decide "safe" — that is the failure mode
    // the whole advisory is about.
    expect(result.class).not.toBe('safe');
  });
});

describe('the forbidden list is unconditional, including inside a carrier', () => {
  // `FORBIDDEN_INVOCATIONS` is the one rule no role, tier or approval can satisfy.
  // It was decided from the outer command alone, so wrapping it degraded an
  // absolute `deny` into a `require-approval` a human can click through.
  it.each([
    ['sh -c', 'sh -c "shutdown -h now"'],
    ['substitution', 'echo $(shutdown -h now)'],
    ['backticks', 'echo `reboot`'],
    ['nested wrapper', `sh -c 'sh -c "poweroff"'`],
    ['eval inside a wrapper', 'sh -c "eval sudo id"'],
  ])('%s does not launder a forbidden invocation', (_label, command) => {
    expect(isForbidden(command)).toBe(true);
  });

  it('still lets ordinary commands through', () => {
    expect(isForbidden('echo $(date)')).toBe(false);
    expect(isForbidden('ls -la')).toBe(false);
    expect(isForbidden('sh -c "ls -la"')).toBe(false);
  });
});
