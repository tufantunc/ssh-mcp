import { describe, expect, it } from 'vitest';
import { classifyCommand, findForbiddenMatch } from '../../../src/policy/classifier.js';

/**
 * GHSA-972x-g47g-3922: a backslash is an escape to a POSIX shell and an
 * ordinary path separator to cmd.exe, and the classifier reads a command
 * without knowing which shell will run it. These suites hold it to the
 * stricter of the two readings.
 *
 * Part 1 — byte fidelity of one reading: quoted backslash words keep their
 * bytes (POSIX keeps `\x` inside double quotes before an ordinary character;
 * single quotes were always literal), and a command word's path is cut on
 * both separators before its name is looked up.
 */
const PS_PATH = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
const encoded = (text: string) => Buffer.from(text, 'utf16le').toString('base64');

describe('quoted backslash words keep their bytes (GHSA-972x-g47g-3922)', () => {
  it.each([
    [`"${PS_PATH}" -EncodedCommand ${encoded('sudo id')}`, 'privileged'],
    [`"${PS_PATH}" -EncodedCommand ${encoded('rm -rf /etc')}`, 'destructive'],
    [`'${PS_PATH}' -EncodedCommand ${encoded('sudo id')}`, 'privileged'],
    [`'C:\\Windows\\pwsh.exe' -e ${encoded('sudo id')}`, 'privileged'],
    [`"\\\\server\\share\\pwsh.exe" -EncodedCommand ${encoded('sudo id')}`, 'privileged'],
  ])('%s is %s', (command, expected) => {
    expect(classifyCommand(command).class, command).toBe(expected);
  });

  it('a backslash before an ordinary character survives inside double quotes', () => {
    // The operand is `C:\logs`, not `C:logs` — one operand either way for an
    // `args: 'any'` reader, so this pins the bytes without pinning a class change.
    expect(classifyCommand('cat "C:\\logs\\app.log"').class).toBe('read-only');
  });

  it('an escaped space still makes one word of one operand', () => {
    // `a\ b` is one operand to POSIX; `cat` accepts any count, so both
    // dialects of the later suite agree here. Pins the escape itself.
    expect(classifyCommand('cat a\\ b').class).toBe('read-only');
  });
});

describe('both dialects are read; the stricter one decides (GHSA-972x-g47g-3922)', () => {
  it.each([
    // The advisory's table: every spelling of the interpreter resolves and
    // decodes, quoted or not. The backslash column was `safe` before.
    [`C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -EncodedCommand ${encoded('sudo id')}`, 'privileged'],
    [`C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -EncodedCommand ${encoded('rm -rf /etc')}`, 'destructive'],
    [`"${PS_PATH}" -NoProfile -EncodedCommand ${encoded('sudo id')}`, 'privileged'],
    [`C:\\Windows\\pwsh.exe -EncodedCommand ${encoded('sudo id')}`, 'privileged'],
    [`\\\\server\\share\\pwsh.exe -EncodedCommand ${encoded('sudo id')}`, 'privileged'],
    [`C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -EncodedCommand ${encoded('sudo id')}`, 'privileged'],
    [`powershell -EncodedCommand ${encoded('sudo id')}`, 'privileged'],
    // Worst case in the other direction: the POSIX reading is the worse one
    // (`\r` is an escape to POSIX, a literal to cmd.exe) and must survive.
    ['re\\boot', 'destructive'],
    ['r\\m -rf /etc', 'destructive'],
    ['\\sudo id', 'privileged'],
  ])('%s is %s', (command, expected) => {
    expect(classifyCommand(command).class, command).toBe(expected);
  });

  it('a carrier nested in a command the dialects read differently still resolves', () => {
    expect(classifyCommand(`echo $(C:\\Windows\\pwsh.exe -EncodedCommand ${encoded('sudo id')})`).class)
      .toBe('privileged');
  });

  it('an unterminated quote still falls back and still resolves under the windows reading', () => {
    expect(classifyCommand(`echo "hi; C:\\Windows\\pwsh.exe -EncodedCommand ${encoded('sudo id')}`).class)
      .toBe('privileged');
  });

  it('a grant requires every reading to qualify', () => {
    // POSIX reads one operand (`a b`); the windows reading reads two (`a\`,
    // `b`), and uniq's second positional operand is its OUTFILE — a write.
    // One reading refusing the grammar keeps the command off `read-only`.
    expect(classifyCommand('uniq a\\ b').class).toBe('safe');
  });

  it('benign windows-native paths are not punished', () => {
    expect(classifyCommand('cat C:\\logs\\app.log').class).toBe('read-only');
  });
});

describe('the engine decision the advisory measured (GHSA-972x-g47g-3922)', () => {
  // Copied from engine.test.ts so this file stands alone.
  function makeProfile(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      name: 'prod', group: 'prod', host: 'localhost', port: 22, user: 'test',
      auth: 'agent', tty: false, timeout: 60000, maxChars: 5000,
      maxOutputBytes: 1048576, role: 'operator', readOnly: false,
      announceAgent: true, approvalPolicy: 'ask-destructive', cert: false,
      sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 600000,
      sessionBackgroundMaxMs: 3600000, commandQuotaPerDay: 0,
      transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
      ...overrides,
    };
  }

  it('operator on prod is refused for the backslash spelling, as for the others', async () => {
    const { PolicyEngine, DEFAULT_RULES } = await import('../../../src/policy/engine.js');
    const engine = new PolicyEngine(DEFAULT_RULES);
    const profile = makeProfile();
    const result = engine.evaluate(
      `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -EncodedCommand ${encoded('sudo id')}`,
      profile as never,
      'read-command',
    );
    expect(result.decision).toBe('deny');
  });
});

describe('the never-allowed list reads both dialects (GHSA-972x-g47g-3922)', () => {
  it('an encoded forbidden invocation behind a backslash path is refused', () => {
    const command = `echo $(C:\\Windows\\pwsh.exe -EncodedCommand ${encoded('shutdown -r')})`;
    expect(findForbiddenMatch(command)).not.toBeNull();
  });

  it('the POSIX reading of an escaped name still refuses', () => {
    expect(findForbiddenMatch('sh\\utdown -h now')).not.toBeNull();
  });

  it('an ordinary windows path does not trip the list', () => {
    expect(findForbiddenMatch('cat C:\\Users\\anne\\notes.txt')).toBeNull();
  });
});

describe('quoted backspelled names keep their bytes (GHSA-972x-g47g-3922)', () => {
  it('a quoted backspelled name classifies as the name a shell would pass', () => {
    // argv[0] keeps the backslash on POSIX and cmd.exe alike; stripping it
    // resolved a name no host runs. The refusal that produced was a fidelity
    // error in the other direction, and this pins its removal as deliberate.
    expect(classifyCommand('"s\\udo" id').class).toBe('safe');
    expect(classifyCommand("'s\\udo' id").class).toBe('safe');
    expect(classifyCommand('"p\\owershell" -EncodedCommand ' + encoded('sudo id')).class).toBe('safe');
    expect(findForbiddenMatch('"sh\\utdown" -h now')).toBeNull();
  });

  it('a backslash at end of string inside quotes falls back and still resolves', () => {
    expect(classifyCommand('cat "abc\\').class).toBe('read-only');
    expect(classifyCommand('sudo "x\\').class).toBe('privileged');
  });
});
