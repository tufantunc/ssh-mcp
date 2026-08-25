import { describe, it, expect } from 'vitest';
import { classifyCommand } from '../../../src/policy/classifier.js';

/**
 * Commands whose *name* is not knowable (GHSA-fj9r-f47j-c73x).
 *
 * `classifyCommand` decides the class — and with it whether the approval gate
 * fires — from the literal text of the command word. When that word is a shell
 * variable expansion, what will actually run is not knowable statically, and the
 * unresolvable word was treated as an ordinary binary: `safe`. The remote shell
 * then expanded it and ran whatever it named.
 *
 * Distinct from GHSA-v8jh-gv7v-3gvq, which hid elevation inside a *carrier*
 * (`$(...)`, backticks, `sh -c`) — statically readable, and now read. This hides
 * it behind a *name*, which is not readable at all: `src/tools/command-tools.ts`
 * notes that a session run keeps the caller's shell state, so `S=sudo` and
 * `$S id` can arrive as two separate calls, and a variable exported in the
 * target's own profile is never visible to this process.
 *
 * So the answer is not to resolve the variable but to stop pretending it was
 * resolved. `destructive` rather than `privileged` deliberately: it requires
 * approval instead of refusing outright, which keeps `$HOME/bin/tool` usable for
 * a role that holds `destructive` on the tier.
 */

describe('a command whose name is a variable', () => {
  it.each([
    ['assignment then use', 'S=sudo; $S id'],
    ['bare use', '$S id'],
    ['braced', '${S} id'],
    ['substitution as the name', '$(which sudo) id'],
    ['behind a wrapper', 'xargs $S'],
    ['behind env', 'env $S id'],
    ['behind nohup', 'nohup $S id'],
    ['path-like', '$PREFIX/bin/tool --version'],
    ['second segment of a pipeline', 'echo id | $S'],
    ['after a legitimate first segment', 'ls -la; $S id'],
  ])('%s requires approval rather than passing as safe', (_label, command) => {
    expect(classifyCommand(command).class).toBe('destructive');
  });

  it('does not fire when the variable is only an argument', () => {
    // The name is known here; only what it operates on is not. Promoting these
    // would put a prompt on most ordinary shell usage. They sit at `safe` rather
    // than `read-only` because `$` is a shell metacharacter and the allowlist
    // branch demotes on those — behaviour that predates this fix and stays.
    expect(classifyCommand('echo $HOME').class).toBe('safe');
    expect(classifyCommand('ls $HOME/bin').class).toBe('safe');
    expect(classifyCommand('cat $CONFIG').class).toBe('safe');
    expect(classifyCommand('grep $PATTERN file.txt').class).toBe('safe');
  });

  it('still lets a real elevation win over the weaker class', () => {
    // A variable command word is `destructive`; an actual sudo is `privileged`.
    // The higher one has to survive.
    expect(classifyCommand('sudo $S').class).toBe('privileged');
    expect(classifyCommand('echo $(sudo id)').class).toBe('privileged');
    // A variable *prefix* on a known binary is still the known binary: `stripPath`
    // reduces `$PREFIX/bin/sudo` to `sudo`, so the elevation scan reaches it first
    // and answers with the stronger class rather than "cannot tell".
    expect(classifyCommand('$PREFIX/bin/sudo id').class).toBe('privileged');
  });

  it('leaves everything else where it was', () => {
    expect(classifyCommand('ls -la').class).toBe('read-only');
    expect(classifyCommand('echo hi').class).toBe('read-only');
    expect(classifyCommand('echo $(date)').class).toBe('safe');
    expect(classifyCommand('rm -rf /tmp/x').class).toBe('destructive');
  });
});
