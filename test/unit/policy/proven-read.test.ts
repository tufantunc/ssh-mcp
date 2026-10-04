import { describe, it, expect } from 'vitest';
import { classifyCommand, READERS } from '../../../src/policy/classifier.js';
import type { ArgGrammar } from '../../../src/policy/reader-grammar.js';
import { PolicyEngine, DEFAULT_RULES } from '../../../src/policy/engine.js';
import type { Profile } from '../../../src/types.js';

/**
 * Task 2 gave every `READERS` entry a required `grammar`, and `classifyOuter`'s
 * allowlist branch consults it — a reader whose argv the grammar does not
 * recognise falls to `safe` instead of `read-only`. Task 3 is the audit that
 * turned that mechanism on: every entry the design round marked "grammar
 * needed" now carries the actual flags/operand shape the audit in
 * `.superpowers/sdd/2026-09-25-proven-read/audit.md` found each binary's
 * read-only surface to be — no longer the bare-only `{ operands: { max: 0 } }`
 * placeholder Task 2 shipped to fail closed until this audit landed. Every
 * `'any'` entry keeps taking any argument, behind an `audit` string this task
 * confirmed or corrected.
 */

describe('every READERS entry has a grammar', () => {
  const entries = Object.entries(READERS);

  it('the table is not empty (a vacuous table proves nothing)', () => {
    expect(entries.length).toBeGreaterThan(0);
  });

  it.each(entries)('%s declares a grammar', (_name, entry) => {
    expect(entry.grammar).toBeDefined();
    expect(['any', 'getopt', 'exact']).toContain(entry.grammar.args);
  });

  const anyEntries = entries.filter(
    (pair): pair is [string, typeof pair[1] & { grammar: Extract<ArgGrammar, { args: 'any' }> }] =>
      pair[1].grammar.args === 'any',
  );

  it("the 'any' candidates are the ones the design round guessed (sanity, not the audit itself)", () => {
    // Not exhaustive — just enough to catch a name landing in the wrong list
    // entirely, which the per-entry test below cannot: it only ever sees the
    // grammar an entry actually has, not the one the spec says it should.
    expect(anyEntries.map(([name]) => name)).toEqual(expect.arrayContaining(['cat', 'ls', 'grep']));
  });

  it.each(anyEntries)("%s's 'any' grammar carries a non-empty audit", (_name, entry) => {
    // `.trim()` so a whitespace-only string — which `.length > 0` alone would
    // accept — still fails this.
    expect(entry.grammar.audit.trim().length).toBeGreaterThan(0);
  });
});

/**
 * The 20 entries the audit gave a real grammar (as opposed to `'any'`):
 * `arp`, `date`, `diff`, `file`, `find`, `hostname`, `ifconfig`, `ip addr`,
 * `ip route`, `journalctl`, `netstat`, `sort`, `ss`, `systemctl status`,
 * `uniq`, `git branch`, `git diff`, `git log`, `git remote`, `git show`.
 * `diff`, `netstat` and `systemctl status` are the three the design round's
 * own guess had filed as `'any'`; the table test at the bottom of this file
 * is what pins all 20 as no longer `'any'`.
 */
const GRAMMAR_ENTRIES: ReadonlyArray<readonly [name: string, allowed: string, denied: string]> = [
  ['arp', 'arp -a', 'arp -d 192.168.1.1'], // -d deletes an ARP entry — excluded
  ['date', 'date -u +%F', 'date -d yesterday'], // -d set the kernel DST flag on old BSD — excluded
  ['diff', 'diff -u a b', 'diff -l a b'], // -l/--paginate runs /usr/bin/pr — excluded
  ['file', 'file -i /etc/hosts', 'file -C -m /usr/share/file/magic/magic'], // -C writes magic.mgc — excluded
  ['find', 'find /tmp -name "*.conf" -type f', 'find /tmp --no-such-option'],
  ['hostname', 'hostname -s', 'hostname new-host-name'], // a bare operand SETS the hostname — excluded (max: 0)
  ['ifconfig', 'ifconfig eth0', 'ifconfig eth0 up'], // a 2nd operand configures the interface — excluded (max: 1)
  ['ip addr', 'ip addr show', 'ip addr add 1.2.3.4/24 dev eth0'], // "add" is not in first: ['show','list']
  ['ip route', 'ip route get 10.0.0.1', 'ip route add 10.0.0.0/24 via 10.0.0.1'], // "add" writes a route
  ['journalctl', 'journalctl -u nginx --since today', 'journalctl --rotate'], // --rotate deletes archives — excluded
  ['netstat', 'netstat -rn', 'netstat --no-such-option'],
  ['sort', 'sort -u /var/log/app.log', 'sort -T /tmp'], // -T picks a write location — excluded (friction #21)
  ['ss', 'ss -tunlp', 'ss -K'], // -K forcibly closes sockets — excluded
  ['systemctl status', 'systemctl status nginx -l', 'systemctl status --no-such-option nginx'],
  ['uniq', 'uniq -c /var/log/app.log', 'uniq /etc/passwd /root/.ssh/authorized_keys'], // 2nd operand is OUTFILE
  ['git branch', 'git branch -a', 'git branch newbranch'], // a bare operand CREATES a branch — excluded (max: 0)
  ['git diff', 'git diff --name-only HEAD~1', 'git diff --output=/tmp/out.txt'], // --output writes — excluded
  ['git log', 'git log --author=alice --max-count=5', 'git log --output=/tmp/out.txt'], // --output writes
  ['git remote', 'git remote -v', 'git remote add origin url'], // "add" writes .git/config — excluded
  ['git show', 'git show --stat HEAD', 'git show --output=/tmp/out.txt HEAD'], // --output writes — excluded
];

describe('every grammar entry accepts what it lists', () => {
  it.each(GRAMMAR_ENTRIES.map(([name, allowed]): [string, string] => [name, allowed]))(
    '%s: an allowed option stays read-only (%s)',
    (_name, command) => {
      expect(classifyCommand(command).class, command).toBe('read-only');
    },
  );
});

describe('every grammar entry refuses what it excludes or never named', () => {
  it.each(GRAMMAR_ENTRIES.map(([name, , denied]): [string, string] => [name, denied]))(
    '%s: an unlisted or excluded argument falls to safe (%s)',
    (_name, command) => {
      expect(classifyCommand(command).class, command).toBe('safe');
    },
  );
});

describe('git log: an optional-value option never swallows the next word', () => {
  it('"--pretty" followed by an unlisted option word falls to safe', () => {
    // `--pretty` is optional-value (`optionalValueFlags`), so a bare
    // `--pretty` must consume nothing after it — if the matcher mistakenly
    // treated it as a required-value flag, it would eat the next word as
    // `--pretty`'s value and this command would wrongly stay read-only.
    expect(classifyCommand('git log --pretty --no-such-option').class).toBe('safe');
  });

  it('"--pretty=short" (attached value) still lets the rest of the line through', () => {
    expect(classifyCommand('git log --pretty=short --oneline').class).toBe('read-only');
  });
});

describe('the design spec\'s friction corpus (§ Testing, item 3) stays read-only', () => {
  it.each([
    'journalctl -u nginx --since today -n 100',
    'git log --oneline -20',
    'ls -la',
    'tail -n 50 -f x',
    'grep -rn foo /etc',
    'find / -name x -type f',
    'ip addr show',
    'date +%F',
    'sort -rn x',
    'uniq -c x',
  ])('%s', (command) => {
    expect(classifyCommand(command).class, command).toBe('read-only');
  });
});

describe('the grammar-needed entries are no longer \'any\'', () => {
  // The design round's own guess filed `diff`, `netstat` and `systemctl
  // status` as 'any' candidates; the audit moved all three to a grammar
  // (`.superpowers/sdd/2026-09-25-proven-read/audit.md` and
  // `task-3-grammars.md`). This is the table that would catch any of the 20
  // slipping back to 'any'.
  it.each(GRAMMAR_ENTRIES.map(([name]) => name))('%s is not \'any\'', (name) => {
    expect(READERS[name].grammar.args, name).not.toBe('any');
  });

  it('is exactly the 20 the audit named', () => {
    const grammarNamed = Object.entries(READERS)
      .filter(([, entry]) => entry.grammar.args !== 'any')
      .map(([name]) => name)
      .sort();
    expect(grammarNamed).toEqual([...GRAMMAR_ENTRIES.map(([name]) => name)].sort());
  });
});

describe('a grammar-needed reader\'s bare invocation still stays read-only', () => {
  it('an excluded or unrecognised argument falls to safe', () => {
    expect(classifyCommand('sort -T /tmp/dir').class).toBe('safe');
    expect(classifyCommand('journalctl --rotate').class).toBe('safe');
    expect(classifyCommand('find /etc --no-such-option').class).toBe('safe');
    expect(classifyCommand('date -d yesterday').class).toBe('safe');
    expect(classifyCommand('ip addr add 1.2.3.4/24 dev eth0').class).toBe('safe');
  });

  it('bare invocation stays read-only', () => {
    expect(classifyCommand('sort').class).toBe('read-only');
    expect(classifyCommand('journalctl').class).toBe('read-only');
    expect(classifyCommand('find').class).toBe('read-only');
    expect(classifyCommand('date').class).toBe('read-only');
    expect(classifyCommand('ip addr').class).toBe('read-only');
  });

  it('a quoted argument is judged the same as its unquoted spelling', () => {
    // Both reach the grammar dequoted — the tokeniser already strips the
    // quotes before classifyOuter ever builds `words`. `-T` is unlisted in
    // sort's grammar (friction decision #21), so both forms fall to `safe`
    // identically.
    expect(classifyCommand('sort "-T"').class).toBe('safe');
    expect(classifyCommand('sort -T').class).toBe('safe');
  });
});

describe("an 'any' reader keeps read-only with arguments", () => {
  it('cat, ls and grep stay read-only however they are called', () => {
    expect(classifyCommand('cat /etc/hosts').class).toBe('read-only');
    expect(classifyCommand('ls -la /root').class).toBe('read-only');
    expect(classifyCommand('grep -rn foo /etc').class).toBe('read-only');
    expect(classifyCommand('echo --anything --at-all').class).toBe('read-only');
  });
});

describe('a two-word READERS entry reads its grammar from index 2', () => {
  it('bare "git log" stays read-only — the offset, not just the grammar, has to be right', () => {
    // If the branch mistakenly read words[1..] for a two-word entry, "log"
    // itself would be read as the first argument word — harmless on its own
    // now that git log's grammar has no operand limit, but this still pins
    // the offset the rest of this describe block builds on.
    expect(classifyCommand('git log').class).toBe('read-only');
  });

  it('"git log -1" is accepted via the numericShort shortcut', () => {
    // git log's grammar sets `numericShort: true` (added for the friction
    // corpus's `git log --oneline -20`): `-1`, a whole word of digits, is
    // git's own `-<n>` revision-limit shortcut, not an unrecognised flag.
    // This replaces the "falls to safe" this test recorded before Task 3
    // gave git log a full grammar.
    expect(classifyCommand('git log -1').class).toBe('read-only');
  });

  it('an unrecognised option still falls to safe past the two-word offset', () => {
    expect(classifyCommand('git log --no-such-option').class).toBe('safe');
  });

  it('a one-word entry keeps reading from index 1 (unaffected by the two-word offset)', () => {
    expect(classifyCommand('sort').class).toBe('read-only');
    expect(classifyCommand('sort -T').class).toBe('safe');
  });
});

describe('READ_ONLY_SYNTHETIC verbs are unaffected by the grammar', () => {
  it('sftp:list and sftp:download stay read-only regardless of arguments', () => {
    // These are synthesised by the tool layer, never typed by a caller — there
    // is no argv for a grammar to read, and READ_ONLY_SYNTHETIC is not in
    // READERS at all, so this also proves the branch does not try to look
    // one up for them.
    expect(classifyCommand('sftp:list /var/log').class).toBe('read-only');
    expect(classifyCommand('sftp:download /etc/nginx/nginx.conf').class).toBe('read-only');
  });
});

describe('DISQUALIFYING_ARGS still runs before the allowlist branch', () => {
  it('sort -o classifies destructive — the list\'s own credit, no nested command involved', () => {
    // `sort -o /tmp/x /etc/passwd` carries no nested command, so nothing but
    // `hasDisqualifyingArgs` can raise it: this is the row that pins the
    // DISQUALIFYING_ARGS-before-grammar ordering itself. (The `find … -exec
    // sudo id +` form below also fires it, but its *privileged* is the
    // find-exec carrier scan's doing, so on its own it credited the wrong
    // mechanism.)
    const result = classifyCommand('sort -o /tmp/x /etc/passwd');
    expect(result.class).not.toBe('safe');
    expect(result.class).toBe('destructive');
  });

  it('find with an -exec carrying sudo classifies above safe', () => {
    // `hasDisqualifyingArgs` and the elevation carrier scan both run earlier
    // than the grammar check this task adds: the former would already return
    // `destructive` for the `-exec` word alone, and the nested `sudo id` the
    // carrier scan extracts raises the final class to `privileged` — so the
    // grammar never gets a chance to lower anything, because the functions
    // involved have already returned.
    const result = classifyCommand('find / -exec sudo id +');
    expect(result.class).not.toBe('safe');
    expect(result.class).toBe('privileged');
  });
});

describe('Windows switch operands on sort and arp fall to safe (Task 4)', () => {
  // Windows 11 build 26200 measurement: `sort.exe /O FILE IN` writes FILE,
  // case-insensitive, abbreviations accepted; `arp.exe` accepts the slash
  // form (`/a` measured), `/d`/`/s` inferred and not run. A `/X` switch is an
  // operand under this POSIX grammar and cannot be told apart from `/etc`
  // without the `each` rule the design's Windows section adds.
  it('sort /O and /T switch forms fall to safe', () => {
    expect(classifyCommand('sort /O x').class).toBe('safe');
    expect(classifyCommand('sort /o x').class).toBe('safe');
    expect(classifyCommand('sort /OU x').class).toBe('safe');
    expect(classifyCommand('sort /T x y').class).toBe('safe');
  });

  it('arp /d and /s switch forms fall to safe', () => {
    expect(classifyCommand('arp /d 10.0.0.1').class).toBe('safe');
    expect(classifyCommand('arp /s 10.0.0.1 00-aa-00-62-c6-09').class).toBe('safe');
  });

  it('a lone Windows-style switch operand falls to safe independent of the operand-count limit', () => {
    // `arp /d 10.0.0.1` and `arp /s 10.0.0.1 00-aa-00-62-c6-09` above already
    // fall to safe under the pre-existing `operands: { max: 1 }` alone (two
    // operands overruns it regardless of `each`), so neither pins the new
    // rule by itself. A single-operand slash form isolates it: without
    // `each` this one operand is within budget and would stay read-only.
    expect(classifyCommand('arp /a').class).toBe('safe');
  });

  it('a POSIX path with a second slash still passes', () => {
    expect(classifyCommand('sort /etc/passwd').class).toBe('read-only');
    expect(classifyCommand('sort -rn /var/log/x').class).toBe('read-only');
    expect(classifyCommand('arp 10.0.0.1').class).toBe('read-only');
  });

  it('find is unaffected — its grammar carries no Windows each rule', () => {
    expect(classifyCommand('find /var -name x').class).toBe('read-only');
  });

  it('the accepted cost is pinned: a single-segment operand under / falls to safe', () => {
    expect(classifyCommand('sort /data').class).toBe('safe');
  });
});

/**
 * Task 5: `classifyCommand` carries the word a reader's grammar rejected, but
 * only when that rejection is still the reason the final class is `safe` —
 * never when a nested command or a synthetic floor raised the class past it,
 * and never when the command was never a reader to begin with.
 */
describe('classifyCommand carries readOnlyRejection only for the outer safe it produced', () => {
  it('names the reader and the rejected flag', () => {
    const result = classifyCommand('journalctl --foo');
    expect(result.class).toBe('safe');
    expect(result.readOnlyRejection).toEqual({ binary: 'journalctl', word: '--foo' });
  });

  it('names the rejected operand, not a flag, for an operand-count violation', () => {
    // hostname's `operands: { max: 0 }`: a bare operand at all is refused, and
    // the word the matcher names is the operand itself, not a flag — proving
    // the sentence still reads correctly for the family of rejections that
    // are not about an unrecognised flag.
    const result = classifyCommand('hostname pwned');
    expect(result.class).toBe('safe');
    expect(result.readOnlyRejection).toEqual({ binary: 'hostname', word: 'pwned' });
  });

  it('carries nothing when the command is not a reader at all', () => {
    // A behaviour pin, not a regression guard: `kubectl` is not a `READERS`
    // key, so `classifyOuter` never reaches the grammar branch at all and
    // `readOnlyRejection` is never set in the first place — no production
    // line in this task's diff can make this assertion fail. It stays here
    // because it is still true and worth stating, not because deleting
    // anything would break it.
    const result = classifyCommand('kubectl get pods');
    expect(result.class).toBe('safe');
    expect(result.readOnlyRejection).toBeUndefined();
  });

  it('carries nothing when a nested command raises the class above safe', () => {
    // A behaviour pin, not a proof of the `highest === outer` guard: the `;`
    // in this string is itself a `SHELL_CONTROL_CHARS` character, so
    // `classifyOuter`'s allowlist branch returns plain `safe` — with no
    // `readOnlyRejection` — before it ever reaches the grammar check that
    // would have produced one. `elevatedBinaryOf` separately finds the nested
    // `sudo id` and raises the *final* class to `privileged`, but the outer
    // never had a rejection to lose in either case, so this does not exercise
    // "the carry survives past a nested command" as much as it looks like it
    // does.
    //
    // The `highest === outer` guard in `classifyCommand` that this test's
    // name refers to is, as far as today's `READERS` table goes, unreachable
    // to violate: every entry has `operandsAreData: true` (so a reader's own
    // segment can never yield an interpreter-carrier finding), and every other
    // way `nestedCommands` finds something — `$()`, `<()`, `>()`, backticks —
    // requires a character from `SHELL_CONTROL_CHARS`, which forces the same
    // early return this test hits. There is currently no command for which
    // `classifyOuter` sets `readOnlyRejection` *and* `nestedCommands`/the
    // `SYNTHETIC_CLASSES` floor also has something to raise the class with.
    // The guard is kept as defensive code (see the comment in
    // `classifyCommand`) for a future `READERS` entry with
    // `operandsAreData: false`, or a future synthetic-verb collision; nothing
    // in this suite independently pins that half of the condition.
    const result = classifyCommand('journalctl --foo; sudo id');
    expect(result.class).toBe('privileged');
    expect(result.readOnlyRejection).toBeUndefined();
  });
});

/**
 * Task 5: the engine copies `readOnlyRejection` onto its `PolicyEvaluation`,
 * and `explainRoleDenial` appends the sentence naming the binary and the word
 * when a role-binding denial refuses a `safe` command that a reader's grammar
 * produced.
 */
describe('the refusal names the word (role-binding denial)', () => {
  const engine = new PolicyEngine(DEFAULT_RULES);

  const readOnlyProfile = {
    name: 'ro-box', host: 'h', port: 22, user: 'viewer', auth: 'agent', tty: false,
    timeout: 60_000, maxChars: 5000, maxOutputBytes: 1_048_576, group: 'dev',
    role: 'viewer', readOnly: true, approvalPolicy: 'ask-destructive', cert: false,
    announceAgent: true, sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 600_000,
    sessionBackgroundMaxMs: 3_600_000, commandQuotaPerDay: 0,
    transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
  } as unknown as Profile;

  const viewerProdProfile = {
    name: 'viewer-prod', host: 'h', port: 22, user: 'viewer', auth: 'agent', tty: false,
    timeout: 60_000, maxChars: 5000, maxOutputBytes: 1_048_576, group: 'prod',
    role: 'viewer', readOnly: false, approvalPolicy: 'ask-destructive', cert: false,
    announceAgent: true, sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 600_000,
    sessionBackgroundMaxMs: 3_600_000, commandQuotaPerDay: 0,
    transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
  } as unknown as Profile;

  it('a readOnly profile: denies the grammar-rejected reader and names the binary and the word', () => {
    const evaluation = engine.evaluate('journalctl --foo', readOnlyProfile);
    expect(evaluation.decision).toBe('deny');
    expect(evaluation.commandClass).toBe('safe');
    expect(evaluation.reason).toContain('journalctl');
    expect(evaluation.reason).toContain('--foo');
  });

  it('appends the exact sentence, verbatim, not just the two words', () => {
    // The two assertions above would still pass if the wording drifted (a
    // typo, a rephrase, a dropped clause) as long as `journalctl` and `--foo`
    // both appeared somewhere in the reason. This pins the whole sentence
    // `formatReadOnlyRejection` produces, worded exactly as the controller
    // ruling on this task specifies.
    const evaluation = engine.evaluate('journalctl --foo', readOnlyProfile);
    expect(evaluation.reason).toContain(
      '`journalctl` is read-only only with the options and operands its grammar lists; ' +
      '`--foo` is not accepted there.',
    );
  });

  it('a viewer on prod (not readOnly): same denial, same naming', () => {
    const evaluation = engine.evaluate('journalctl --foo', viewerProdProfile);
    expect(evaluation.decision).toBe('deny');
    expect(evaluation.commandClass).toBe('safe');
    expect(evaluation.reason).toContain('journalctl');
    expect(evaluation.reason).toContain('--foo');
  });
});

/**
 * Task 6: the advisory's measured forms, driven through the engine end to end
 * rather than through `classifyCommand` alone. Every row here is a concrete,
 * harmless instance of a form from spec § Measured — a command that classified
 * `read-only` on 2.12.0 and let a reader change host state through an option or
 * operand a caller was never meant to reach. Task 3's grammars are what closes
 * each one: an excluded option or operand is no longer part of what the reader's
 * grammar recognises, so the command falls out of the allowlist branch. Every
 * row is measured on this head first (none of them is `read-only`, and every one
 * lands on `safe` — none is raised further by `DISQUALIFYING_ARGS` or a nested
 * elevation), and this table asserts that exact class together with the deny
 * decision it must produce for the two consumers of `read-only` that a plain
 * `safe` classification is not enough to stop: a `readOnly` profile and a
 * `viewer` on `prod`.
 *
 * `git remote add x url`, `ip route add …` and `arp -d HOST` are written out as
 * one concrete instance each (a placeholder host, `x` for a remote name) — the
 * spec states these forms generically; the string itself is only ever
 * classified here, never executed.
 */
describe("the advisory's measured forms: writes through a reader classify safe, not read-only", () => {
  const readOnlyProfile = {
    name: 'ro-prod', host: 'h', port: 22, user: 'viewer', auth: 'agent', tty: false,
    timeout: 60_000, maxChars: 5000, maxOutputBytes: 1_048_576, group: 'prod',
    role: 'viewer', readOnly: true, approvalPolicy: 'ask-destructive', cert: false,
    announceAgent: true, sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 600_000,
    sessionBackgroundMaxMs: 3_600_000, commandQuotaPerDay: 0,
    transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
  } as unknown as Profile;

  const viewerProdProfile = {
    name: 'viewer-prod', host: 'h', port: 22, user: 'viewer', auth: 'agent', tty: false,
    timeout: 60_000, maxChars: 5000, maxOutputBytes: 1_048_576, group: 'prod',
    role: 'viewer', readOnly: false, approvalPolicy: 'ask-destructive', cert: false,
    announceAgent: true, sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 600_000,
    sessionBackgroundMaxMs: 3_600_000, commandQuotaPerDay: 0,
    transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
  } as unknown as Profile;

  const engine = new PolicyEngine(DEFAULT_RULES);

  // From the draft advisory, measured against real binaries.
  const DRAFT_ADVISORY_ROWS: ReadonlyArray<readonly [name: string, command: string]> = [
    ['uniq: overwrites the second operand (positional output file)',
      'uniq /etc/passwd /root/.ssh/authorized_keys'],
    ['journalctl --vacuum-time: deletes archived journal files', 'journalctl --vacuum-time=1s'],
    ['journalctl --rotate: rotates journal files', 'journalctl --rotate'],
    ['hostname: sets the hostname', 'hostname pwned'],
    ['date -s: sets the system clock', 'date -s 00:00'],
    ['git branch -D: deletes a branch', 'git branch -D main'],
    ['git remote add: writes repository config', 'git remote add x http://10.0.0.1/repo.git'],
    ['find -fprint0: creates/truncates FILE', 'find /tmp -fprint0 /tmp/out'],
    ['ip route add: changes the routing table', 'ip route add 10.0.0.0/24 via 10.0.0.1'],
    ['ifconfig down: takes an interface down', 'ifconfig eth0 down'],
    ['arp -d: deletes an ARP entry', 'arp -d 10.0.0.1'],
  ];

  // Found during this design round.
  const DESIGN_ROUND_ROWS: ReadonlyArray<readonly [name: string, command: string]> = [
    ['git log --output: writes FILE (git, local)', 'git log --output=/tmp/out.txt'],
    ['git show --output: writes FILE (git, local)', 'git show --output=/tmp/out.txt HEAD'],
    ['git diff --output: documented, same option family', 'git diff --output=/tmp/out.txt'],
    ['sort /O FILE IN on Windows: writes FILE', 'sort /O /tmp/out.txt /tmp/in.txt'],
    ['arp /d on Windows: inferred delete', 'arp /d 10.0.0.1'],
    ['arp /s on Windows: inferred add', 'arp /s 10.0.0.1 00-aa-00-62-c6-09'],
    ['ss -K: documented, kills sockets', 'ss -K dst 10.0.0.1'],
    ['file -C -m: documented, writes a compiled .mgc', 'file -C -m /tmp/magic.mgc'],
    ['journalctl --flush: documented effect', 'journalctl --flush'],
    ['journalctl --sync: documented effect', 'journalctl --sync'],
    ['journalctl --relinquish-var: documented effect', 'journalctl --relinquish-var'],
    ['ip route flush all: documented effect', 'ip route flush all'],
    ['ip addr flush dev: documented effect', 'ip addr flush dev eth0'],
    ['git remote set-url: documented effect', 'git remote set-url origin http://10.0.0.1/repo.git'],
    ['git branch -m: documented effect', 'git branch -m oldname newname'],
    ['hostname -F FILE: documented effect', 'hostname -F /tmp/hostname-file'],
    ['date --set=…: documented effect', 'date --set=00:00'],
  ];

  // Four exclusions pinned separately: real excluded options an audit found,
  // not merely an unrecognised word the grammar was always going to refuse.
  const AUDIT_EXCLUSION_ROWS: ReadonlyArray<readonly [name: string, command: string]> = [
    ['find -newermt: excluded from the audit', 'find . -newermt 2020-01-01'],
    ['netstat -z: excluded from the audit', 'netstat -z'],
    ['systemctl status -H: excluded from the audit', 'systemctl status -H somehost nginx'],
    ['ss -D: excluded from the audit', 'ss -D /tmp/x'],
  ];

  const ALL_ROWS = [...DRAFT_ADVISORY_ROWS, ...DESIGN_ROUND_ROWS, ...AUDIT_EXCLUSION_ROWS];

  it.each(ALL_ROWS)('%s: is not read-only (%s)', (_name, command) => {
    // Measured on this head: every row's classification lands on `safe`, never
    // `read-only` — the property every row in this table exists to pin — and
    // never raised further by DISQUALIFYING_ARGS or a nested elevation either.
    expect(classifyCommand(command).class, command).toBe('safe');
  });

  it.each(ALL_ROWS)('%s: a readOnly profile classifies safe and denies it (%s)', (_name, command) => {
    const evaluation = engine.evaluate(command, readOnlyProfile);
    expect(evaluation.commandClass, command).toBe('safe');
    expect(evaluation.decision, command).toBe('deny');
  });

  it.each(ALL_ROWS)('%s: a viewer on prod classifies safe and denies it (%s)', (_name, command) => {
    const evaluation = engine.evaluate(command, viewerProdProfile);
    expect(evaluation.commandClass, command).toBe('safe');
    expect(evaluation.decision, command).toBe('deny');
  });
});

/**
 * Final-review fix wave (2026-09-26): the review over a297c73..596d829 found
 * one Critical and four Important classes plus two Minors, and the ledger
 * ruled them into one fail-closed wave. Every block below drives its fix
 * through the engine (`classifyCommand` plus a `PolicyEngine` decision), and
 * each behaviour pin was measured failing on the pre-fix head before its
 * production line landed.
 */
describe('final review: an unquoted glob word falls a grammar-checked reader to safe (Critical)', () => {
  const readOnlyProfile = {
    name: 'ro-fix', host: 'h', port: 22, user: 'viewer', auth: 'agent', tty: false,
    timeout: 60_000, maxChars: 5000, maxOutputBytes: 1_048_576, group: 'prod',
    role: 'viewer', readOnly: true, approvalPolicy: 'ask-destructive', cert: false,
    announceAgent: true, sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 600_000,
    sessionBackgroundMaxMs: 3_600_000, commandQuotaPerDay: 0,
    transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
  } as unknown as Profile;
  const engine = new PolicyEngine(DEFAULT_RULES);

  it('uniq with a one-word glob operand falls to safe — the advisory\'s lead form', () => {
    // The matcher counted one operand, but the host shell expands the glob:
    // `id_ed25519*` becomes `id_ed25519 id_ed25519.pub`, the second word is
    // uniq's OUTFILE, and measured on debian:12 the .pub was overwritten with
    // the private key while the command classified `read-only`.
    expect(classifyCommand('uniq /root/.ssh/id_ed25519*').class).toBe('safe');
  });

  it('the rejection names the glob word', () => {
    expect(classifyCommand('uniq /root/.ssh/id_ed25519*').readOnlyRejection).toEqual({
      binary: 'uniq',
      word: '/root/.ssh/id_ed25519*',
    });
  });

  it('a quoted glob stays read-only — the quotes make it one operand of data', () => {
    expect(classifyCommand('find /var -name "*.conf" -type f').class).toBe('read-only');
  });

  it('an escaped glob falls to safe — the windows reading sees it unquoted', () => {
    // `\*` is escaped only to POSIX; cmd.exe reads the backslash as an ordinary
    // path character, so the glob word is unquoted in that reading, and a grant
    // must qualify under every reading (GHSA-972x-g47g-3922).
    expect(classifyCommand('sort /var/log/\\*').class).toBe('safe');
  });

  it('an unquoted glob in a value flag\'s word is judged too', () => {
    expect(classifyCommand('find /var -name *.conf').class).toBe('safe');
  });

  it("'any' readers are exempt — extra operands are data there, no option to inject", () => {
    expect(classifyCommand('cat /etc/*.conf').class).toBe('read-only');
    expect(classifyCommand('ls /root/*').class).toBe('read-only');
  });

  it('a readOnly profile denies the glob form and the reason names the word', () => {
    const evaluation = engine.evaluate('uniq /root/.ssh/id_ed25519*', readOnlyProfile);
    expect(evaluation.commandClass).toBe('safe');
    expect(evaluation.decision).toBe('deny');
    expect(evaluation.reason).toContain('`/root/.ssh/id_ed25519*`');
  });
});

describe('final review: an option word after the first operand falls to safe where an implementation does not permute', () => {
  const readOnlyProfile = {
    name: 'ro-fix', host: 'h', port: 22, user: 'viewer', auth: 'agent', tty: false,
    timeout: 60_000, maxChars: 5000, maxOutputBytes: 1_048_576, group: 'prod',
    role: 'viewer', readOnly: true, approvalPolicy: 'ask-destructive', cert: false,
    announceAgent: true, sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 600_000,
    sessionBackgroundMaxMs: 3_600_000, commandQuotaPerDay: 0,
    transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
  } as unknown as Profile;
  const engine = new PolicyEngine(DEFAULT_RULES);

  it('uniq: a trailing option word falls to safe — macOS reads it as OUTFILE', () => {
    // macOS uniq's optstring is `+`-prefixed (POSIX order), so `uniq IN -c`
    // makes `-c` the second operand — the OUTFILE uniq overwrites. GNU
    // permutes and the same word is harmless there; the grammar must hold
    // for every implementation the name resolves to.
    expect(classifyCommand('uniq /etc/passwd -c').class).toBe('safe');
  });

  it('ifconfig: a trailing option cluster falls to safe — macOS letters after the interface are settings', () => {
    expect(classifyCommand('ifconfig en0 -av').class).toBe('safe');
    expect(classifyCommand('ifconfig en0 -dad').class).toBe('safe');
  });

  it('options before the operand still pass, on both readers', () => {
    expect(classifyCommand('uniq -c /etc/passwd').class).toBe('read-only');
    expect(classifyCommand('ifconfig -a').class).toBe('read-only');
    expect(classifyCommand('ifconfig en0').class).toBe('read-only');
  });

  it('a reader without the flag keeps accepting option words after operands', () => {
    // `sort` permutes on every implementation the audit measured (GNU,
    // busybox, BSD), so it does not set `optionsBeforeOperands`; this pins
    // that the new refusal is opt-in per entry, not a matcher-wide rule.
    expect(classifyCommand('sort x -k2,2').class).toBe('read-only');
  });

  it('a readOnly profile denies uniq IN -c and the reason names the option word', () => {
    const result = classifyCommand('uniq /etc/passwd -c');
    expect(result.readOnlyRejection).toEqual({ binary: 'uniq', word: '-c' });
    const evaluation = engine.evaluate('uniq /etc/passwd -c', readOnlyProfile);
    expect(evaluation.commandClass).toBe('safe');
    expect(evaluation.decision).toBe('deny');
    expect(evaluation.reason).toContain('`-c`');
  });

  it('uniq IN -- falls to safe — the re-review finding', () => {
    // The getopt `--` branch ran before the option-position rule, so the
    // terminator swallowed the word and `uniq /etc/passwd --` stayed
    // read-only. On a non-permuting implementation (macOS uniq's
    // `+`-prefixed optstring) option scanning has already stopped at the
    // INPUT operand, and `--` is read as the OUTFILE — a write to a file
    // literally named `--`. `--` is an option-looking word and must be
    // judged by the position rule like any other.
    const result = classifyCommand('uniq /etc/passwd --');
    expect(result.class).toBe('safe');
    expect(result.readOnlyRejection).toEqual({ binary: 'uniq', word: '--' });
  });

  it('ifconfig en0 -- falls to safe — same class, same fix', () => {
    // BSD ifconfig reads everything after the interface operand as
    // interface configuration words; `--` is one of them, not a terminator.
    expect(classifyCommand('ifconfig en0 --').class).toBe('safe');
  });

  it('`--` before the first operand keeps its terminator meaning', () => {
    expect(classifyCommand('uniq -- /etc/passwd').class).toBe('read-only');
  });

  it('a readOnly profile denies uniq IN -- and the reason names `--`', () => {
    const evaluation = engine.evaluate('uniq /etc/passwd --', readOnlyProfile);
    expect(evaluation.commandClass).toBe('safe');
    expect(evaluation.decision).toBe('deny');
    expect(evaluation.reason).toContain('`--`');
  });
});

describe('final review: exact style refuses `--` instead of ending checks there', () => {
  const readOnlyProfile = {
    name: 'ro-fix', host: 'h', port: 22, user: 'viewer', auth: 'agent', tty: false,
    timeout: 60_000, maxChars: 5000, maxOutputBytes: 1_048_576, group: 'prod',
    role: 'viewer', readOnly: true, approvalPolicy: 'ask-destructive', cert: false,
    announceAgent: true, sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 600_000,
    sessionBackgroundMaxMs: 3_600_000, commandQuotaPerDay: 0,
    transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
  } as unknown as Profile;
  const engine = new PolicyEngine(DEFAULT_RULES);

  it('find: `--` is refused as an unrecognised word, so primaries after it are still checked', () => {
    // GNU find keeps evaluating its primaries after `--` (measured: `find --
    // d -fprint /tmp/x` wrote the file), so ending the checks at `--` voids
    // the proof. The harmless spelling is refused with it — the ruling's
    // priced cost (`find -- dir …`, rare).
    expect(classifyCommand('find -- /etc/hosts -type f').class).toBe('safe');
  });

  it('the finding\'s own write form stays above safe — DISQUALIFYING_ARGS raises it regardless', () => {
    expect(classifyCommand('find -- d -fprint /tmp/x').class).toBe('destructive');
  });

  it('getopt keeps `--` as end-of-options', () => {
    expect(classifyCommand('git diff -- a b').class).toBe('read-only');
  });

  it('a readOnly profile denies find -- PATH -type f', () => {
    const evaluation = engine.evaluate('find -- /etc/hosts -type f', readOnlyProfile);
    expect(evaluation.commandClass).toBe('safe');
    expect(evaluation.decision).toBe('deny');
  });
});

describe('final review: `git remote show` falls to safe — its operand can run a program', () => {
  const readOnlyProfile = {
    name: 'ro-fix', host: 'h', port: 22, user: 'viewer', auth: 'agent', tty: false,
    timeout: 60_000, maxChars: 5000, maxOutputBytes: 1_048_576, group: 'prod',
    role: 'viewer', readOnly: true, approvalPolicy: 'ask-destructive', cert: false,
    announceAgent: true, sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 600_000,
    sessionBackgroundMaxMs: 3_600_000, commandQuotaPerDay: 0,
    transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
  } as unknown as Profile;
  const engine = new PolicyEngine(DEFAULT_RULES);

  it('git remote show <name> falls to safe', () => {
    expect(classifyCommand('git remote show origin').class).toBe('safe');
  });

  it('git remote show <URL> falls to safe — the finding\'s own form', () => {
    // Measured in the review: git accepts a URL there and runs ssh /
    // git-remote-<helper> against the caller-chosen target.
    expect(classifyCommand('git remote show http://10.0.0.1/repo.git').class).toBe('safe');
  });

  it('bare git remote, -v and get-url stay read-only', () => {
    expect(classifyCommand('git remote').class).toBe('read-only');
    expect(classifyCommand('git remote -v').class).toBe('read-only');
    expect(classifyCommand('git remote get-url origin').class).toBe('read-only');
  });

  it('a readOnly profile denies git remote show <URL> and the reason names `show`', () => {
    const evaluation = engine.evaluate('git remote show http://10.0.0.1/repo.git', readOnlyProfile);
    expect(evaluation.commandClass).toBe('safe');
    expect(evaluation.decision).toBe('deny');
    expect(evaluation.reason).toContain('`show`');
  });
});

describe('final review: viewer holds safe on dev — the engine the docs must describe', () => {
  // The review found docs claiming `viewer` holds `read-only` "on every
  // tier". The engine's DEFAULT_RULES give viewer `['read-only', 'safe']` on
  // dev, so the claim was false where it mattered: on dev a viewer runs
  // `safe` commands. This pin exists so any future doc sentence of that
  // shape has a falsifiable counterpart here; the fix itself was to the
  // docs (README, SECURITY.md, the changeset), which cannot make an engine
  // test fail.
  const engine = new PolicyEngine(DEFAULT_RULES);

  const viewerOn = (group: string) => ({
    name: `viewer-${group}`, host: 'h', port: 22, user: 'viewer', auth: 'agent', tty: false,
    timeout: 60_000, maxChars: 5000, maxOutputBytes: 1_048_576, group,
    role: 'viewer', readOnly: false, approvalPolicy: 'ask-destructive', cert: false,
    announceAgent: true, sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 600_000,
    sessionBackgroundMaxMs: 3_600_000, commandQuotaPerDay: 0,
    transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
  } as unknown as Profile);

  it('viewer on dev ALLOWS a safe command', () => {
    const evaluation = engine.evaluate('npm install', viewerOn('dev'));
    expect(evaluation.commandClass).toBe('safe');
    expect(evaluation.decision).toBe('allow');
  });

  it('viewer on prod DENIES the same safe command', () => {
    const evaluation = engine.evaluate('npm install', viewerOn('prod'));
    expect(evaluation.commandClass).toBe('safe');
    expect(evaluation.decision).toBe('deny');
  });
});

describe('final review: Windows trailing-slash switch operands fall to safe', () => {
  // Measured 2026-09-26 on the Windows VM (build 10.0.26200.9550), confined
  // to %TEMP%: `sort /O vmo.txt vmi.txt` (control) wrote vmo.txt, while
  // `/O/`, `/o/`, `/OU/`, `/OUTPUT/`, `/T/` and `/A/` all failed with
  // "Invalid switch" and wrote nothing. The rule is tightened anyway
  // (fail-closed): it is shared with `arp`, whose `/d`/`/s` slash tolerance
  // cannot be measured without running a state-changing form.
  const readOnlyProfile = {
    name: 'ro-fix', host: 'h', port: 22, user: 'viewer', auth: 'agent', tty: false,
    timeout: 60_000, maxChars: 5000, maxOutputBytes: 1_048_576, group: 'prod',
    role: 'viewer', readOnly: true, approvalPolicy: 'ask-destructive', cert: false,
    announceAgent: true, sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 600_000,
    sessionBackgroundMaxMs: 3_600_000, commandQuotaPerDay: 0,
    transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
  } as unknown as Profile;
  const engine = new PolicyEngine(DEFAULT_RULES);

  it('sort /O/ and its siblings fall to safe', () => {
    expect(classifyCommand('sort /O/ /tmp/o /tmp/i').class).toBe('safe');
    expect(classifyCommand('sort /OUTPUT/ /tmp/o /tmp/i').class).toBe('safe');
    expect(classifyCommand('sort /T/ /tmp/o /tmp/i').class).toBe('safe');
  });

  it('arp /d/ falls to safe — unmeasured, fail-closed', () => {
    expect(classifyCommand('arp /d/').class).toBe('safe');
  });

  it('the priced friction: a trailing-slash top-level dir operand falls to safe', () => {
    expect(classifyCommand('sort /etc/').class).toBe('safe');
  });

  it('a multi-segment path with a trailing slash still passes', () => {
    expect(classifyCommand('sort /var/log/').class).toBe('read-only');
  });

  it('a readOnly profile denies sort /O/ FILE IN', () => {
    const evaluation = engine.evaluate('sort /O/ /tmp/o /tmp/i', readOnlyProfile);
    expect(evaluation.commandClass).toBe('safe');
    expect(evaluation.decision).toBe('deny');
  });
});

describe('final review: an empty rejected word renders as "" in the refusal', () => {
  const readOnlyProfile = {
    name: 'ro-fix', host: 'h', port: 22, user: 'viewer', auth: 'agent', tty: false,
    timeout: 60_000, maxChars: 5000, maxOutputBytes: 1_048_576, group: 'prod',
    role: 'viewer', readOnly: true, approvalPolicy: 'ask-destructive', cert: false,
    announceAgent: true, sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 600_000,
    sessionBackgroundMaxMs: 3_600_000, commandQuotaPerDay: 0,
    transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
  } as unknown as Profile;
  const engine = new PolicyEngine(DEFAULT_RULES);

  it('a quoted empty operand is refused with the empty word carried', () => {
    const result = classifyCommand('hostname ""');
    expect(result.class).toBe('safe');
    expect(result.readOnlyRejection).toEqual({ binary: 'hostname', word: '' });
  });

  it('the engine reason renders the empty word as "" — not blank backticks', () => {
    const evaluation = engine.evaluate('hostname ""', readOnlyProfile);
    expect(evaluation.decision).toBe('deny');
    expect(evaluation.reason).toContain('`""` is not accepted there.');
  });
});
