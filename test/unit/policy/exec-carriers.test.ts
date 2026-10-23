import { describe, it, expect } from 'vitest';
import { classifyCommand } from '../../../src/policy/classifier.js';
import { PolicyEngine } from '../../../src/policy/engine.js';
import type { Profile } from '../../../src/types.js';
import { cpuMs } from './cpu-cost.js';

/**
 * GHSA-cm4c-4q74-mgmj: binaries that hand a program to another executor — or
 * reach root by their own design — were absent from every table this file
 * keeps, so each classified `safe`: the one class the default bindings grant
 * an `operator` on `prod`, and the one class that never trips the approval
 * gate. Every case below ran, with no approval and no role check, while
 * `sudo id` was refused.
 *
 * The classes follow the file's existing answers for the same shape:
 *
 *  - a flag-borne program in a language this classifier cannot read is
 *    `destructive` (`gdb -ex`, `expect -c`, `vi -c` — the python/perl/node
 *    answer);
 *  - a carrier whose shell text it CAN read keeps the shell text as the
 *    nested command, so `tar --checkpoint-action=exec=sudo id` comes out
 *    `privileged` exactly like `awk 'BEGIN{system("sudo id")}'` does, and the
 *    outer stays `destructive` when the carried command is harmless;
 *  - a privilege broker is `privileged` (`docker run --privileged`,
 *    `docker exec -u 0`, `systemd-run --uid=0`, `nsenter -t`), the
 *    `runuser`/`setpriv` answer;
 *  - `make` runs recipes this classifier never sees, and `ssh` hands its
 *    operands to a shell on another host, so both are `destructive` — the
 *    "we cannot tell" answer, same as `awk -f progfile`.
 *
 * The review round added every adjacent spelling the first cut missed:
 * flag long forms and attached values (`--eval-command`, `--cmd`, `-u0`,
 * `0:0`), subcommand synonyms and global flags (`docker container run`,
 * `-H`), tar abbreviation prefixes and the detached `--checkpoint-action
 * exec=…` value, Windows `.exe`/case spellings, and the wrapper prefixes
 * (`strace`, `flock`, …) that hid every head-keyed gate.
 */
describe('exec carriers and privilege brokers (GHSA-cm4c-4q74-mgmj)', () => {
  it.each([
    ['sqlite3 :memory: ".shell id"', 'destructive'],
    ['sqlite3 :memory: ".shell sudo id"', 'privileged'],
    ['sqlite3 :memory: ".system touch /tmp/x"', 'destructive'],
    ['tar -cf /dev/null --checkpoint=1 "--checkpoint-action=exec=sudo id" .', 'privileged'],
    ['tar --checkpoint-action=exec=touch /tmp/x .', 'destructive'],
    // Every spelling of the option GNU tar honours: unambiguous prefixes from
    // `--checkpoint-a` up (real tar runs `--checkpoint-act`), and the value
    // detached as the next argv word (measured executing on tar 1.34).
    ['tar --checkpoint-act=exec=sudo id .', 'privileged'],
    ['tar --checkpoint-a=exec=touch /tmp/x .', 'destructive'],
    ['tar -cf out.tar --checkpoint=1 --checkpoint-action "exec=sudo id" .', 'privileged'],
    ['tar --checkpoint-action exec=touch /tmp/x .', 'destructive'],
    ['gdb -nx -batch -ex "shell id"', 'destructive'],
    // The -ex program is gdb's own language, so it is unreadable like
    // python's -c: the outer class is the answer, the text inside is not
    // re-read. `shell sudo id` still gates on approval as destructive.
    ['gdb -ex "shell sudo id"', 'destructive'],
    // gdb's documented sibling spellings of -ex.
    ['gdb --eval-command "shell id"', 'destructive'],
    ['gdb -iex "shell id"', 'destructive'],
    ['gdb --init-eval-command "shell id"', 'destructive'],
    ['expect -c "spawn id"', 'destructive'],
    ['vi -c "!id" /tmp/f', 'destructive'],
    ['ex -c "!sudo id" /tmp/f', 'destructive'],
    // --cmd runs ex commands before the vimrc (measured: `!cmd` executes);
    // view/gvim/vimdiff are vim under other names.
    ['vim --cmd "silent! !sudo id" /tmp/f', 'destructive'],
    ['view -c "!id" /tmp/f', 'destructive'],
    ['gvim -c "!id"', 'destructive'],
    ['vimdiff -c "!id" a b', 'destructive'],
    ['make -f /tmp/pwn.mk', 'destructive'],
    ['make deploy', 'destructive'],
    ['make', 'destructive'],
    // flock takes a lockfile before the command it runs, so the wrapped
    // form carries one (`flock make pwn` would lock a file named `make`
    // and run `pwn` — the review of GHSA-5cjr-rc2p-f66f corrected the
    // wrapper's operand reading here).
    ['flock /tmp/lk make pwn', 'destructive'],
    ['ssh other-host id', 'destructive'],
    ['ssh other-host "sudo id"', 'privileged'],
  ])('%j classifies %s, not safe', (command, expected) => {
    expect(classifyCommand(command).class, command).toBe(expected);
  });

  it.each([
    ['docker run --privileged alpine id'],
    ['docker run --privileged=true alpine id'],
    ['docker run --privileged=1 alpine id'],
    ['docker exec -u 0 ssh-mcp-ssh-admin-1 id'],
    // pflag's attached shorthands and docker's documented user:group form —
    // each is uid 0 in the container.
    ['docker exec -u0 ctr id'],
    ['docker exec -u=0 ctr id'],
    ['docker exec -u 0:0 ctr cat /etc/shadow'],
    ['docker run -u root:root alpine id'],
    ['docker run --user 0 alpine id'],
    ['docker run --user=0 alpine id'],
    ['docker run --user=root alpine id'],
    // Two-word subcommand synonym, and the global flags an operator aiming
    // at a remote daemon writes before it.
    ['docker container run --privileged alpine id'],
    ['docker container exec -u 0 ctr id'],
    ['docker -H tcp://127.0.0.1 run --privileged alpine id'],
    ['docker --context prod run --privileged alpine id'],
    ['systemd-run --uid=0 id'],
    ['systemd-run --uid 0 id'],
    ['systemd-run --uid=root id'],
    // The property spelling of the same root choice.
    ['systemd-run -p User=root id'],
    ['systemd-run --property=User=0 id'],
    ['nsenter -t 1 -m -u -i -n -p id'],
    ['nsenter -t1 id'],
    ['nsenter --target=1 id'],
    // Wrappers the tables step over — `env` and `nice` on the wrapper list,
    // and the review round's strace/flock additions.
    ['env docker run --privileged alpine id'],
    ['nice nsenter -t 1 id'],
    ['strace docker run --privileged alpine id'],
    // The pre-existing hole the same round closes for free.
    ['strace sudo id'],
  ])('%j reaches root by design, so it classifies privileged', (command) => {
    const parsed = classifyCommand(command);
    expect(parsed.class, command).toBe('privileged');
    expect(parsed.binary, command).not.toBe('sudo');
  });

  it('Windows spellings of the same binaries reach the same gates', () => {
    for (const [command, expected] of [
      ['docker.exe run --privileged alpine id', 'privileged'],
      ['Docker run --privileged alpine id', 'privileged'],
      ['make.exe deploy', 'destructive'],
      ['MAKE deploy', 'destructive'],
      ['ssh.exe other-host id', 'destructive'],
      ['sqlite3.exe :memory: ".shell id"', 'destructive'],
      ['nsenter.exe -t 1 id', 'privileged'],
      ['systemd-run.exe --uid=0 id', 'privileged'],
    ] as const) {
      expect(classifyCommand(command).class, command).toBe(expected);
    }
  });

  it('the approval gate no longer lets them through for an operator on prod', () => {
    // The reporter's harness: compiled-in defaults, operator/prod, and the
    // policy class that is supposed to gate execution. `safe` never gates,
    // and for this profile the bindings allow only read-only and safe, so
    // the decision is exactly `deny` — not merely "not allow".
    const engine = new PolicyEngine();
    const profile = {
      name: 'prod', role: 'operator', group: 'prod',
      approvalPolicy: 'ask-destructive', readOnly: false,
    } as unknown as Profile;

    for (const command of [
      'sqlite3 :memory: ".shell id"',
      'tar -cf /dev/null --checkpoint=1 "--checkpoint-action=exec=sudo id" .',
      'tar --checkpoint-act=exec=sudo id .',
      'gdb -nx -batch -ex "shell id"',
      'gdb --eval-command "shell id"',
      'docker run --privileged alpine id',
      'docker exec -u 0:0 ssh-mcp-ssh-admin-1 id',
      'docker container exec -u 0 ctr id',
      'systemd-run --uid=0 id',
      'nsenter -t 1 -m -u -i -n -p id',
      'expect -c "spawn id"',
      'vi -c "!id" /tmp/f',
      'vim --cmd "!sudo id" /tmp/f',
      'make -f /tmp/pwn.mk',
      'ssh other-host id',
    ]) {
      const evaluation = engine.evaluate(command, profile);
      expect(evaluation.decision, command).toBe('deny');
      expect(evaluation.commandClass, command).not.toBe('safe');
    }
  });

  it('keeps the ordinary invocations of the same binaries as they were', () => {
    // Boundaries, deliberately: the gates above key on the carrier spelling,
    // not on the binary's name. Plain `docker exec` runs as the container's
    // default user and plain `gdb`/`vi`/`expect` take a file the way
    // `python3 script.py` already does — a script-file execution this file
    // has never gated, and changing that here would be a different decision
    // than the one this advisory forces.
    for (const [command, expected] of [
      ['sqlite3 db "SELECT 1"', 'safe'],
      ['tar -cf out.tgz dir', 'safe'],
      ['tar --checkpoint=1 .', 'safe'],
      // An empty exec value runs nothing.
      ['tar --checkpoint-action=exec= .', 'safe'],
      ['docker run -e FOO=bar img', 'safe'],
      ['docker exec ssh-mcp-ssh-admin-1 id', 'safe'],
      // `docker ps` is an allowlisted two-word reader, not a safe fall-through.
      ['docker ps', 'read-only'],
      ['docker compose up', 'safe'],
      ['docker run --privileged=false alpine id', 'safe'],
      ['docker run -u 1000 alpine id', 'safe'],
      ['docker run --user=1000 alpine id', 'safe'],
      ['systemd-run --uid=1000 id', 'safe'],
      ['systemd-run -p User=1000 id', 'safe'],
      ['nsenter -m -u -i -n -p id', 'safe'],
      ['gdb ./a.out', 'safe'],
      ['vi /tmp/f', 'safe'],
      ['expect script.exp', 'safe'],
      ['ssh -V', 'safe'],
      ['kubectl get pods', 'safe'],
      ['cargo build', 'safe'],
    ] as const) {
      expect(classifyCommand(command).class, command).toBe(expected);
    }
  });

  it('a mention of a carrier spelling is not an invocation', () => {
    // The review round's false positives: the tar extraction used to fire on
    // any word of any segment, so echoing or grepping build text that
    // contains the flag handed the model a `privileged` class with the wrong
    // binary named in the audit record. Head-gated like every other rule.
    for (const [command, expected] of [
      ["echo '--checkpoint-action=exec=sudo reboot'", 'read-only'],
      ['grep -e "--checkpoint-action=exec=sudo reboot" build.sh', 'read-only'],
      ['cat --checkpoint-action=exec=rm', 'read-only'],
    ] as const) {
      expect(classifyCommand(command).class, command).toBe(expected);
    }
  });

  it('accepts and pins the one over-classification it chose', () => {
    // Docker's own value-taking flags make "where docker's flags end and the
    // image's argv begins" unparseable without docker's full option table,
    // so the broker scan reads past the image operand. A `--privileged` in
    // the container's argv still names root-seeking behaviour inside it, and
    // the cost of asking is an approval prompt — the direction this file
    // errs in. Pinned so the choice is a decision, not a surprise.
    expect(classifyCommand('docker run alpine echo --privileged').class).toBe('privileged');
    expect(classifyCommand('docker run alpine env --user=root id').class).toBe('privileged');
  });

  it('stays cheap on many long tar and sqlite carrier words', () => {
    // The review round's cost measurement: these carriers join the depth-8
    // classify×nested cross-recursion, so the bound is a growth ratio like
    // the sibling cost tests — near-linear passes, a quadratic blow-up does
    // not.
    const fastestMs = (command: string) => cpuMs(() => classifyCommand(command));
    const scale = (n: number) =>
      `tar cf o.tgz i ${'--checkpoint-action=exec=x '.repeat(n)}sqlite3 db '${'.shell y '.repeat(n)}'`;
    const a = fastestMs(scale(50));
    const b = fastestMs(scale(500));
    // 10x the input; anything near linear is fine, quadratic is not.
    expect(b).toBeLessThan(Math.max(a * 300, 100));
  });
});
