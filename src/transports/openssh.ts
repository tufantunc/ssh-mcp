import { spawn, ChildProcess, execFile } from 'node:child_process';
import { promises as fs, rmSync } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { randomBytes } from 'node:crypto';
import {
  ISshTransport,
  ExecOptions,
  ExecElevatedOptions,
  ExecResult,
  ErrorCategory,
  TransportConfig,
} from './types.js';

/**
 * OpenSshTransport — spawns the system `ssh` binary per command.
 *
 * Rationale: the mscdex/ssh2 library does not implement GSSAPI/Kerberos
 * userauth (upstream issue #333, open since 2015). Delegating to the OS's
 * OpenSSH client is the only way to get Kerberos SSO support without
 * reimplementing the SSH userauth state machine.
 *
 * No connection multiplexing: Win32-OpenSSH does not support ControlMaster
 * (issue #1328), so each exec spawns a fresh `ssh` process. This accepts a
 * per-call handshake cost (including Kerberos AP-REQ round trip) in
 * exchange for feature completeness on Windows domain-joined clients.
 */
export class OpenSshTransport implements ISshTransport {
  readonly name = 'openssh' as const;

  private askpassDir?: string;
  private askpassEnvName?: string;
  private cleanupRegistered = false;

  constructor(private cfg: TransportConfig) {}

  async init(): Promise<void> {
    await this.verifySshBinary();

    if (this.cfg.authMode === 'password') {
      if (!this.cfg.password) {
        throw new Error('authMode=password requires --password');
      }
      await this.prepareAskpassHelper(this.cfg.password);
    }

    if (!this.cleanupRegistered) {
      const cleanup = () => { void this.close(); };
      process.once('exit', cleanup);
      process.once('SIGINT', () => { cleanup(); process.exit(130); });
      process.once('SIGTERM', () => { cleanup(); process.exit(143); });
      this.cleanupRegistered = true;
    }
  }

  async exec(command: string, opts: ExecOptions): Promise<ExecResult> {
    // If suPassword is configured, route through PTY-su state machine to
    // preserve the implicit-su behaviour that ssh2 transport has.
    if (this.cfg.suPassword) {
      return this.runSuViaPty(command, this.cfg.suPassword, opts);
    }
    return this.runSsh(command, opts);
  }

  async execElevated(command: string, opts: ExecElevatedOptions): Promise<ExecResult> {
    if (opts.mode === 'sudo') {
      const pwd = opts.password ?? this.cfg.sudoPassword;
      // Match ssh2 persistent-root semantics: the ssh2 transport establishes a
      // root `su` shell at connect time when --suPassword is set, so its
      // sudo-exec re-enters that already-root shell and `sudo -n` trivially
      // succeeds. The OpenSSH transport spawns a fresh process per command, so a
      // plain `sudo -n` would run as the unprivileged user and fail for users
      // who followed the documented persistent-root `--suPassword` setup. When
      // no sudo password is available but a su password is, run the command as
      // root via su to preserve equivalent behaviour.
      if (pwd === undefined && this.cfg.suPassword) {
        return this.runSuViaPty(command, this.cfg.suPassword, opts);
      }
      if (pwd !== undefined) {
        // OpenSSH receives the remote command as a local ssh argv element.
        // Embedding the sudo password in that command (the ssh2 wrapper style)
        // exposes it to local process inspection. Keep argv password-free and
        // feed sudo -S via stdin instead.
        const wrapped = buildOpenSshSudoWrapper(command, true);
        return this.runSsh(wrapped, {
          ...opts,
          stdin: `${pwd}\n${opts.stdin ?? ''}`,
        });
      }
      const wrapped = buildOpenSshSudoWrapper(command, false);
      return this.runSsh(wrapped, opts);
    }
    const suPwd = opts.password ?? this.cfg.suPassword;
    if (!suPwd) {
      return {
        stdout: '',
        stderr: 'su elevation requires --suPassword',
        exitCode: null,
        category: 'auth',
      };
    }
    return this.runSuViaPty(command, suPwd, opts);
  }

  async close(): Promise<void> {
    if (this.askpassDir) {
      try {
        // Synchronous removal: close() is invoked from process 'exit'/SIGINT/
        // SIGTERM handlers (see init()), which cannot await. An async fs.rm()
        // there would be discarded — the event loop is torn down by
        // process.exit() before the removal runs, leaking the short-lived
        // askpass temp dir. rmSync guarantees cleanup completes before exit.
        rmSync(this.askpassDir, { recursive: true, force: true });
      } catch (e) {
        // best-effort cleanup
      }
      this.askpassDir = undefined;
      this.askpassEnvName = undefined;
    }
  }

  /** Verify `ssh` is on PATH and usable. Throws if missing. */
  private async verifySshBinary(): Promise<void> {
    return new Promise((resolve, reject) => {
      execFile('ssh', ['-V'], (err) => {
        if (err) {
          reject(new Error(
            'ssh binary not found on PATH. ' +
            'Install OpenSSH client (Windows: Settings > Apps > Optional features > OpenSSH Client; ' +
            'Linux: apt install openssh-client).'
          ));
          return;
        }
        resolve();
      });
    });
  }

  /**
   * Write a `.cmd`/`.sh` askpass helper to a temp dir and remember its path.
   * Password lives in an env var passed only to spawned ssh children —
   * never written to disk, never placed in argv.
   */
  private async prepareAskpassHelper(password: string): Promise<void> {
    const envName = `SSH_MCP_PW_${process.pid}`;
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ssh-mcp-'));
    const isWindows = process.platform === 'win32';
    const helperName = isWindows ? 'askpass.cmd' : 'askpass.sh';
    const helperPath = path.join(dir, helperName);
    const content = renderAskpassHelper(envName, isWindows);
    await fs.writeFile(helperPath, content, { encoding: 'utf8' });
    if (!isWindows) {
      await fs.chmod(helperPath, 0o700);
    }
    this.askpassDir = dir;
    this.askpassEnvName = envName;
    (this as any)._askpassPath = helperPath;
    (this as any)._askpassPassword = password;
  }

  /** Build the ssh argv array for a single invocation. */
  buildArgs(opts: ExecOptions): string[] {
    const cfg = this.cfg;
    const a: string[] = [
      '-o', `StrictHostKeyChecking=${cfg.strictHostKeyChecking ?? 'accept-new'}`,
      '-o', `ConnectTimeout=${Math.max(1, Math.ceil(opts.timeoutMs / 1000))}`,
      '-o', 'ServerAliveInterval=30',
      '-o', 'ServerAliveCountMax=3',
      '-o', 'BatchMode=no',
      '-p', String(cfg.port),
    ];
    if (cfg.knownHostsFile) {
      a.push('-o', `UserKnownHostsFile=${cfg.knownHostsFile}`);
    }

    switch (cfg.authMode) {
      case 'kerberos':
        a.push(
          '-o', 'GSSAPIAuthentication=yes',
          '-o', `GSSAPIDelegateCredentials=${cfg.gssapiDelegateCredentials ?? 'no'}`,
          '-o', 'PreferredAuthentications=gssapi-with-mic',
          '-o', 'PubkeyAuthentication=no',
          '-o', 'PasswordAuthentication=no',
        );
        break;
      case 'key':
        if (cfg.keyPath) {
          a.push('-i', cfg.keyPath);
          // Force OpenSSH to use ONLY the supplied key. Without
          // IdentitiesOnly=yes, ssh still offers every ssh-agent identity
          // first, which can exhaust the server's MaxAuthTries before the
          // chosen `-i` key is ever tried. This matches the ssh2 path, which
          // authenticates with exactly the configured key.
          a.push('-o', 'IdentitiesOnly=yes');
        }
        a.push(
          '-o', 'PreferredAuthentications=publickey',
          '-o', 'PasswordAuthentication=no',
          '-o', 'GSSAPIAuthentication=no',
        );
        break;
      case 'password':
        a.push(
          '-o', 'PreferredAuthentications=password,keyboard-interactive',
          '-o', 'PubkeyAuthentication=no',
          '-o', 'GSSAPIAuthentication=no',
        );
        break;
      default:
        break;
    }

    if (opts.pty) a.push('-tt');
    a.push(`${cfg.username}@${cfg.host}`);
    return a;
  }

  /** Assemble env vars for spawned ssh process. Injects askpass env when needed. */
  private buildEnv(): NodeJS.ProcessEnv {
    const env: NodeJS.ProcessEnv = { ...process.env };
    if (this.cfg.authMode === 'password' && (this as any)._askpassPath) {
      env.SSH_ASKPASS = (this as any)._askpassPath;
      env.SSH_ASKPASS_REQUIRE = 'force';
      env.DISPLAY = env.DISPLAY ?? 'dummy:0';
      env[this.askpassEnvName!] = (this as any)._askpassPassword;
    }
    return env;
  }

  /** Run a single command via `ssh host <cmd>`, collect output, enforce timeout. */
  private runSsh(command: string, opts: ExecOptions): Promise<ExecResult> {
    return new Promise((resolve) => {
      const args = [...this.buildArgs(opts), command];
      let timedOut = false;
      let exited = false;
      let stdout = '';
      let stderr = '';

      const child: ChildProcess = spawn('ssh', args, {
        env: this.buildEnv(),
        windowsHide: true,
      });

      child.stdout?.on('data', (b: Buffer) => { stdout += b.toString('utf8'); });
      child.stderr?.on('data', (b: Buffer) => { stderr += b.toString('utf8'); });

      if (opts.stdin) {
        try { child.stdin?.end(opts.stdin); } catch (e) { /* ignore */ }
      } else {
        try { child.stdin?.end(); } catch (e) { /* ignore */ }
      }

      const timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGTERM');
        setTimeout(() => {
          // `child.killed` only reflects that a signal was *sent*, not that the
          // process actually exited. Gate the SIGKILL fallback on the real
          // `exited` flag (set from the close event) so a process ignoring
          // SIGTERM is still force-killed instead of being left to hang.
          if (!exited) child.kill('SIGKILL');
        }, 2000);
      }, opts.timeoutMs);

      child.on('error', (err: Error) => {
        exited = true;
        clearTimeout(timer);
        resolve({
          stdout,
          stderr: stderr + `\nspawn error: ${err.message}`,
          exitCode: null,
          category: 'transport',
        });
      });

      child.on('close', (code, signal) => {
        exited = true;
        clearTimeout(timer);
        const category = timedOut ? 'timeout' : classifyError(code, stderr);
        resolve({
          stdout,
          stderr,
          exitCode: timedOut ? null : (code ?? null),
          signal: signal ?? undefined,
          category,
        });
      });
    });
  }

  /**
   * PTY-based su interactive exec. Uses `ssh -tt` to force remote PTY
   * allocation. Drives an expect-style state machine via sentinel prompts.
   *
   * Random nonce in sentinels prevents collision if remote command output
   * happens to contain the same string literally.
   */
  private runSuViaPty(command: string, suPassword: string, opts: ExecOptions): Promise<ExecResult> {
    const nonce = randomBytes(8).toString('hex');
    const readyMark = `__SSH_MCP_READY_${nonce}__`;
    const endMark = `__SSH_MCP_END_${nonce}__`;
    const pwRe = /(?:^|\r?\n|[^\w])[Pp]assword(?:\s+for\s+\S+)?:\s*$/m;
    const failRe = /(authentication failure|incorrect password|su: (?:failed|Authentication failure|incorrect))/i;
    const readyRe = new RegExp(`${readyMark}`);
    const endRe = new RegExp(`${endMark}(\\d{1,3})(?:\\r?\\n|$)`);

    return new Promise((resolve) => {
      const args = [...this.buildArgs({ ...opts, pty: true }), 'su -'];
      let state: 'SU_PROMPT' | 'PASSWORD_SENT' | 'ROOT_SHELL' | 'EXEC' | 'DONE' = 'SU_PROMPT';
      let buffer = '';
      let stdoutTail = '';
      let capturedStdout = '';
      // Unbounded capture of all stdout received while in the EXEC state. The
      // scanning `buffer` below is truncated to ~4KB to bound regex cost, but
      // truncating the captured output would silently drop the head of any
      // command emitting more than ~8KB (inconsistent with runSsh, which
      // returns the full stream). Keep the full EXEC output here.
      let execCapture = '';
      // The exact input line written to the root shell in the EXEC state. With
      // `ssh -tt` the remote PTY echoes it back onto stdout, so it is stored
      // here to strip that single echoed line from the captured output.
      let execInput = '';
      let capturedStderr = '';
      let exitCode: number | null = null;
      let timedOut = false;
      let exited = false;
      let stateTimer: NodeJS.Timeout | null = null;

      const child: ChildProcess = spawn('ssh', args, {
        env: this.buildEnv(),
        windowsHide: true,
      });

      const setStateTimer = (ms: number, reason: string) => {
        if (stateTimer) clearTimeout(stateTimer);
        stateTimer = setTimeout(() => {
          stateTimer = null;
          capturedStderr += `\nState timeout in ${state}: ${reason}`;
          child.kill('SIGTERM');
        }, ms);
      };

      const clearStateTimer = () => {
        if (stateTimer) { clearTimeout(stateTimer); stateTimer = null; }
      };

      const writeLine = (s: string) => {
        try { child.stdin?.write(s + '\n'); } catch (e) { /* ignore */ }
      };

      // Initial state: wait up to 10s for `su` password prompt
      setStateTimer(10000, 'awaiting su password prompt');

      // Overall hard deadline. types.ts ExecOptions.timeoutMs is documented as a
      // hard ceiling every transport must enforce; runSsh applies it to the
      // whole spawn, so the su path must too. The handshake phases (su prompt,
      // password, root-shell sentinel) are bounded by their own per-state timers
      // above; they do not get an extra budget on top of the contract deadline.
      const overallTimer = setTimeout(() => {
        timedOut = true;
        clearStateTimer();
        child.kill('SIGTERM');
        // Gate the SIGKILL fallback on the real `exited` flag, not
        // `child.killed` (which is set the instant SIGTERM is *sent*, so the
        // fallback would always be skipped and a process ignoring SIGTERM
        // could hang past the deadline).
        setTimeout(() => { if (!exited) child.kill('SIGKILL'); }, 2000);
      }, opts.timeoutMs);

      child.stdout?.on('data', (chunk: Buffer) => {
        const text = chunk.toString('utf8');
        buffer += text;
        // Keep last ~4KB for regex scanning
        if (buffer.length > 8192) buffer = buffer.slice(buffer.length - 4096);
        stdoutTail = buffer;
        // Accumulate the full EXEC-state output separately from the truncated
        // scan buffer so large command output is not lost (see execCapture decl).
        if (state === 'EXEC') execCapture += text;

        // Auth-failure detection must run ONLY during the su/login phases.
        // Once the state machine reaches EXEC, the stream carries the user
        // command's own stdout, which may legitimately contain phrases like
        // "incorrect password" or "authentication failure" (e.g. grepping auth
        // logs). Matching there would kill the session and mis-report the
        // command's output as an auth error, so gate the check on the pre-EXEC
        // login states.
        const inLoginPhase =
          state === 'SU_PROMPT' || state === 'PASSWORD_SENT' || state === 'ROOT_SHELL';
        if (inLoginPhase && failRe.test(stdoutTail)) {
          clearStateTimer();
          capturedStderr += stdoutTail;
          child.kill('SIGTERM');
          return;
        }

        if (state === 'SU_PROMPT' && pwRe.test(stdoutTail)) {
          clearStateTimer();
          state = 'PASSWORD_SENT';
          writeLine(suPassword);
          setStateTimer(8000, 'awaiting root shell after password');
          return;
        }

        if (state === 'PASSWORD_SENT') {
          // Send sentinel PS1 once we see a non-prompt line (typical: post-auth motd)
          // Trigger: any newline after password sent.
          if (/\r?\n/.test(text)) {
            // Set a sentinel PS1 so the root-shell prompt is machine-detectable,
            // and clear PS2 to '' so the multiline subshell wrapper written in
            // the EXEC state (see below) does not emit `> ` continuation prompts
            // into the captured PTY stream.
            writeLine(`export PS1='${readyMark}$ '; export PS2=''`);
            state = 'ROOT_SHELL';
            setStateTimer(5000, 'awaiting sentinel prompt');
            buffer = '';
            stdoutTail = '';
            return;
          }
        }

        if (state === 'ROOT_SHELL' && readyRe.test(stdoutTail)) {
          clearStateTimer();
          state = 'EXEC';
          buffer = '';
          stdoutTail = '';
          // Run the user command inside a subshell, then echo the sentinel and
          // its exit status on the SAME input line.
          //
          //  - Subshell isolation: a command that exits or exec-replaces its
          //    shell (e.g. `echo ok; exit 0`, `exec true`) only terminates the
          //    subshell. The root control shell survives to run the sentinel, so
          //    the real exit status is reported instead of the close path
          //    mistaking a clean exit for a transport failure and dropping the
          //    output. `$?` after `( ... )` is the subshell's exit status.
          //  - Same-line sentinel: with `ssh -tt` the sentinel-emit is echoed as
          //    part of this one input line, so it can never glue onto command
          //    output that lacks a trailing newline (e.g. `printf foo`).
          execInput = `( ${command} ); echo ${endMark}$?`;
          writeLine(execInput);
          return;
        }

        if (state === 'EXEC') {
          const m = stdoutTail.match(endRe);
          if (m) {
            exitCode = parseInt(m[1], 10);
            // Derive output from the unbounded EXEC capture (not the truncated
            // scan buffer) so large command output is preserved in full. Locate
            // the end-marker within the full capture for the slice boundary.
            // endRe requires a digit after the marker, so the echoed
            // `echo <endMark>$?` (literal `$?`) never matches — only the real
            // sentinel output does.
            const em = execCapture.match(endRe);
            const endIdx = em ? em.index! : execCapture.length;
            capturedStdout = execCapture.slice(0, endIdx).replace(/\r\n/g, '\n');
            // Strip the echoed PS1-sentinel leftovers if any
            capturedStdout = capturedStdout.replace(new RegExp(`${readyMark}\\$\\s*`, 'g'), '');
            // Strip the single echoed input line the remote PTY replayed at the
            // head of the capture (present with `ssh -tt`). Because the command
            // and sentinel-emit are combined into one known `execInput` line,
            // removing exactly that line (and its trailing newline) yields the
            // command's real stdout — even when the output is unterminated.
            const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            capturedStdout = capturedStdout.replace(
              new RegExp(`^${escapeRe(execInput)}\\r?\\n?`),
              '',
            );
            state = 'DONE';
            writeLine('exit');
            writeLine('exit');
          }
        }
      });

      child.stderr?.on('data', (chunk: Buffer) => {
        capturedStderr += chunk.toString('utf8');
      });

      child.on('error', (err: Error) => {
        exited = true;
        clearStateTimer();
        clearTimeout(overallTimer);
        resolve({
          stdout: capturedStdout,
          stderr: capturedStderr + `\nspawn error: ${err.message}`,
          exitCode: null,
          category: 'transport',
        });
      });

      child.on('close', (code, signal) => {
        exited = true;
        clearStateTimer();
        clearTimeout(overallTimer);

        if (timedOut) {
          resolve({
            stdout: capturedStdout,
            stderr: capturedStderr || `PTY exec timed out after ${opts.timeoutMs}ms`,
            exitCode: null,
            signal: signal ?? undefined,
            category: 'timeout',
          });
          return;
        }

        if (state === 'DONE' && exitCode !== null) {
          resolve({
            stdout: capturedStdout,
            // A PTY merges remote stdout and stderr into the captured stdout
            // stream. Preserve that merged diagnostic text as stderr for
            // non-zero exits so resultToMcpContent can surface `ls: cannot
            // access ...` instead of only a generic exit status.
            stderr: exitCode === 0 ? '' : capturedStdout,
            exitCode,
            category: exitCode === 0 ? undefined : 'remote_exit',
          });
          return;
        }

        // Did not reach DONE — classify based on stderr content
        const category: ErrorCategory = failRe.test(stdoutTail + capturedStderr)
          ? 'auth'
          : (classifyError(code, capturedStderr) ?? 'transport');
        resolve({
          stdout: capturedStdout,
          stderr: capturedStderr || stdoutTail,
          exitCode: code ?? null,
          signal: signal ?? undefined,
          category,
        });
      });
    });
  }
}

/**
 * Build a sudo wrapper for the OpenSSH subprocess transport.
 *
 * Unlike the ssh2 wrapper, this must never embed the sudo password in the
 * command string: OpenSSH receives the remote command as a local `ssh` argv
 * element. When a password is needed, the caller supplies it through stdin for
 * `sudo -S` instead.
 */
export function buildOpenSshSudoWrapper(command: string, expectsPassword: boolean): string {
  const escaped = command.replace(/'/g, "'\\''");
  if (expectsPassword) {
    return `sudo -p "" -S sh -c '${escaped}'`;
  }
  return `sudo -n sh -c '${escaped}'`;
}

/**
 * Render the askpass helper script body that prints the password held in the
 * given environment variable, followed by a newline.
 *
 * Windows: a naive `@echo off` + `echo %VAR%` is unsafe — CMD expands `%VAR%`
 * and then re-parses the resulting line, so a password containing `& | < > ^ %`
 * breaks the echo (and thus auth). Even `setlocal EnableDelayedExpansion` +
 * `echo !VAR!` mishandles `!`. Instead, shell out to PowerShell and read the
 * variable verbatim via `$env:VAR`: the password value is fetched at runtime by
 * PowerShell and never substituted onto a command line, so no metacharacter is
 * ever re-interpreted. The env var NAME is `[A-Za-z0-9_]`-only (it is always
 * `SSH_MCP_PW_<pid>`), so embedding it in the command string is safe.
 *
 * POSIX: `printf '%s\n' "$VAR"` is already metacharacter-safe.
 */
export function renderAskpassHelper(envName: string, isWindows: boolean): string {
  if (isWindows) {
    return (
      `@echo off\r\n` +
      `powershell -NoProfile -NonInteractive -Command ` +
      `"[Console]::Out.Write($env:${envName} + [char]10)"\r\n`
    );
  }
  return `#!/bin/sh\nprintf '%s\\n' "$${envName}"\n`;
}

/**
 * Map SSH exit code + stderr to structured ErrorCategory.
 *
 *   exit 0                → undefined  (success)
 *   exit 1-254            → remote_exit (remote command's own non-zero exit)
 *   exit 255              → inspect stderr for SSH-layer failure type;
 *                           falls back to remote_exit when no SSH-layer
 *                           signature matches (ssh(1) documents 255 as either
 *                           an SSH error OR the remote command's own exit 255)
 *   exit null             → treated as transport failure
 */
export function classifyError(code: number | null, stderr: string): ErrorCategory | undefined {
  if (code === 0) return undefined;
  if (code === null) return 'transport';
  if (code !== 255) return 'remote_exit';

  const s = stderr.toLowerCase();
  if (/permission denied/.test(s)) return 'auth';
  if (/authentication failed|authentication failure/.test(s)) return 'auth';
  if (/no credentials cache|no credential/.test(s)) return 'auth';
  if (/ticket expired/.test(s)) return 'auth';
  if (/gss.*credential|gssapi.*failure|gssapi.*unspecified/.test(s)) return 'auth';
  if (/clock skew too great/.test(s)) return 'auth';
  if (/server not found in kerberos database/.test(s)) return 'auth';
  if (/host key verification failed/.test(s)) return 'host_key';
  if (/remote host identification has changed/.test(s)) return 'host_key';
  if (/connection refused/.test(s)) return 'connect';
  if (/connection timed out/.test(s)) return 'connect';
  if (/connection reset/.test(s)) return 'connect';
  if (/could not resolve|name or service not known/.test(s)) return 'connect';
  if (/no route to host|network unreachable/.test(s)) return 'connect';
  // No SSH-layer signature matched. Per ssh(1), 255 is also the exit code a
  // remote command can legitimately return, so surface it as the remote
  // command's own non-zero exit (Error (code 255)) rather than masking it as
  // a generic SSH transport error.
  return 'remote_exit';
}
