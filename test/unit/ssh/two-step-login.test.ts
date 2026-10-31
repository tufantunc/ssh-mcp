import { describe, it, expect, afterEach } from 'vitest';
import { Server, utils } from 'ssh2';
import { SSHConnection } from '../../../src/ssh/connection.js';
import type { Profile } from '../../../src/types.js';
import type { HostKeyMode } from '../../../src/ssh/host-key.js';

/**
 * Logging in to a server that wants a second authentication round.
 *
 * A Dell iDRAC7/8 accepts the password with *partial success* (PuTTY prints "Further
 * authentication required") and then runs one more, empty, keyboard-interactive round.
 * ssh2 only offers keyboard-interactive when asked, so without `keyboardInteractive` the
 * login ends in "All configured authentication methods failed" although the password is right.
 * That BMC is also slow to log in (10-40 s measured), which the fixed 20 s limit could not
 * cover.
 *
 * The servers below are in-process ssh2 servers that behave the same way, so the test needs
 * neither a BMC nor Docker.
 */

const hostKey = utils.generateKeyPairSync('ed25519').private;
let server: Server | undefined;

afterEach(async () => {
  if (server) await new Promise<void>((r) => server!.close(() => r()));
  server = undefined;
});

const profileFor = (port: number, over: Partial<Profile> = {}): Profile => ({
  name: 'bmc',
  host: '127.0.0.1',
  port,
  user: 'u',
  auth: 'password',
  tty: false,
  timeout: 2000,
  maxChars: 5000,
  maxOutputBytes: 1_048_576,
  role: 'admin',
  readOnly: false,
  announceAgent: true,
  approvalPolicy: 'auto',
  cert: false,
  sessionMaxPerConnection: 5,
  sessionIdleTimeoutMs: 60_000,
  sessionBackgroundMaxMs: 3_600_000,
  commandQuotaPerDay: 0,
  outputTruncation: 'head',
  transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
  ...over,
});

interface Seen { answers?: string[] }

/**
 * Password -> partial success (after `passwordDelayMs`), then one keyboard-interactive round.
 * With `question` set the round asks a real question and refuses whatever comes back; without
 * it the round has no prompts and is accepted.
 */
async function twoStepServer(opts: { passwordDelayMs?: number; question?: string; seen?: Seen } = {}): Promise<number> {
  server = new Server({ hostKeys: [hostKey] }, (client) => {
    client.on('authentication', (ctx) => {
      if (ctx.method === 'password' && ctx.password === 'secret') {
        setTimeout(() => ctx.reject(['keyboard-interactive'], true), opts.passwordDelayMs ?? 0);
      } else if (ctx.method === 'keyboard-interactive') {
        if (opts.question) {
          ctx.prompt([{ prompt: opts.question, echo: false }], '', '', (answers) => {
            if (opts.seen) opts.seen.answers = answers;
            ctx.reject();
          });
        } else {
          ctx.prompt([], '', '', () => ctx.accept());
        }
      } else {
        ctx.reject(['password']);
      }
    });
    client.on('error', () => { /* the client hangs up mid-test */ });
  });
  await new Promise<void>((r) => server!.listen(0, '127.0.0.1', () => r()));
  return (server!.address() as { port: number }).port;
}

const connect = (profile: Profile, password = 'secret') =>
  new SSHConnection(profile, { password }, new Map(), 'insecure' as HostKeyMode);

describe('a server that demands a second authentication round', () => {
  it('refuses a profile that did not opt in, with the correct password', async () => {
    const conn = connect(profileFor(await twoStepServer()));
    await expect(conn.ensureConnected()).rejects.toThrow(/All configured authentication methods failed/);
    await conn.close().catch(() => {});
  }, 20000);

  it("logs in with keyboardInteractive = 'empty'", async () => {
    const conn = connect(profileFor(await twoStepServer(), { keyboardInteractive: 'empty' }));
    await conn.ensureConnected();
    expect(conn.isConnected()).toBe(true);
    await conn.close().catch(() => {});
  }, 20000);

  // The property that keeps the option safe to offer: a real question is not an invitation to
  // type the stored password again, and it must not leave the login waiting for a person.
  it('answers a real question with an empty string, never the stored password', async () => {
    const seen: Seen = {};
    const conn = connect(
      profileFor(await twoStepServer({ question: 'Verification code: ', seen }), { keyboardInteractive: 'empty' }),
    );
    await expect(conn.ensureConnected()).rejects.toThrow(/All configured authentication methods failed/);
    expect(seen.answers).toEqual(['']);
    await conn.close().catch(() => {});
  }, 20000);
});

describe('connectTimeoutMs', () => {
  it('bounds a slow login, and a larger value lets the same login through', async () => {
    const port = await twoStepServer({ passwordDelayMs: 700 });

    const tight = connect(profileFor(port, { keyboardInteractive: 'empty', connectTimeoutMs: 200 }));
    await expect(tight.ensureConnected()).rejects.toThrow(/timeout|timed out/i);
    await tight.close().catch(() => {});

    const roomy = connect(profileFor(port, { keyboardInteractive: 'empty', connectTimeoutMs: 8000 }));
    await roomy.ensureConnected();
    expect(roomy.isConnected()).toBe(true);
    await roomy.close().catch(() => {});
  }, 20000);
});

/**
 * A server that takes passwords only through keyboard-interactive, as VMware ESXi does with
 * `PasswordAuthentication no` in sshd_config: the `password` method is refused, and the
 * keyboard-interactive round asks one hidden `Password: ` prompt. Every answer is recorded.
 * With `question` set it asks that instead; `rounds` lets a wrong password be asked again.
 */
async function kbdOnlyServer(opts: { question?: string; echo?: boolean; rounds?: number; seen: string[][] }): Promise<number> {
  server = new Server({ hostKeys: [hostKey] }, (client) => {
    let roundsLeft = opts.rounds ?? 1;
    client.on('authentication', (ctx) => {
      if (ctx.method === 'keyboard-interactive') {
        const ask = () => ctx.prompt([{ prompt: opts.question ?? 'Password: ', echo: opts.echo ?? false }], '', '', (answers) => {
          opts.seen.push(answers);
          if (answers[0] === 'secret') return ctx.accept();
          roundsLeft -= 1;
          if (roundsLeft > 0) return ask();
          ctx.reject(['keyboard-interactive']);
        });
        ask();
      } else {
        ctx.reject(['keyboard-interactive']);
      }
    });
    client.on('error', () => { /* the client hangs up mid-test */ });
  });
  await new Promise<void>((r) => server!.listen(0, '127.0.0.1', () => r()));
  return (server!.address() as { port: number }).port;
}

describe('a server that takes passwords only through keyboard-interactive (ESXi)', () => {
  it("is refused with keyboardInteractive unset or 'empty'", async () => {
    for (const mode of [undefined, 'empty'] as const) {
      const seen: string[][] = [];
      const conn = connect(profileFor(await kbdOnlyServer({ seen }), { keyboardInteractive: mode }));
      await expect(conn.ensureConnected()).rejects.toThrow(/All configured authentication methods failed/);
      expect(seen.flat()).not.toContain('secret');
      await conn.close().catch(() => {});
      await new Promise<void>((r) => server!.close(() => r()));
      server = undefined;
    }
  }, 20000);

  it("logs in with keyboardInteractive = 'password'", async () => {
    const seen: string[][] = [];
    const conn = connect(profileFor(await kbdOnlyServer({ seen }), { keyboardInteractive: 'password' }));
    await conn.ensureConnected();
    expect(conn.isConnected()).toBe(true);
    expect(seen).toEqual([['secret']]);
    await conn.close().catch(() => {});
  }, 20000);

  it('sends a wrong password once and answers the next round with an empty string', async () => {
    const seen: string[][] = [];
    const conn = connect(profileFor(await kbdOnlyServer({ seen, rounds: 3 }), { keyboardInteractive: 'password' }), 'wrong');
    await expect(conn.ensureConnected()).rejects.toThrow(/All configured authentication methods failed/);
    expect(seen).toEqual([['wrong'], [''], ['']]);
    await conn.close().catch(() => {});
  }, 20000);

  it('never types the password into a prompt that is not a hidden password prompt', async () => {
    for (const ask of [{ question: 'Verification code: ' }, { question: 'Password: ', echo: true }]) {
      const seen: string[][] = [];
      const conn = connect(profileFor(await kbdOnlyServer({ seen, ...ask }), { keyboardInteractive: 'password' }));
      await expect(conn.ensureConnected()).rejects.toThrow(/All configured authentication methods failed/);
      expect(seen).toEqual([['']]);
      await conn.close().catch(() => {});
      await new Promise<void>((r) => server!.close(() => r()));
      server = undefined;
    }
  }, 20000);
});

describe("keyboardInteractive = 'password' on the iDRAC-style server", () => {
  it('still logs in: the empty second round is answered as before', async () => {
    const conn = connect(profileFor(await twoStepServer(), { keyboardInteractive: 'password' }));
    await conn.ensureConnected();
    expect(conn.isConnected()).toBe(true);
    await conn.close().catch(() => {});
  }, 20000);
});
