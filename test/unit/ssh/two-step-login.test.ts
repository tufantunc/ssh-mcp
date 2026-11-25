import { describe, it, expect, afterEach, vi } from 'vitest';
import ssh2, { type AuthenticationType } from 'ssh2';
import { SSHConnection } from '../../../src/ssh/connection.js';
import type { Profile } from '../../../src/types.js';
import type { HostKeyMode } from '../../../src/ssh/host-key.js';
import { makeProfile } from '../../fixtures/profile.js';

// Default import, as src/ssh/sftp.ts does: Node itself does not see ssh2's named exports.
const { Server, utils } = ssh2;

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
let servers: InstanceType<typeof Server>[] = [];
let conns: SSHConnection[] = [];

// Closed here, not at the end of each test: a test that fails before its own close would
// otherwise leave a logged-in client holding server.close() until the hook times out.
afterEach(async () => {
  vi.useRealTimers();
  await Promise.all(conns.map((c) => c.close().catch(() => {})));
  await Promise.all(servers.map((s) => new Promise<void>((r) => s.close(() => r()))));
  conns = [];
  servers = [];
});

const profileFor = (port: number, over: Partial<Profile> = {}): Profile =>
  makeProfile({ name: 'bmc', host: '127.0.0.1', port, user: 'u', timeout: 2000, approvalPolicy: 'auto', ...over });

const connect = (profile: Profile, password = 'secret') => {
  const conn = new SSHConnection(profile, { password }, new Map(), 'insecure' as HostKeyMode);
  conns.push(conn);
  return conn;
};

/** Start `server` on a free port and return the port. */
async function listen(server: InstanceType<typeof Server>): Promise<number> {
  servers.push(server);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  return (server.address() as { port: number }).port;
}

interface Seen { answers?: string[] }

/**
 * Password -> partial success, then one keyboard-interactive round. With `question` set the
 * round asks a real question and refuses whatever comes back; without it the round has no
 * prompts and is accepted. With `hold` set, the reply to the password waits until `hold` is
 * called back, so a test can let time pass during the login.
 */
function twoStepServer(opts: { question?: string; seen?: Seen; hold?: (release: () => void) => void } = {}): Promise<number> {
  return listen(new Server({ hostKeys: [hostKey] }, (client) => {
    client.on('authentication', (ctx) => {
      if (ctx.method === 'password' && ctx.password === 'secret') {
        const release = () => ctx.reject(['keyboard-interactive'], true);
        if (opts.hold) opts.hold(release);
        else release();
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
  }));
}

describe('a server that demands a second authentication round', () => {
  it('refuses a profile that did not opt in, with the correct password', async () => {
    const conn = connect(profileFor(await twoStepServer()));
    await expect(conn.ensureConnected()).rejects.toThrow(/All configured authentication methods failed/);
  }, 20000);

  it("logs in with keyboardInteractive = 'empty'", async () => {
    const conn = connect(profileFor(await twoStepServer(), { keyboardInteractive: 'empty' }));
    await conn.ensureConnected();
    expect(conn.isConnected()).toBe(true);
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
  }, 20000);
});

/**
 * connectTimeoutMs feeds two timers: the connection's own and ssh2's `readyTimeout`. The login
 * is held at the password step while fake time passes, so a test can ask about a login slower
 * than the 20 s default without waiting for one. Only setTimeout is faked: the sockets are real.
 */
describe('connectTimeoutMs', () => {
  /** A login held at the password step, and the means to let it go on. */
  async function heldLogin(connectTimeoutMs: number) {
    let release!: () => void;
    const held = new Promise<void>((r) => {
      void twoStepServer({ hold: (go) => { release = go; r(); } }).then((port) => {
        vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
        login.conn = connect(profileFor(port, { keyboardInteractive: 'empty', connectTimeoutMs }));
        login.result = login.conn.ensureConnected();
        // Observed now, so an early rejection is not reported as unhandled before the test reads it.
        login.result.catch(() => {});
      });
    });
    const login = { conn: undefined as SSHConnection | undefined, result: undefined as Promise<void> | undefined, held, release: () => release() };
    await held;
    return login as { conn: SSHConnection; result: Promise<void>; release: () => void };
  }

  // Both timers have to move: either one left at 20 s cuts this login off.
  it('lets a login run past 20 s when the profile allows 90 s', async () => {
    const login = await heldLogin(90_000);
    await vi.advanceTimersByTimeAsync(25_000);
    login.release();
    await login.result;
    expect(login.conn.isConnected()).toBe(true);
  }, 20000);

  it('cuts a login off at the profile’s limit, and says which setting to raise', async () => {
    const login = await heldLogin(5_000);
    await vi.advanceTimersByTimeAsync(5_000);
    await expect(login.result).rejects.toThrow(
      /^SSH connection timeout after 5000 ms; for a host with a slow login, raise connectTimeoutMs on its profile$/,
    );
  }, 20000);
});

/**
 * A server that takes passwords through keyboard-interactive, and records every password it is
 * sent and how. By default it refuses the `password` method and lists keyboard-interactive only,
 * as VMware ESXi does with `PasswordAuthentication no`; with `passwordMethod` it lists and checks
 * that method too, as a stock OpenSSH does. Each keyboard-interactive round asks one prompt
 * (`questions` in order, the last one repeated); `rounds` lets a wrong answer be asked again.
 */
interface Recorded { method: string; password?: string; answers?: string[] }

function kbdServer(opts: {
  questions?: { prompt: string; echo?: boolean }[];
  rounds?: number;
  passwordMethod?: boolean;
  seen: Recorded[];
}): Promise<number> {
  const listed: AuthenticationType[] = opts.passwordMethod ? ['password', 'keyboard-interactive'] : ['keyboard-interactive'];
  const questions = opts.questions ?? [{ prompt: 'Password: ' }];
  return listen(new Server({ hostKeys: [hostKey] }, (client) => {
    client.on('authentication', (ctx) => {
      if (ctx.method === 'keyboard-interactive') {
        let round = 0;
        const ask = () => {
          const q = questions[Math.min(round, questions.length - 1)];
          ctx.prompt([{ prompt: q.prompt, echo: q.echo ?? false }], '', '', (answers) => {
            opts.seen.push({ method: 'keyboard-interactive', answers });
            if (answers[0] === 'secret') return ctx.accept();
            round += 1;
            if (round < (opts.rounds ?? 1)) return ask();
            ctx.reject(listed);
          });
        };
        ask();
      } else if (ctx.method === 'password') {
        opts.seen.push({ method: 'password', password: ctx.password });
        if (opts.passwordMethod && ctx.password === 'secret') return ctx.accept();
        ctx.reject(listed);
      } else {
        ctx.reject(listed);
      }
    });
    client.on('error', () => { /* the client hangs up mid-test */ });
  }));
}

/** Every password the server was sent, by either method. */
const passwordsSent = (seen: Recorded[]) =>
  seen.flatMap((r) => (r.method === 'password' ? [r.password] : (r.answers ?? []).filter((a) => a !== '')));

describe('a server that takes passwords only through keyboard-interactive (ESXi)', () => {
  it("is refused with keyboardInteractive unset or 'empty'", async () => {
    for (const mode of [undefined, 'empty'] as const) {
      const seen: Recorded[] = [];
      const conn = connect(profileFor(await kbdServer({ seen }), { keyboardInteractive: mode }));
      await expect(conn.ensureConnected()).rejects.toThrow(/All configured authentication methods failed/);
      expect(seen.flatMap((r) => r.answers ?? [])).not.toContain('secret');
    }
  }, 20000);

  // The `password` method is not listed, so it is not tried: a refused attempt would count
  // against the server's failed-login limit for nothing.
  it("logs in with keyboardInteractive = 'password', without trying the password method", async () => {
    const seen: Recorded[] = [];
    const conn = connect(profileFor(await kbdServer({ seen }), { keyboardInteractive: 'password' }));
    await conn.ensureConnected();
    expect(conn.isConnected()).toBe(true);
    expect(seen).toEqual([{ method: 'keyboard-interactive', answers: ['secret'] }]);
  }, 20000);

  it('sends a wrong password once and answers the next round with an empty string', async () => {
    const seen: Recorded[] = [];
    const conn = connect(profileFor(await kbdServer({ seen, rounds: 3 }), { keyboardInteractive: 'password' }), 'wrong');
    await expect(conn.ensureConnected()).rejects.toThrow(/All configured authentication methods failed/);
    expect(seen.map((r) => r.answers)).toEqual([['wrong'], [''], ['']]);
  }, 20000);

  it('never types the password into a prompt that is not a hidden password prompt', async () => {
    for (const q of [{ prompt: 'Verification code: ' }, { prompt: 'Password: ', echo: true }]) {
      const seen: Recorded[] = [];
      const conn = connect(profileFor(await kbdServer({ seen, questions: [q] }), { keyboardInteractive: 'password' }));
      await expect(conn.ensureConnected()).rejects.toThrow(/All configured authentication methods failed/);
      expect(seen.map((r) => r.answers)).toEqual([['']]);
    }
  }, 20000);

  // A question that is not for the password does not use the password up.
  it('answers a password prompt that comes after a question it answered with an empty string', async () => {
    const seen: Recorded[] = [];
    const conn = connect(profileFor(
      await kbdServer({ seen, rounds: 2, questions: [{ prompt: 'Verification code: ' }, { prompt: 'Password: ' }] }),
      { keyboardInteractive: 'password' },
    ));
    await conn.ensureConnected();
    expect(seen.map((r) => r.answers)).toEqual([[''], ['secret']]);
  }, 20000);
});

describe('a server that takes the password both ways (stock OpenSSH)', () => {
  // ssh2 on its own tries the `password` method and then keyboard-interactive, so a wrong
  // password would go out twice in one login, both counted as failures.
  it('sends a wrong password once in the whole login', async () => {
    const seen: Recorded[] = [];
    const conn = connect(
      profileFor(await kbdServer({ seen, passwordMethod: true }), { keyboardInteractive: 'password' }),
      'wrong',
    );
    await expect(conn.ensureConnected()).rejects.toThrow(/All configured authentication methods failed/);
    expect(passwordsSent(seen)).toEqual(['wrong']);
    expect(seen).toEqual([
      { method: 'password', password: 'wrong' },
      { method: 'keyboard-interactive', answers: [''] },
    ]);
  }, 20000);

  it('logs in by the password method when the password is right', async () => {
    const seen: Recorded[] = [];
    const conn = connect(profileFor(await kbdServer({ seen, passwordMethod: true }), { keyboardInteractive: 'password' }));
    await conn.ensureConnected();
    expect(seen).toEqual([{ method: 'password', password: 'secret' }]);
  }, 20000);
});

describe("keyboardInteractive = 'password' on the iDRAC-style server", () => {
  it('still logs in: the empty second round is answered as before', async () => {
    const conn = connect(profileFor(await twoStepServer(), { keyboardInteractive: 'password' }));
    await conn.ensureConnected();
    expect(conn.isConnected()).toBe(true);
  }, 20000);
});
