import { describe, it, expect } from 'vitest';
import { keyboardInteractiveLogin } from '../../../src/ssh/keyboard-interactive.js';

const hidden = (prompt: string) => ({ prompt, echo: false });

/** A login in `mode`, with password `s`, or with none when `password` is `null`. */
const login = (mode: 'empty' | 'password', password: string | null = 's') => {
  const l = keyboardInteractiveLogin(mode, password ?? undefined);
  if (!l) throw new Error(`expected a login for ${mode}`);
  return l;
};

/** Every method the login offers, in order, as ssh2 would ask for them with `methodsLeft`. */
const methods = (l: ReturnType<typeof login>, methodsLeft: readonly string[] | null) => {
  const out: string[] = [];
  for (let m = l.nextMethod(null); m !== false; m = l.nextMethod(methodsLeft)) out.push(m);
  return out;
};

describe('keyboardInteractiveLogin', () => {
  it("is nothing at all when the mode is 'off' or unset", () => {
    expect(keyboardInteractiveLogin('off', 's')).toBeUndefined();
    expect(keyboardInteractiveLogin(undefined, 's')).toBeUndefined();
  });

  describe('answering a round', () => {
    it('answers one hidden password prompt with the password in password mode', () => {
      expect(login('password').answer([hidden('Password: ')])).toEqual(['s']);
      expect(login('password').answer([hidden("root@esx's PASSWORD:")])).toEqual(['s']);
    });

    it('never answers with the password in empty mode', () => {
      expect(login('empty').answer([hidden('Password: ')])).toEqual(['']);
    });

    it('answers everything else with empty strings', () => {
      expect(login('password').answer([hidden('Verification code: ')])).toEqual(['']);
      expect(login('password').answer([{ prompt: 'Password: ', echo: true }])).toEqual(['']);
      expect(login('password').answer([hidden('Password: '), hidden('OTP: ')])).toEqual(['', '']);
      expect(login('password', null).answer([hidden('Password: ')])).toEqual(['']);
    });

    it('types the password in once, however many password rounds follow', () => {
      const l = login('password');
      expect(l.answer([hidden('Password: ')])).toEqual(['s']);
      expect(l.answer([hidden('Password: ')])).toEqual(['']);
      expect(l.answer([hidden('Password: ')])).toEqual(['']);
    });

    // A question that is not a password prompt does not use up the password: the prompt after
    // it still gets it.
    it('still answers a password prompt that follows a question it answered with an empty string', () => {
      const l = login('password');
      expect(l.answer([hidden('Verification code: ')])).toEqual(['']);
      expect(l.answer([hidden('Password: ')])).toEqual(['s']);
    });
  });

  describe('choosing the next method', () => {
    it("keeps ssh2's order when the server lists the password method", () => {
      expect(methods(login('password'), ['password', 'keyboard-interactive']))
        .toEqual(['none', 'password', 'publickey', 'agent', 'keyboard-interactive']);
    });

    // ESXi with `PasswordAuthentication no` lists keyboard-interactive only. A `password`
    // attempt there is refused, and counts against the server's failed-login limit.
    it('skips the password method when the server does not list it', () => {
      expect(methods(login('password'), ['publickey', 'keyboard-interactive']))
        .toEqual(['none', 'publickey', 'agent', 'keyboard-interactive']);
    });

    it('skips the password method when there is no password to send', () => {
      expect(methods(login('password', null), ['password', 'keyboard-interactive']))
        .toEqual(['none', 'publickey', 'agent', 'keyboard-interactive']);
    });

    // The property that keeps a wrong password from going out twice in one login, on a server
    // that takes both methods.
    it('gives no prompt the password once the password method has sent it', () => {
      const l = login('password');
      l.nextMethod(null);
      expect(l.nextMethod(['password', 'keyboard-interactive'])).toBe('password');
      expect(l.answer([hidden('Password: ')])).toEqual(['']);
    });

    it('starts over for each login', () => {
      const first = login('password');
      expect(first.answer([hidden('Password: ')])).toEqual(['s']);
      expect(login('password').answer([hidden('Password: ')])).toEqual(['s']);
    });
  });
});
