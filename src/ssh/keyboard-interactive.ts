import type { AuthenticationType, Prompt } from 'ssh2';
import type { KeyboardInteractiveMode } from '../types.js';

/** What a prompt must look like to be answered with the password: asks for one, by name. */
const PASSWORD_PROMPT = /password/i;

/**
 * ssh2's own method order (lib/client.js builds `authsAllowed` in this order and its default
 * handler walks it). `hostbased` is left out: no profile configures it. A method the connection
 * has no credential for is skipped by ssh2 itself.
 */
const METHOD_ORDER: readonly AuthenticationType[] = ['none', 'password', 'publickey', 'agent', 'keyboard-interactive'];

/** One login's worth of keyboard-interactive handling. See Profile.keyboardInteractive. */
export interface KeyboardInteractiveLogin {
  /**
   * ssh2's `authHandler`: the next method to try, or `false` when none is left. `methodsLeft` is
   * what the server said can continue, `null` before the first attempt.
   */
  nextMethod(methodsLeft: readonly string[] | null): AuthenticationType | false;
  /** The answers to one keyboard-interactive round. */
  answer(prompts: readonly Prompt[]): string[];
}

/**
 * The keyboard-interactive half of one login, or `undefined` when the mode is `off`. Make a new
 * one per connection attempt: it remembers whether the password has gone out.
 *
 * The password goes out at most once per login, by whichever method reaches it first. ssh2's
 * default handler tries the `password` method before keyboard-interactive whatever the server
 * offers, so on a server that takes both, a wrong password would go out twice, and on one that
 * does not offer the method at all (ESXi with `PasswordAuthentication no`), a refused attempt
 * would be spent before the prompt. Here the `password` method is tried only when the server
 * lists it, and once it has been tried, no prompt gets the password. Each connection attempt is
 * its own login.
 *
 * Only in `password` mode, only for a round of exactly one prompt that does not echo and asks for
 * a password, is the password typed in. Every other prompt gets `''`: the login then fails at once
 * instead of waiting for a person, and the password never reaches a question it was not meant for
 * (a one-time code, a username, a second factor).
 */
export function keyboardInteractiveLogin(
  mode: KeyboardInteractiveMode | undefined,
  password: string | undefined,
): KeyboardInteractiveLogin | undefined {
  if (mode === undefined || mode === 'off') return undefined;
  let passwordSent = false;
  let next = 0;
  return {
    nextMethod(methodsLeft) {
      while (next < METHOD_ORDER.length) {
        const method = METHOD_ORDER[next++];
        if (method === 'password') {
          if (password === undefined) continue;
          if (methodsLeft !== null && !methodsLeft.includes('password')) continue;
          passwordSent = true;
        }
        return method;
      }
      return false;
    },
    answer(prompts) {
      if (
        mode === 'password' &&
        password !== undefined &&
        !passwordSent &&
        prompts.length === 1 &&
        prompts[0].echo !== true &&
        PASSWORD_PROMPT.test(prompts[0].prompt)
      ) {
        passwordSent = true;
        return [password];
      }
      return prompts.map(() => '');
    },
  };
}
