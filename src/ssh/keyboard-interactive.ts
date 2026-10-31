import type { KeyboardInteractiveMode } from '../types.js';

/** One prompt of a keyboard-interactive round, as ssh2 hands it over. */
export interface KeyboardInteractivePrompt {
  prompt: string;
  echo?: boolean;
}

/** What a prompt must look like to be answered with the password: asks for one, by name. */
const PASSWORD_PROMPT = /password/i;

/**
 * The answers to one keyboard-interactive round. See Profile.keyboardInteractive.
 *
 * Only in `password` mode, only for a round of exactly one prompt that does not echo and asks for
 * a password, and only when a password is passed in, is the password returned. Every other prompt
 * gets `''`: the login then fails at once instead of waiting for a person, and the password is
 * never typed into a question it was not meant for (a one-time code, a username, a second factor).
 * The caller passes `undefined` once the password has gone out, so a refused one is not retried.
 */
export function keyboardInteractiveAnswers(
  mode: KeyboardInteractiveMode,
  prompts: readonly KeyboardInteractivePrompt[],
  password: string | undefined,
): string[] {
  if (
    mode === 'password' &&
    password !== undefined &&
    prompts.length === 1 &&
    prompts[0].echo !== true &&
    PASSWORD_PROMPT.test(prompts[0].prompt)
  ) {
    return [password];
  }
  return prompts.map(() => '');
}
