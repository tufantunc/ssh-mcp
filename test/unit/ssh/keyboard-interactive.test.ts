import { describe, it, expect } from 'vitest';
import { keyboardInteractiveAnswers } from '../../../src/ssh/keyboard-interactive.js';

const hidden = (prompt: string) => ({ prompt, echo: false });

describe('keyboardInteractiveAnswers', () => {
  it('answers one hidden password prompt with the password in password mode', () => {
    expect(keyboardInteractiveAnswers('password', [hidden('Password: ')], 's')).toEqual(['s']);
    expect(keyboardInteractiveAnswers('password', [hidden("root@esx's PASSWORD:")], 's')).toEqual(['s']);
  });

  it('answers a round with no prompts with no answers', () => {
    expect(keyboardInteractiveAnswers('password', [], 's')).toEqual([]);
    expect(keyboardInteractiveAnswers('empty', [], 's')).toEqual([]);
  });

  it('never returns the password in empty mode', () => {
    expect(keyboardInteractiveAnswers('empty', [hidden('Password: ')], 's')).toEqual(['']);
  });

  it('answers everything else with empty strings', () => {
    expect(keyboardInteractiveAnswers('password', [hidden('Verification code: ')], 's')).toEqual(['']);
    expect(keyboardInteractiveAnswers('password', [{ prompt: 'Password: ', echo: true }], 's')).toEqual(['']);
    expect(keyboardInteractiveAnswers('password', [hidden('Password: '), hidden('OTP: ')], 's')).toEqual(['', '']);
  });

  it('answers with an empty string once the caller has no password to give', () => {
    expect(keyboardInteractiveAnswers('password', [hidden('Password: ')], undefined)).toEqual(['']);
  });
});
