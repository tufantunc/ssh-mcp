import { describe, it, expect } from 'vitest';
import { profileSchema } from '../../../src/config/schema.js';

const base = {
  name: 'p',
  host: 'h.example',
  user: 'u',
};

describe('forwardAgent', () => {
  it('defaults to false', () => {
    const parsed = profileSchema.parse({ ...base, auth: 'agent' });
    expect(parsed.forwardAgent).toBe(false);
  });

  it('accepts forwarding when the profile authenticates with an agent', () => {
    const parsed = profileSchema.parse({ ...base, auth: 'agent', forwardAgent: true });
    expect(parsed.forwardAgent).toBe(true);
  });

  it('refuses forwarding without an agent', () => {
    const parsed = profileSchema.safeParse({ ...base, auth: 'key', forwardAgent: true });
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      expect(parsed.error.issues.some((issue) => issue.message.includes('auth = "agent"'))).toBe(true);
    }
  });
});
