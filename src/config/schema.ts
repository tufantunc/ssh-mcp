import { z } from 'zod';

const authMethodSchema = z.enum(['agent', 'key', 'password', 'keychain']);
const approvalModeSchema = z.enum(['auto', 'ask-destructive', 'ask-all', 'deny']);

export const defaultsSchema = z.object({
  defaultProfile: z.string().optional(),
  sessionMaxPerConnection: z.number().int().positive().default(5),
  sessionIdleTimeoutMs: z.number().int().positive().default(600_000),
  sessionBackgroundMaxMs: z.number().int().positive().default(3_600_000),
  commandTimeoutMs: z.number().int().positive().default(60_000),
  commandMaxChars: z.number().int().positive().default(5000),
  commandMaxOutputBytes: z.number().int().positive().default(1_048_576),
  connectionIdleReapMs: z.number().int().positive().default(900_000),
  // 0 = unlimited. A circuit breaker for runaway agents, not a rate limit.
  commandQuotaPerDay: z.number().int().nonnegative().default(0),
  // 0 = every destructive command prompts. Auto-approval weakens the gate, so
  // it is opt-in rather than a default convenience.
  approvalGrantTtlMs: z.number().int().nonnegative().default(0),
  approvalMode: approvalModeSchema.default('ask-destructive'),
}).strict();

export const profileSchema = z.object({
  name: z.string().min(1),
  host: z.string().min(1),
  port: z.number().int().min(1).max(65535).default(22),
  user: z.string().min(1),
  auth: authMethodSchema.default('agent'),
  keyRef: z.string().optional(),
  keychainEntry: z.string().optional(),
  via: z.string().optional(),
  // Drives the role-binding tier. Without it the tier is guessed from the
  // profile name, and an unrecognised name resolves to the strictest tier.
  group: z.string().optional(),
  workdir: z.string().optional(),
  trustedHostKey: z.string().optional(),
  tty: z.boolean().default(false),
  role: z.string().default('operator'),
  readOnly: z.boolean().default(false),
  cert: z.boolean().default(false),
  // Left optional on purpose: normalizeConfig() fills these from [defaults], and
  // a schema-level .default() would make "user omitted it" indistinguishable
  // from "user set the default value", silently shadowing [defaults].
  timeout: z.number().int().positive().optional(),
  maxChars: z.number().int().positive().optional(),
  maxOutputBytes: z.number().int().positive().optional(),
  approvalPolicy: approvalModeSchema.optional(),
  sessionMaxPerConnection: z.number().int().positive().optional(),
  sessionIdleTimeoutMs: z.number().int().positive().optional(),
  sessionBackgroundMaxMs: z.number().int().positive().optional(),
  commandQuotaPerDay: z.number().int().nonnegative().optional(),
}).strict();

export const configSchema = z.object({
  defaults: defaultsSchema.default({}),
  profiles: z.array(profileSchema).min(1),
});

export type RawDefaults = z.infer<typeof defaultsSchema>;
export type RawProfile = z.infer<typeof profileSchema>;
export type RawConfig = z.infer<typeof configSchema>;
