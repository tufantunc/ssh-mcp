import { z } from 'zod';

const authMethodSchema = z.enum(['agent', 'key', 'password', 'keychain']);
const approvalModeSchema = z.enum(['auto', 'ask-destructive', 'ask-all', 'deny']);
const commandClassSchema = z.enum(['read-only', 'safe', 'destructive', 'privileged']);

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

/**
 * Overrides merged over the compiled-in DEFAULT_RULES at startup.
 *
 * `roleBindings` is keyed role → host group → command classes, and the group
 * key is a free string on purpose: a config that defines its own tier makes
 * `group = "tier-1"` on a profile resolve to that tier instead of falling back
 * to the strictest one.
 *
 * Command classes are validated against the enum rather than accepted as free
 * strings, so `priviledged` fails at load instead of parsing to a grant of
 * nothing, which reads at runtime exactly like a policy decision.
 *
 * `allowlist` is deliberately absent: PolicyRules declares the field but no
 * code reads it, so accepting it here would document a key that does nothing.
 */
export const policySchema = z.object({
  roleBindings: z.record(z.string(), z.record(z.string(), z.array(commandClassSchema))).optional(),
  denylist: z.array(z.string()).optional(),
}).strict();

// .strict() on the root as well: without it an unknown section (a typo, or a
// key from a newer version) parses cleanly and is dropped with no warning, so
// the operator gets a clean startup and none of the behaviour they configured.
export const configSchema = z.object({
  defaults: defaultsSchema.default({}),
  profiles: z.array(profileSchema).min(1),
  policy: policySchema.optional(),
}).strict();

export type RawDefaults = z.infer<typeof defaultsSchema>;
export type RawProfile = z.infer<typeof profileSchema>;
export type RawPolicy = z.infer<typeof policySchema>;
export type RawConfig = z.infer<typeof configSchema>;
