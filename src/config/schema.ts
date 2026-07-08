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
  approvalMode: approvalModeSchema.default('ask-destructive'),
});

export const profileSchema = z.object({
  name: z.string().min(1),
  host: z.string().min(1),
  port: z.number().int().min(1).max(65535).default(22),
  user: z.string().min(1),
  auth: authMethodSchema.default('agent'),
  keyRef: z.string().optional(),
  keychainEntry: z.string().optional(),
  via: z.string().optional(),
  workdir: z.string().optional(),
  trustedHostKey: z.string().optional(),
  hostFingerprint: z.string().optional(),
  tty: z.boolean().default(false),
  timeout: z.number().int().positive().default(60_000),
  maxChars: z.number().int().positive().default(5000),
  role: z.string().default('operator'),
  readOnly: z.boolean().default(false),
  approvalPolicy: approvalModeSchema.default('ask-destructive'),
  cert: z.boolean().default(false),
  caFingerprint: z.string().optional(),
  sessionMaxPerConnection: z.number().int().positive().optional(),
  sessionIdleTimeoutMs: z.number().int().positive().optional(),
});

export const configSchema = z.object({
  defaults: defaultsSchema.default({}),
  profiles: z.array(profileSchema).min(1),
});

export type RawDefaults = z.infer<typeof defaultsSchema>;
export type RawProfile = z.infer<typeof profileSchema>;
export type RawConfig = z.infer<typeof configSchema>;
