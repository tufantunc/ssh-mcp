import { z } from 'zod';

const authMethodSchema = z.enum(['agent', 'key', 'password', 'keychain']);
const approvalModeSchema = z.enum(['auto', 'ask-destructive', 'ask-all', 'deny']);
const commandClassSchema = z.enum(['read-only', 'safe', 'destructive', 'privileged']);

/**
 * Role and tier names, which are free strings so operators can define their own.
 *
 * `__proto__` is excluded because merging assigns into a plain object, and that
 * assignment lands on the prototype instead of creating a key: a role by that
 * name would be accepted and then not exist. `constructor` and `prototype` are
 * excluded alongside it rather than reasoned about case by case.
 */
const RESERVED_BINDING_KEYS = ['__proto__', 'constructor', 'prototype'];
const RESERVED_KEY_MESSAGE =
  `Reserved name (${RESERVED_BINDING_KEYS.join(', ')}). Rename the role or tier.`;

/** Only the length rule. The reserved-name rule lives in `checkReservedKeys` below. */
const bindingKeySchema = z.string().min(1);

/**
 * How deep the walk goes: role -> tier -> classes.
 *
 * The schema descends exactly two levels whatever the input looks like, but this
 * function follows the *data*, so without a bound it recurses as deep as the TOML
 * nests. `smol-toml` parses ten thousand levels happily, and the resulting
 * `RangeError` escapes `loadConfig` — `safeParse` throws rather than returning
 * `{ success: false }`, and that call sits outside the loader's try/catch — so the
 * operator got a stack trace where zod 3 printed a validation error.
 */
const MAX_BINDING_DEPTH = 2;

/**
 * The reserved-key check, run against the raw object before `z.record` sees it.
 *
 * `bindingKeySchema` alone stopped being enough at zod 4. Its record
 * implementation never hands `__proto__` to the key schema — it drops the key and
 * returns an object without it, so a config naming that role parsed *cleanly* and
 * came out empty. Measured: `Object.keys` on the parsed TOML shows `__proto__`,
 * `z.record` accepts, and the result has zero keys.
 *
 * zod 4 broke it in two separate ways, both measured. `z.record` never hands
 * `__proto__` to the key schema — it drops the key and returns an object without it.
 * And for the keys it does check, zod 4 replaces the key schema's message with its
 * own `Invalid key in record`, so neither the reserved-name text nor `min(1)`'s
 * reached the operator.
 *
 * The dropped key is not prototype pollution — zod 4 declines to write it at all,
 * which is the safe half. What was lost is the refusal, and downstream catches it
 * only when a profile uses the role: `resolvePolicyRules` throws for a role with no
 * bindings, but a binding block no profile references was dropped in silence.
 *
 * So this owns both rules outright rather than layering over the key schema. The
 * reserved-name `refine` came off `bindingKeySchema` at the same time — the pipe
 * short-circuits, so it could never run, and calling it a second layer would have
 * described something that was not there.
 *
 * `getOwnPropertyNames` and a property descriptor rather than `Object.keys` and a
 * property read. Measured, neither changes the outcome for anything this can
 * receive: `smol-toml` yields enumerable string keys, and an own `__proto__` data
 * property shadows the prototype accessor, so even a direct read returns the key.
 * They are kept because a descriptor cannot run a getter, and because whether a key
 * is enumerable is the TOML parser's decision rather than ours.
 */
function checkReservedKeys(
  value: unknown,
  ctx: z.RefinementCtx,
  prefix: (string | number)[] = [],
): void {
  if (typeof value !== 'object' || value === null) return;
  if (prefix.length >= MAX_BINDING_DEPTH) return;

  for (const key of Object.getOwnPropertyNames(value)) {
    // The path carries the ancestry, so a reserved tier names the role it sits under.
    // Reporting only the leaf pointed the operator at a top-level role that was not in
    // their file, which is the opposite of a refusal they can act on.
    const path = [...prefix, key];

    if (RESERVED_BINDING_KEYS.includes(key)) {
      ctx.addIssue({ code: 'custom', message: RESERVED_KEY_MESSAGE, path });
      // `continue` rather than `return`: a config with several bad names should hear
      // about all of them, the way the policy engine's coherence check does.
      continue;
    }
    if (key.length === 0) {
      ctx.addIssue({ code: 'custom', message: 'Role and tier names cannot be empty.', path });
      continue;
    }

    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor && typeof descriptor.value === 'object' && descriptor.value !== null) {
      checkReservedKeys(descriptor.value, ctx, path);
    }
  }
}

export const defaultsSchema = z.object({
  defaultProfile: z.string().optional(),
  sessionMaxPerConnection: z.number().int().positive().default(5),
  sessionIdleTimeoutMs: z.number().int().positive().default(600_000),
  sessionBackgroundMaxMs: z.number().int().positive().default(3_600_000),
  commandTimeoutMs: z.number().int().positive().default(60_000),
  // 0 = unlimited, matching `--maxChars=none` on the CLI. normalizeConfig()
  // maps it to Number.MAX_SAFE_INTEGER so both surfaces hand the rest of the
  // code an identical Profile.
  commandMaxChars: z.number().int().nonnegative().default(5000),
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
  // 0 = unlimited, as in [defaults].commandMaxChars above.
  maxChars: z.number().int().nonnegative().optional(),
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
  roleBindings: z.unknown()
    .superRefine(checkReservedKeys)
    .pipe(z.record(
      bindingKeySchema,
      z.record(bindingKeySchema, z.array(commandClassSchema)),
    ))
    .optional(),
  denylist: z.array(z.string()).optional(),
}).strict();

// .strict() on the root as well: without it an unknown section (a typo, or a
// key from a newer version) parses cleanly and is dropped with no warning, so
// the operator gets a clean startup and none of the behaviour they configured.
export const configSchema = z.object({
  defaults: defaultsSchema.prefault({}),
  profiles: z.array(profileSchema).min(1),
  policy: policySchema.optional(),
}).strict();

export type RawDefaults = z.infer<typeof defaultsSchema>;
export type RawProfile = z.infer<typeof profileSchema>;
export type RawPolicy = z.infer<typeof policySchema>;
export type RawConfig = z.infer<typeof configSchema>;
