import { isDeepStrictEqual } from 'node:util';
import { ConfigParseError, ConfigSchemaError, OperatorError, errorName } from '../errors.js';
import { PolicyEngine, resolvePolicyRules, type CompiledRules, type PolicyRules } from '../policy/engine.js';
import { RELEASE, sessionKind, sessionReleaseCommand } from '../audit/session-release.js';
import { loadConfigWithDigest } from './loader.js';
import type { ConfigSource, LoadedConfig } from './loaded.js';
import type { CloseReason, ProfileChange, ProfileDiff } from './reload-diff.js';
import type { AclOptions } from './windows-acl.js';
import type { AuditStore } from '../audit/store.js';
import type { ApplyResult, ConnectionRegistry } from '../ssh/connection-registry.js';
import type { AppConfig } from '../types.js';

export interface ReloadDeps {
  /** The ACL options startup checked the file with, from argv once in main(); never reloaded. */
  aclOptions: AclOptions;
  registry: ConnectionRegistry;
  policy: PolicyEngine;
  audit: AuditStore;
  /** The object the transfer tools read; only none → some is written through it. */
  localPath: { transferRoot?: string };
  startup: LoadedConfig;
}

export interface ReloadStatus {
  path: string;
  source: ConfigSource;
  /** When the live config was loaded: at startup, or by the last applied reload. */
  loadedAt: string;
  /** Of the bytes the live config was parsed from; null while no file has been. */
  sha256: string | null;
  last: ReloadOutcome | null;
}

export interface ClosedConnection {
  profile: string;
  reason: CloseReason;
  /** Session names, collected before the close. */
  sessions: string[];
  /** Set when the close failed: the error class and code only. */
  error?: string;
}

export interface ReloadOutcome {
  ok: boolean;
  at: string;
  trigger: 'tool' | 'sighup';
  /** On refusal. Built from safe parts only: never a value or a snippet from the file. */
  error?: { name: string; message: string };
  /**
   * Set when the failure came after the swap began, so the server may run part old, part
   * new config. A refusal (validation failed) leaves it unset: nothing was changed.
   */
  partial?: boolean;
  diff?: ProfileDiff;
  policyChanged?: boolean;
  closed?: ClosedConnection[];
  /** Profiles with an open connection, kept open, whose session-fixed fields changed. */
  sessionFieldsChanged?: ProfileChange[];
  grantsInvalidated?: boolean;
  /** Of the bytes that were parsed and applied. */
  sha256?: string;
  /** When the new config went live. */
  loadedAt?: string;
}

/** A refusal by a reload-only rule. Its message names fields and the path, never values. */
export class ReloadRefusedError extends OperatorError {
  constructor(message: string) {
    super(message);
    this.name = 'ReloadRefusedError';
  }
}

/**
 * A failure whose own message may quote the file, carried with one that does not. The
 * name stays the original error's class.
 */
class Redacted extends Error {
  constructor(readonly reported: { name: string; message: string }) {
    super(reported.message);
  }
}

interface Validated {
  next: AppConfig;
  compiled: CompiledRules;
  sha256: string;
  /** Against the rules the engine runs on now, so a partial failure leaves no stale baseline. */
  policyChanged: boolean;
}

type CloseEntry = ApplyResult['toClose'][number];

const FLAGS_REFUSAL = 'started from command-line flags; restart to use a config file';

const CLOSE_REASONS: Record<CloseReason, string> = {
  removed: 'profile removed',
  'connection-field': 'connection field changed',
  'bastion-closed': 'its bastion closed',
};

/**
 * Reloads config.toml into the running server: validate exactly as startup does, into
 * fresh objects; swap in one synchronous step; then close what has to close, audit, and
 * report. A refused reload changes nothing, including the registry's generation, so it
 * does not invalidate approval grants either.
 */
export class ConfigReloader {
  private readonly deps: ReloadDeps;
  private source: ConfigSource;
  private readonly path: string;
  private loadedAt: string;
  private sha256: string | null;
  private last: ReloadOutcome | null = null;
  /** The previous reload. Each call chains on it, so two never interleave. */
  private queue: Promise<unknown> = Promise.resolve();
  /** A reload queued behind the running one and not yet started; later calls join it. */
  private waiting: Promise<ReloadOutcome> | null = null;

  constructor(deps: ReloadDeps) {
    this.deps = deps;
    this.source = deps.startup.source;
    this.path = deps.startup.path;
    this.loadedAt = deps.startup.loadedAt;
    this.sha256 = deps.startup.sha256;
  }

  status(): ReloadStatus {
    return {
      path: this.path,
      source: this.source,
      loadedAt: this.loadedAt,
      sha256: this.sha256,
      last: this.last,
    };
  }

  /**
   * Reloads run one at a time. A call made while one is waiting to start joins that one
   * and gets its outcome (reported and audited under the trigger and request id of the
   * call that queued it), so a client calling in a loop, or a burst of SIGHUPs, costs at
   * most the reload running now and one more. A reload already running is never joined:
   * it may have read the file before the change the caller is asking to apply.
   */
  reload(trigger: 'tool' | 'sighup', requestId: string | number): Promise<ReloadOutcome> {
    if (this.waiting) return this.waiting;
    const run = this.queue.then(() => {
      this.waiting = null;
      return this.run(trigger, requestId);
    });
    this.waiting = run;
    // A defect that rejects one reload must not wedge every later one.
    this.queue = run.catch(() => {});
    return run;
  }

  /** The one human-readable summary: the tool's text and the stderr line. */
  formatOutcome(o: ReloadOutcome): string {
    if (!o.ok) {
      const error = o.error ?? { name: 'Error', message: 'unknown failure' };
      if (o.partial) {
        return (
          `Config reload (${o.trigger}) failed after the swap began: ${error.name}: ${error.message}\n` +
          'Check reload-config status, and restart the server if it does not show the new config.'
        );
      }
      return `Config reload (${o.trigger}) refused: ${error.name}: ${error.message}\nNothing was changed.`;
    }

    /** "name (field, field), name (field)": a profile change by name and field names only. */
    const describeChanges = (cs: ProfileChange[]) => cs.map((c) => `${c.name} (${c.fields.join(', ')})`).join(', ');

    const lines = [`Config reloaded from ${this.path} (${o.trigger}); sha256 ${o.sha256}, loaded at ${o.loadedAt}.`];
    const diff = o.diff;
    if (diff && (diff.added.length || diff.removed.length || diff.changed.length)) {
      const parts: string[] = [];
      if (diff.added.length) parts.push(`added ${diff.added.join(', ')}`);
      if (diff.removed.length) parts.push(`removed ${diff.removed.join(', ')}`);
      if (diff.changed.length) {
        parts.push(`changed ${describeChanges(diff.changed)}`);
      }
      lines.push(`Profiles: ${parts.join('; ')}.`);
    } else {
      lines.push('Profiles: unchanged.');
    }
    lines.push(`Policy rules: ${o.policyChanged ? 'changed' : 'unchanged'}.`);
    for (const c of o.closed ?? []) {
      const sessions = c.sessions.length ? `sessions closed: ${c.sessions.join(', ')}` : 'no sessions';
      const failed = c.error ? `; close failed: ${c.error}` : '';
      lines.push(`Closed connection ${c.profile} (${CLOSE_REASONS[c.reason]}), ${sessions}${failed}.`);
    }
    if (o.sessionFieldsChanged?.length) {
      lines.push(
        `Kept open; the new values apply to new sessions and commands: ${describeChanges(o.sessionFieldsChanged)}.`,
      );
    }
    if (o.grantsInvalidated) lines.push('Approval grants: cleared; the next approval grants anew.');
    return lines.join('\n');
  }

  private async run(trigger: 'tool' | 'sighup', requestId: string | number): Promise<ReloadOutcome> {
    const startedAt = Date.now();
    const at = new Date(startedAt).toISOString();

    let validated: Validated;
    try {
      validated = await this.validate();
    } catch (err) {
      return this.finish({ ok: false, at, trigger, error: this.safeError(err) }, requestId, startedAt);
    }
    const { next, compiled, sha256, policyChanged } = validated;

    // Validation passed, so from here on a throw is a defect, and it may leave the server
    // part old, part new. It is still audited and reported like any other attempt, and
    // the call resolves with that outcome rather than rejecting: a SIGHUP handler or a
    // tool reports it the same way, and nothing has to remember to catch.
    try {
      // The swap: one synchronous block, no await, so no tool call observes a mix. The
      // rules were compiled while validating, so installing them cannot throw.
      const { registry, policy, localPath } = this.deps;
      policy.replaceRules(compiled);
      const applied = registry.applyConfig(next);
      if (localPath.transferRoot === undefined && next.defaults.transferRoot !== undefined) {
        localPath.transferRoot = next.defaults.transferRoot;
      }
      const loadedAt = new Date().toISOString();
      this.source = 'file';
      this.loadedAt = loadedAt;
      this.sha256 = sha256;

      const closed = await this.closeAll(applied.toClose, requestId);
      return await this.finish(
        {
          ok: true,
          at,
          trigger,
          diff: applied.diff,
          policyChanged,
          closed,
          sessionFieldsChanged: applied.sessionFieldsChanged,
          // applyConfig bumped the generation, which is what invalidates every grant.
          grantsInvalidated: true,
          sha256,
          loadedAt,
        },
        requestId,
        startedAt,
      );
    } catch (err) {
      const error = {
        name: errorName(err),
        message:
          `Reload of ${this.path} failed after the swap began, so it may be partially applied.`,
      };
      return this.finish({ ok: false, at, trigger, error, partial: true }, requestId, startedAt);
    }
  }

  /** Startup's pipeline plus the reload-only rules, into fresh objects. Mutates nothing. */
  private async validate(): Promise<Validated> {
    if (this.source === 'flags') throw new ReloadRefusedError(FLAGS_REFUSAL);

    // The hash is of the very bytes the loader parsed, not of a second read.
    const { config: next, sha256 } = await loadConfigWithDigest(this.path, this.deps.aclOptions);

    let rules: PolicyRules;
    try {
      rules = resolvePolicyRules(next.profiles, next.policy);
    } catch (err) {
      // The problems quote role and group names from the file.
      throw new Redacted({
        name: errorName(err),
        message:
          `Policy configuration error in ${this.path}: the profiles' role/group and ` +
          '[policy.roleBindings] do not agree. The details quote values from the file, ' +
          'so they are not repeated here; startup prints them in full.',
      });
    }
    let compiled: CompiledRules;
    try {
      compiled = PolicyEngine.compile(rules);
    } catch (err) {
      // The engine's message quotes the pattern.
      throw new Redacted({
        name: errorName(err),
        message: `Invalid denylist pattern in ${this.path}: policy.denylist has an entry that is not a valid regular expression.`,
      });
    }

    const before = this.deps.localPath.transferRoot;
    const after = next.defaults.transferRoot;
    if (before !== undefined && after !== before) {
      throw new ReloadRefusedError(
        after === undefined
          ? 'defaults.transferRoot was removed; that needs a restart, since a transfer in flight holds the old root.'
          : 'defaults.transferRoot changed; that needs a restart, since a transfer in flight holds the old root.',
      );
    }

    return { next, compiled, sha256, policyChanged: !isDeepStrictEqual(this.deps.policy.rules, rules) };
  }

  /**
   * The outcome's error, built from safe parts: the error class, the config path, and for
   * a schema error the issue paths and codes. The parser quotes source text, a schema
   * message can name what it received, and the policy messages quote patterns and role
   * names, so none of those messages is used.
   */
  private safeError(err: unknown): { name: string; message: string } {
    if (err instanceof Redacted) return err.reported;
    if (err instanceof ConfigParseError) {
      const where = err.line !== undefined ? ` (line ${err.line}, column ${err.column ?? '?'})` : '';
      return { name: err.name, message: `Failed to parse TOML config at ${this.path}${where}.` };
    }
    if (err instanceof ConfigSchemaError) {
      const issues = err.issues.map((i) => `${maskedIssuePath(i.path)} (${i.code})`).join(', ');
      return { name: err.name, message: `Config validation error in ${this.path}: ${issues}.` };
    }
    // What is left from the loader is our own refusals, a missing or unreadable file, and
    // the permission check: built from the path, the file mode and the accounts on an
    // ACL, never from the file's contents.
    if (err instanceof OperatorError) return { name: err.name, message: err.message };
    return { name: errorName(err), message: `Unexpected failure while reloading ${this.path}.` };
  }

  /**
   * Close dependents first, so a bastion link never dies under its dependents' sessions.
   * A failed close is reported, not rolled back: the new config is already in effect.
   */
  private async closeAll(toClose: CloseEntry[], requestId: string | number): Promise<ClosedConnection[]> {
    const sessions = new Map(toClose.map((e) => [e, sessionsOf(e.conn)]));
    const results = new Map<CloseEntry, ClosedConnection>();

    for (const wave of dependentsFirst(toClose)) {
      await Promise.all(
        wave.map(async (entry) => {
          const startedAt = Date.now();
          let error: string | undefined;
          try {
            await entry.conn.close();
          } catch (err) {
            error = describeCloseError(err);
          }
          const names = sessions.get(entry) ?? [];
          results.set(entry, {
            profile: entry.profile,
            reason: entry.reason,
            sessions: names.map((s) => s.name),
            ...(error ? { error } : {}),
          });
          for (const s of names) {
            await this.audit({
              mcpRequestId: requestId,
              profile: entry.profile,
              user: entry.conn.profile.user,
              command: sessionReleaseCommand(s.kind, s.name, { reload: true }),
              commandClass: RELEASE.commandClass,
              binary: RELEASE.binary,
              decision: RELEASE.decision,
              ruleId: RELEASE.ruleId,
              exitCode: error ? 1 : 0,
              durationMs: Date.now() - startedAt,
              error,
            });
          }
        }),
      );
    }
    return toClose.map((e) => results.get(e) as ClosedConnection);
  }

  private async finish(
    outcome: ReloadOutcome,
    requestId: string | number,
    startedAt: number,
  ): Promise<ReloadOutcome> {
    this.last = outcome;
    // The second synthetic record after session:close; a proper non-command
    // AuditRecord variant is the queued fix for both. Three cases: applied (allow),
    // refused with nothing changed (deny), and failed after the swap began, so possibly
    // part applied (deny, with its own rule id so the log tells it from a refusal).
    await this.audit({
      mcpRequestId: requestId,
      profile: '-',
      user: '-',
      command: 'config:reload',
      commandClass: 'safe',
      binary: 'config:reload',
      decision: outcome.ok ? 'allow' : 'deny',
      ruleId: outcome.partial ? 'config-reload-partial' : 'config-reload',
      durationMs: Date.now() - startedAt,
      error: outcome.error ? `${outcome.error.name}: ${outcome.error.message}` : undefined,
    });
    console.error(this.formatOutcome(outcome));
    return outcome;
  }

  /** A failed audit write is reported, never thrown: the reload already happened, or did not. */
  private async audit(entry: Parameters<AuditStore['record']>[0]): Promise<void> {
    try {
      await this.deps.audit.record(entry);
    } catch (err) {
      console.error(`Audit write failed while recording a config reload: ${describeCloseError(err)}`);
    }
  }
}

/**
 * SIGHUP reloads the config, on platforms where SIGHUP is a signal an operator sends. On
 * Windows it means the console is closing, so it is not wired there. Never exits: the
 * reload reports its own outcome, and a defect that rejects anyway is logged by class only,
 * since its message may quote the file.
 */
export function installSighupReload(
  reloader: Pick<ConfigReloader, 'reload'>,
  proc: Pick<NodeJS.Process, 'platform' | 'on'> = process,
): boolean {
  if (proc.platform === 'win32') return false;
  proc.on('SIGHUP', () => {
    reloader.reload('sighup', 'sighup').catch((err: unknown) => {
      console.error(`Config reload on SIGHUP failed unexpectedly (${errorName(err)}); the server keeps running.`);
    });
  });
  return true;
}

/**
 * Waves of connections to close, each closed only after every connection running
 * through it. The via read is the connection's own profile, which is the hop its live
 * channel actually runs over.
 */
function dependentsFirst(entries: CloseEntry[]): CloseEntry[][] {
  const waves: CloseEntry[][] = [];
  let remaining = entries;
  while (remaining.length > 0) {
    const bastions = new Set(remaining.map((e) => e.conn.profile.via));
    const ready = remaining.filter((e) => !bastions.has(e.profile));
    // A via cycle leaves nothing ready; close the rest together rather than never.
    const wave = ready.length > 0 ? ready : remaining;
    waves.push(wave);
    remaining = remaining.filter((e) => !wave.includes(e));
  }
  return waves;
}

/**
 * A connection's sessions, collected before it closes. One connection that cannot list
 * them, or one session that cannot describe itself, must not stop the others closing.
 */
function sessionsOf(conn: CloseEntry['conn']): { name: string; kind: string }[] {
  let list: ReturnType<CloseEntry['conn']['listSessions']>;
  try {
    list = conn.listSessions();
  } catch {
    return [];
  }
  return list.map((s) => ({ name: s.name, kind: sessionKind(s) }));
}

/**
 * A schema issue's path, with the keys the operator chose replaced by `*`. Under
 * `policy.roleBindings` the next two segments are a role name and a group name, which are
 * values from the file in the sense the cross-check refusal withholds them.
 */
function maskedIssuePath(path: string[]): string {
  if (path.length === 0) return '(root)';
  const masked = path[0] === 'policy' && path[1] === 'roleBindings'
    ? path.map((seg, i) => (i === 2 || i === 3 ? '*' : seg))
    : path;
  return masked.join('.');
}

/** Class and code only: a transport error's message can name the host. */
function describeCloseError(err: unknown): string {
  const code = (err as { code?: unknown } | null)?.code;
  return typeof code === 'string' || typeof code === 'number'
    ? `${errorName(err)} (${code})`
    : errorName(err);
}
