/**
 * config-watcher.ts — debounced fs.watch driver (PR-9).
 *
 * Exercises the WHEN-of-reload in isolation against a real temp file, with no
 * SSH host and no real config: a burst of writes must collapse to a single
 * onChange (debounce); changes arriving DURING an in-flight reload must coalesce
 * to exactly one trailing reload (re-entrancy guard); a throwing callback must
 * not kill the watcher; an empty path is a no-op (CLI mode).
 */
import { mkdtempSync, rmSync, writeFileSync, renameSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';

import { startConfigWatcher, DEFAULT_DEBOUNCE_MS } from '../config-watcher.js';

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

describe('startConfigWatcher', () => {
  let dir: string;
  let cfgPath: string;
  let stop: (() => void) | null;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'ssh-mcp-watch-'));
    cfgPath = join(dir, 'config.toml');
    writeFileSync(cfgPath, 'sources = []\n');
    stop = null;
  });

  afterEach(() => {
    if (stop) { try { stop(); } catch { /* ignore */ } }
    rmSync(dir, { recursive: true, force: true });
  });

  it('returns null (no-op) when the path is empty', () => {
    const cleanup = startConfigWatcher({ configPath: '', onChange: () => {} });
    expect(cleanup).toBeNull();
  });

  it('coalesces a burst of writes into a single onChange (debounce)', async () => {
    let calls = 0;
    stop = startConfigWatcher({
      configPath: cfgPath,
      debounceMs: 80,
      onChange: () => { calls++; },
      log: () => {},
    });
    expect(stop).toBeTypeOf('function');

    // Fire several rapid writes — like an editor saving (truncate+write+rename).
    for (let i = 0; i < 5; i++) {
      writeFileSync(cfgPath, `sources = []\n# edit ${i}\n`);
      await sleep(10);
    }
    // Wait past the debounce window.
    await sleep(200);
    expect(calls).toBe(1);
  });

  it('coalesces changes during an in-flight reload into one trailing reload', async () => {
    const order: string[] = [];
    let resolveFirst!: () => void;
    let signalStarted!: () => void;
    const firstStarted = new Promise<void>(res => { signalStarted = res; });
    let started = false;

    stop = startConfigWatcher({
      configPath: cfgPath,
      debounceMs: 40,
      log: () => {},
      onChange: async () => {
        order.push('start');
        if (!started) {
          started = true;
          signalStarted();
          // Hold the first reload open so subsequent change events arrive
          // while isReloading === true.
          await new Promise<void>(res => { resolveFirst = res; });
        }
        order.push('end');
      },
    });

    // Trigger the first reload.
    writeFileSync(cfgPath, 'sources = []\n# a\n');
    await firstStarted; // first reload is now in-flight (awaiting resolveFirst)

    // Fire 3 more changes while the first reload is parked.
    for (let i = 0; i < 3; i++) {
      writeFileSync(cfgPath, `sources = []\n# b${i}\n`);
      await sleep(10);
    }
    // Let the first reload finish; the guard should schedule exactly ONE more.
    resolveFirst();
    await sleep(200);

    const starts = order.filter(o => o === 'start').length;
    // First reload + exactly one coalesced trailing reload = 2 (not 4).
    expect(starts).toBe(2);
  });

  it('keeps watching after the callback throws', async () => {
    let calls = 0;
    stop = startConfigWatcher({
      configPath: cfgPath,
      debounceMs: 40,
      log: () => {},
      onChange: () => {
        calls++;
        throw new Error('boom');
      },
    });

    writeFileSync(cfgPath, 'sources = []\n# 1\n');
    await sleep(120);
    expect(calls).toBe(1);

    // A second change still fires — the watcher survived the throw.
    writeFileSync(cfgPath, 'sources = []\n# 2\n');
    await sleep(120);
    expect(calls).toBe(2);
  });

  it('exposes a 500ms default debounce constant', () => {
    expect(DEFAULT_DEBOUNCE_MS).toBe(500);
  });

  it('cleanup stops further reloads', async () => {
    let calls = 0;
    const cleanup = startConfigWatcher({
      configPath: cfgPath,
      debounceMs: 40,
      log: () => {},
      onChange: () => { calls++; },
    })!;
    cleanup();
    stop = null;

    writeFileSync(cfgPath, 'sources = []\n# after-stop\n');
    await sleep(120);
    expect(calls).toBe(0);
  });

  it('does not fire onChange after cleanup runs during an in-flight reload', async () => {
    // Race regression: a change arrives while a reload is in flight
    // (reloadPending = true), cleanup() runs, and the in-flight reload's
    // `finally` must NOT re-schedule a trailing reload that fires onChange()
    // after the watcher was closed.
    const order: string[] = [];
    let resolveFirst!: () => void;
    let signalStarted!: () => void;
    const firstStarted = new Promise<void>(res => { signalStarted = res; });
    let started = false;

    const cleanup = startConfigWatcher({
      configPath: cfgPath,
      debounceMs: 40,
      log: () => {},
      onChange: async () => {
        order.push('start');
        if (!started) {
          started = true;
          signalStarted();
          // Park the first reload so the second change lands while
          // isReloading === true (sets reloadPending).
          await new Promise<void>(res => { resolveFirst = res; });
        }
        order.push('end');
      },
    })!;
    stop = null;

    // Kick off the first reload and wait until it is parked in-flight.
    writeFileSync(cfgPath, 'sources = []\n# a\n');
    await firstStarted;

    // A change arrives DURING the in-flight reload. Wait past the debounce
    // window so its debounce timer FIRES runReload(), which sees isReloading
    // and sets reloadPending = true (this is the state the finally-reschedule
    // race depends on; clearing the timer too early would never reach it).
    writeFileSync(cfgPath, 'sources = []\n# b\n');
    await sleep(80);

    // Tear the watcher down while the first reload is still parked and
    // reloadPending is latched.
    cleanup();

    // Release the parked reload; its `finally` sees reloadPending but must
    // bail because the watcher is now closed.
    resolveFirst();
    await sleep(200);

    // Exactly ONE onChange ran (the first, already in flight at cleanup) and
    // NO trailing reload fired after cleanup.
    expect(order.filter(o => o === 'start').length).toBe(1);
  });

  it('keeps firing after an atomic-rename save replaces the file inode', async () => {
    let calls = 0;
    stop = startConfigWatcher({
      configPath: cfgPath,
      debounceMs: 60,
      onChange: () => { calls++; },
      log: () => {},
    });
    expect(stop).toBeTypeOf('function');

    // First save via atomic rename: editors/tools write a temp file then
    // rename it over config.toml, which REPLACES the inode. A file-inode
    // watcher would see this once and then go deaf; a directory watcher does
    // not.
    const tmp1 = join(dir, '.config.toml.tmp1');
    writeFileSync(tmp1, 'sources = []\n# rename-1\n');
    renameSync(tmp1, cfgPath);
    await sleep(160);
    expect(calls).toBe(1);

    // Plain in-place edit to the NEW inode still fires — proves the watcher is
    // not stuck on the old, now-unlinked inode.
    writeFileSync(cfgPath, 'sources = []\n# in-place\n');
    await sleep(160);
    expect(calls).toBe(2);

    // A SECOND atomic-rename save also fires — this is exactly what breaks with
    // a file-bound fs.watch (it only re-arms, at best, for one rename).
    const tmp2 = join(dir, '.config.toml.tmp2');
    writeFileSync(tmp2, 'sources = []\n# rename-2\n');
    renameSync(tmp2, cfgPath);
    await sleep(160);
    expect(calls).toBe(3);
  });

  it('ignores changes to OTHER files in the watched directory', async () => {
    let calls = 0;
    stop = startConfigWatcher({
      configPath: cfgPath,
      debounceMs: 60,
      onChange: () => { calls++; },
      log: () => {},
    });

    // Churn a sibling file in the same directory — must NOT trigger a reload.
    const sibling = join(dir, 'unrelated.toml');
    writeFileSync(sibling, 'noise = 1\n');
    await sleep(160);
    expect(calls).toBe(0);

    // The watched file still fires.
    writeFileSync(cfgPath, 'sources = []\n# real\n');
    await sleep(160);
    expect(calls).toBe(1);
  });
});
