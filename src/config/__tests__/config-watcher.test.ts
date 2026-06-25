/**
 * config-watcher.ts — debounced fs.watch driver (PR-9).
 *
 * Exercises the WHEN-of-reload in isolation against a real temp file, with no
 * SSH host and no real config: a burst of writes must collapse to a single
 * onChange (debounce); changes arriving DURING an in-flight reload must coalesce
 * to exactly one trailing reload (re-entrancy guard); a throwing callback must
 * not kill the watcher; an empty path is a no-op (CLI mode).
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
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
});
