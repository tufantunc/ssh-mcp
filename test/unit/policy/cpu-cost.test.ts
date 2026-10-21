import { describe, it, expect } from 'vitest';
import { cpuMs, growthRatio } from './cpu-cost.js';

/**
 * The growth-ratio cost tests rest on `cpuMs` and `growthRatio` actually measuring
 * work, so they get checks of their own: a helper that returned a constant, or zero,
 * would turn every one of them into a test that cannot fail.
 */
const quadratic = (n: number) => () => {
  let x = 0;
  for (let i = 0; i < n; i++) for (let j = 0; j < n; j++) x += i ^ j;
  return x;
};

describe('cpuMs', () => {
  it('sees a quadratic cost grow far past a linear bound', () => {
    // 4x the input, 16x the work: well past the 8x bound the linear tests use.
    const ratio = cpuMs(quadratic(2_000)) / cpuMs(quadratic(500));
    expect(ratio).toBeGreaterThan(8);
  });

  it('averages a cost far below the clock resolution of a Windows runner', () => {
    // A clock that ticks every 15.6ms, like GetProcessTimes, around work that costs
    // 0.01ms a run. One reading of one run would say 0; the per-run cost has to come
    // out of enough runs to span many ticks.
    let workMs = 0;
    const coarseClock = () => Math.floor(workMs / 15.6) * 15.6;
    const perRun = cpuMs(() => { workMs += 0.01; }, { clock: coarseClock });
    expect(perRun).toBeGreaterThan(0.009);
    expect(perRun).toBeLessThan(0.011);
  });
});

describe('growthRatio', () => {
  it('sees a quadratic cost grow far past a linear bound', () => {
    expect(growthRatio(quadratic(500), quadratic(2_000))).toBeGreaterThan(8);
  });

  /**
   * A machine that is `slowdown` times slower from call `from` to call `to`, the way
   * it is after a move to an efficiency core (3.7x on the dev machine), around work
   * that costs `ms` a run at full speed.
   */
  const slowSpell = (from: number, to: number, slowdown = 3.7) => {
    let nowMs = 0;
    let calls = 0;
    const work = (ms: number) => () => {
      nowMs += calls >= from && calls < to ? ms * slowdown : ms;
      calls++;
    };
    return { work, clock: () => nowMs };
  };

  it('reads a slowdown between two cpuMs calls as growth', () => {
    // The failure `growthRatio` exists for, pinned so the sweep below is known to
    // cover it: 4x the work, read as 14.8x because the small size's 150 runs were
    // all at full speed and the large size's all after the slowdown.
    const { work, clock } = slowSpell(150, Infinity);
    const small = cpuMs(work(1), { clock });
    expect(cpuMs(work(4), { clock }) / small).toBeGreaterThan(8);
  });

  it('reads 4x the work as 4x, and 16x as 16x, whenever one slow spell falls', () => {
    // Every start and end within the ~320 calls a measurement makes, and spells
    // that never end. Linear must stay under the 8x bound and quadratic over it.
    // Both directions are load-bearing: the highest pair ratio reads the linear
    // work as 14.8x here, and the lowest reads the quadratic as 4.3x.
    let linearWorst = 0;
    let quadraticBest = Infinity;
    for (let from = 0; from <= 330; from++) {
      for (const to of [...Array.from({ length: 331 - from }, (_, i) => from + 1 + i), Infinity]) {
        const linear = slowSpell(from, to);
        linearWorst = Math.max(linearWorst,
          growthRatio(linear.work(1), linear.work(4), { clock: linear.clock }));
        const squared = slowSpell(from, to);
        quadraticBest = Math.min(quadraticBest,
          growthRatio(squared.work(1), squared.work(16), { clock: squared.clock }));
      }
    }
    expect(linearWorst).toBeLessThan(8);
    expect(quadraticBest).toBeGreaterThan(8);
  });
});
