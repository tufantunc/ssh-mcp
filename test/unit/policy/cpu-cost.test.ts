import { describe, it, expect } from 'vitest';
import { cpuMs } from './cpu-cost.js';

/**
 * The growth-ratio cost tests rest on `cpuMs` actually measuring work, so it gets a
 * check of its own: a helper that returned a constant, or zero, would turn every one
 * of them into a test that cannot fail.
 */
describe('cpuMs', () => {
  const quadratic = (n: number) => () => {
    let x = 0;
    for (let i = 0; i < n; i++) for (let j = 0; j < n; j++) x += i ^ j;
    return x;
  };

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
