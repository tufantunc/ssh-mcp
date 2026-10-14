/**
 * The cost of `fn` in milliseconds of CPU time this process spent on it: the
 * cheapest of `samples` readings, each averaged over as many runs as it takes to
 * accumulate `minTotalMs`.
 *
 * CPU time rather than wall-clock time, for the growth-ratio tests. On a busy
 * machine the scheduler preempts a long run more often than a short one, so a
 * wall-clock ratio drifts upward with the load rather than with the code's cost.
 * Measured with all 16 cores of the dev machine busy: the awk linearity tests read
 * 8.6-9.2x for 4x the input against an 8x bound in three of six runs, and passed
 * all six on CPU time. Vitest runs each test file in its own process (the default
 * `forks` pool), so another file's work is not counted; V8's GC threads are, and
 * they are part of the cost being measured.
 *
 * Averaged over repeated runs because CPU clocks are coarse on some platforms —
 * Windows' GetProcessTimes ticks every ~15.6ms, so a single sub-millisecond run
 * would read as zero or as a whole tick. The minimum of several readings still
 * matters: JIT warm-up and a GC pause only ever add time.
 */
export interface CpuMsOptions {
  samples?: number;
  minTotalMs?: number;
  maxRuns?: number;
  /** Milliseconds of CPU time so far; injectable so a coarse clock can be tested. */
  clock?: () => number;
}

const processCpuMs = () => {
  const used = process.cpuUsage();
  return (used.user + used.system) / 1000;
};

export function cpuMs(
  fn: () => unknown,
  { samples = 3, minTotalMs = 50, maxRuns = 100_000, clock = processCpuMs }: CpuMsOptions = {},
): number {
  let best = Infinity;
  for (let sample = 0; sample < samples; sample++) {
    const started = clock();
    let runs = 0;
    let spentMs = 0;
    do {
      fn();
      runs++;
      spentMs = clock() - started;
    } while (spentMs < minTotalMs && runs < maxRuns);
    best = Math.min(best, spentMs / runs);
  }
  return best;
}
