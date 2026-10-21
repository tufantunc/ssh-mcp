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
 *
 * Comparing two sizes? Use `growthRatio`, not two calls to this: CPU time still
 * moves with the speed of the core it is spent on.
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

type Reading = Required<Omit<CpuMsOptions, 'samples'>>;

/** One reading: the CPU time per run of `fn`, averaged over at least `minTotalMs`. */
function averageMs(fn: () => unknown, { minTotalMs, maxRuns, clock }: Reading): number {
  const started = clock();
  let runs = 0;
  let spentMs = 0;
  do {
    fn();
    runs++;
    spentMs = clock() - started;
  } while (spentMs < minTotalMs && runs < maxRuns);
  return spentMs / runs;
}

export function cpuMs(
  fn: () => unknown,
  { samples = 3, minTotalMs = 50, maxRuns = 100_000, clock = processCpuMs }: CpuMsOptions = {},
): number {
  let best = Infinity;
  for (let sample = 0; sample < samples; sample++) {
    best = Math.min(best, averageMs(fn, { minTotalMs, maxRuns, clock }));
  }
  return best;
}

/**
 * How many times the CPU cost of `small` the cost of `large` is: the median ratio
 * across `samples` pairs of readings, each pair taken back to back.
 *
 * CPU time is time, not work. It ignores load, but not the speed of the core the
 * time is spent on: on the dev machine (M4 Max) the awk string-literal case costs
 * ~3.7x the CPU time per run on an efficiency core as on a performance core, and a
 * VM runner adds a host that can slow or deschedule the vCPU without the guest
 * knowing. Two `cpuMs` calls read all of one size, then all of the other, so a
 * slowdown that begins between them reads as growth: with the process moved to the
 * efficiency cores 20-180ms in, the four awk linearity cases read 8.4-16.4x where
 * they read 4.1-4.6x, 18 times in 20. A GitHub macOS runner read 8.2x against the 8x
 * bound the same way.
 *
 * Paired, the two sizes are read moments apart, so a change of speed skews only the
 * pair it lands in — a slow spell skews at most the two pairs its start and end fall
 * in — and the median of five comes from a pair it missed. The same move to the
 * efficiency cores read 3.8-4.8x, forty times in forty. A median rather than the
 * lowest ratio, because one pair can also read low: a quiet run measured 2.4x for a
 * 4.1x case, and a minimum would hand that to a quadratic cost as well. Each side
 * runs once first, so the first pair does not pay for compiling either.
 */
export function growthRatio(
  small: () => unknown,
  large: () => unknown,
  { samples = 5, minTotalMs = 50, maxRuns = 100_000, clock = processCpuMs }: CpuMsOptions = {},
): number {
  const reading = { minTotalMs, maxRuns, clock };
  small();
  large();
  const ratios: number[] = [];
  for (let pair = 0; pair < samples; pair++) {
    const smallMs = averageMs(small, reading);
    const largeMs = averageMs(large, reading);
    ratios.push(smallMs > 0 ? largeMs / smallMs : Infinity);
  }
  ratios.sort((a, b) => a - b);
  return ratios[Math.floor(ratios.length / 2)];
}
