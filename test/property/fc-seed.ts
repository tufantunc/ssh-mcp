import type { CommandClass } from '../../src/types.js';

/**
 * The seed every property run uses unless `FC_SEED` says otherwise.
 *
 * Fixed rather than random, on purpose. These properties guard the command classifier,
 * and CI logs are public: a random seed could one day find a real gap and print its
 * counterexample in a public log, next to a red public check. With a fixed seed, CI
 * replays inputs that have already been checked. Exploring new seeds is done privately,
 * by setting `FC_SEED` on a local run.
 */
export const FC_DEFAULT_SEED = 20261023;

/** `{ numRuns, seed }` for `fc.assert`, with the seed from `FC_SEED` when it is set. */
export function fcParams(numRuns: number): { numRuns: number; seed: number } {
  const raw = process.env.FC_SEED;
  if (raw === undefined || raw === '') return { numRuns, seed: FC_DEFAULT_SEED };
  // A typo that silently fell back to the default would make a "new seed" run replay the
  // old one and report the space as explored.
  if (!/^-?\d+$/.test(raw)) throw new Error(`FC_SEED must be an integer, got ${JSON.stringify(raw)}`);
  const seed = Number(raw);
  // fast-check reduces the seed to a signed 32-bit integer, so a larger one silently
  // replays another seed's inputs — the same failure as the typo above.
  if ((seed | 0) !== seed) throw new Error(`FC_SEED must fit in a signed 32-bit integer, got ${raw}`);
  return { numRuns, seed };
}

/**
 * The class ordering, written here as a literal rather than imported: the classifier's
 * own table is not exported, and the contract under test should not be read from the
 * code under test.
 */
export const CLASS_RANK: Record<CommandClass, number> = {
  'read-only': 0,
  safe: 1,
  destructive: 2,
  privileged: 3,
};

/** `a` is the same class as `b`, or a higher one. */
export function atLeast(a: CommandClass, b: CommandClass): boolean {
  return CLASS_RANK[a] >= CLASS_RANK[b];
}
