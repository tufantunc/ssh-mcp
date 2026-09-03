import { isAbsolute, relative, sep } from 'node:path';

/** Path-segment-aware containment; unlike a prefix check, siblings never match. */
export function isWithinRoot(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

/** True when either path contains the other (including equality). */
export function pathsOverlap(left: string, right: string): boolean {
  return isWithinRoot(left, right) || isWithinRoot(right, left);
}
