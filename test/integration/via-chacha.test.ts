import { describe, it, expect } from 'vitest';
import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { isSshServerUp, assertAvailable, SSH_HOST } from './helpers.js';

/**
 * #315 end to end: a `via` profile over two OpenSSH hops, on ssh2's JavaScript cipher
 * path.
 *
 * That path is the whole point and is why proxy-jump.test.ts never saw this: CI's
 * `npm ci` builds ssh2's optional native binding, which has no such bug, while the
 * published Docker image (`npm ci --ignore-scripts`) and installs without build tools
 * run the JavaScript ciphers. So the hops run in a child that cannot load the binding,
 * and the child reports that it could not, so a green run cannot mean the wrong path.
 *
 * ssh2 is driven directly with the two algorithm sets because the decision that picks
 * between them — a connection with a bastion socket offers FORWARDED_ALGORITHMS — is
 * pinned in test/unit/ssh/forwarded-algorithms.test.ts, and the child would otherwise
 * need the built server.
 */

const BASTION_PORT = 2225;
const TARGET_FROM_BASTION = { host: 'ssh-operator', port: 2222 };
/** Far above the ~50ms a working two-hop exec takes here; a broken one never returns. */
const HANG_MS = 6000;

const CHILD = fileURLToPath(new URL('./fixtures/via-chacha-child.mjs', import.meta.url));
const HIDE_BINDING = fileURLToPath(new URL('./fixtures/hide-ssh2-binding.cjs', import.meta.url));

function twoHops(outer: 'frozen' | 'forwarded', inner: 'frozen' | 'forwarded') {
  return new Promise<{ result: string; bindingAvailable: boolean }>((resolve, reject) => {
    // `--experimental-transform-types` so the child imports src/ssh/algorithms.ts itself,
    // the module under test, rather than a build that may be stale.
    const child = spawn(process.execPath, [
      '--require', HIDE_BINDING, '--experimental-transform-types', '--no-warnings', CHILD,
      outer, inner, SSH_HOST, String(BASTION_PORT),
      TARGET_FROM_BASTION.host, String(TARGET_FROM_BASTION.port), String(HANG_MS),
    ], { stdio: ['ignore', 'pipe', 'inherit'] });
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    child.on('error', reject);
    child.on('close', () => {
      try { resolve(JSON.parse(out)); } catch { reject(new Error(`child printed ${JSON.stringify(out)}`)); }
    });
  });
}

const bastionUp = await isSshServerUp(SSH_HOST, BASTION_PORT)
  .then((up) => assertAvailable(up, `bastion (${SSH_HOST}:${BASTION_PORT})`));

describe.skipIf(!bastionUp)('a via profile on ssh2\'s JavaScript ciphers', () => {
  it('connects when the inner hop offers the forwarded set', async () => {
    const { result, bindingAvailable } = await twoHops('frozen', 'forwarded');
    expect(bindingAvailable, 'the child loaded the native binding, so this tested nothing').toBe(false);
    expect(result).toBe('ok');
  }, HANG_MS + 10_000);

  it('still hangs with chacha20 on both hops, which is the ssh2 bug this works around', async () => {
    // The control. If this starts passing, ssh2 has fixed mscdex/ssh2#1523: retire
    // FORWARDED_ALGORITHMS rather than keep a workaround for a bug that is gone.
    const { result, bindingAvailable } = await twoHops('frozen', 'frozen');
    expect(bindingAvailable).toBe(false);
    expect(result, 'ssh2 no longer corrupts the nested chacha20 nonce; FORWARDED_ALGORITHMS can go').toBe('hang');
  }, HANG_MS + 10_000);
});
