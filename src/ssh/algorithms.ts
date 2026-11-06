export const FROZEN_ALGORITHMS = {
  kex: [
    'curve25519-sha256',
    'curve25519-sha256@libssh.org',
    'ecdh-sha2-nistp256',
    'ecdh-sha2-nistp384',
    'ecdh-sha2-nistp521',
    'diffie-hellman-group16-sha512',
    'diffie-hellman-group14-sha256',
  ],
  cipher: [
    'chacha20-poly1305@openssh.com',
    'aes256-gcm@openssh.com',
    'aes128-gcm@openssh.com',
    'aes256-ctr',
    'aes192-ctr',
    'aes128-ctr',
  ],
  serverHostKey: [
    'ssh-ed25519',
    'ecdsa-sha2-nistp256',
    'ecdsa-sha2-nistp384',
    'ecdsa-sha2-nistp521',
    'rsa-sha2-512',
    'rsa-sha2-256',
  ],
  hmac: [
    'hmac-sha2-256-etm@openssh.com',
    'hmac-sha2-512-etm@openssh.com',
    'hmac-sha2-256',
    'hmac-sha2-512',
  ],
};


const CHACHA20 = 'chacha20-poly1305@openssh.com';

/**
 * The algorithms for a connection carried inside another SSH connection — every hop of a
 * `via` profile past the first. The frozen set, with chacha20-poly1305 offered last.
 *
 * ssh2's JavaScript chacha20 cipher keeps its nonce in one module-level buffer and hands
 * the encrypted packet length to the socket before it encrypts the payload. When that
 * socket is a channel of another connection, the write encrypts the outer packet then and
 * there, and the outer cipher leaves *its* sequence number in the shared buffer — so the
 * inner payload goes out under the wrong nonce, the server cannot read the first
 * encrypted packet (`ssh-userauth`'s SERVICE_REQUEST), and the handshake hangs (#315,
 * mscdex/ssh2#1523). It takes chacha20 on this hop and on any hop it is carried over —
 * the write passes through non-chacha hops in between — plus the JavaScript path, which
 * is what runs whenever ssh2's optional native binding is absent: the published Docker
 * image installs with `--ignore-scripts`, so every two-hop profile there was affected.
 *
 * Moved rather than removed: any other common cipher is chosen first, and a server that
 * only speaks chacha20 is still offered it. On the JavaScript path such a server inside
 * a chain still hangs, as it did before; nothing that connected stops connecting.
 * test/integration/via-chacha.test.ts fails its control the day ssh2 ships the fix, which
 * is when this goes.
 */
export const FORWARDED_ALGORITHMS = {
  ...FROZEN_ALGORITHMS,
  cipher: [...FROZEN_ALGORITHMS.cipher.filter((c) => c !== CHACHA20), CHACHA20],
};
