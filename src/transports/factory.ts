import { ISshTransport, TransportConfig } from './types.js';
import { Ssh2Transport } from './ssh2.js';
import { OpenSshTransport } from './openssh.js';

/**
 * Choose and construct a transport based on cfg.transport. Default is 'ssh2'
 * to preserve upstream behaviour for users who don't opt in to OpenSSH.
 */
export function createTransport(cfg: TransportConfig): ISshTransport {
  const choice = cfg.transport ?? 'ssh2';
  if (choice === 'openssh') return new OpenSshTransport(cfg);
  return new Ssh2Transport(cfg);
}
