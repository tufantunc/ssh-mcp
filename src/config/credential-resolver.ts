import { readFile } from 'fs/promises';
import { resolve } from 'path';
import type { Profile, ResolvedCredentials } from '../types.js';

let keyringGet: ((service: string, account: string) => Promise<string | null>) | null = null;
let keyringSet: ((service: string, account: string, password: string) => Promise<void>) | null = null;

export function isKeychainAvailable(): boolean {
  return keyringGet !== null;
}

export async function initKeychain(): Promise<boolean> {
  try {
    // @ts-ignore — optional dependency, may not be installed
    const mod: any = await import('@napi-rs/keyring');
    keyringGet = async (service: string, account: string) => {
      const entry = new mod.Entry(service, account);
      return (await entry.getPassword()) || null;
    };
    keyringSet = async (service: string, account: string, password: string) => {
      const entry = new mod.Entry(service, account);
      await entry.setPassword(password);
    };
    return true;
  } catch {
    return false;
  }
}

export async function setKeychainEntry(service: string, account: string, password: string): Promise<void> {
  if (!keyringSet) throw new Error('Keychain not initialized. Install @napi-rs/keyring.');
  await keyringSet(service, account, password);
}

export async function resolveCredentials(profile: Profile): Promise<ResolvedCredentials> {
  const creds: ResolvedCredentials = {};

  const envPrefix = `SSH_MCP_${profile.name.toUpperCase().replace(/[^A-Z0-9]/g, '_')}`;

  if (process.env.SSH_AUTH_SOCK && profile.auth === 'agent') {
    creds.agentSocket = process.env.SSH_AUTH_SOCK;
  }

  // Warn rather than silently walking down to a weaker credential source: a
  // profile that asked for the OS keychain and got an env var instead has a
  // different security posture than the operator configured.
  if (profile.auth === 'keychain' && !keyringGet) {
    console.error(
      `Profile "${profile.name}" requests auth = "keychain" but @napi-rs/keyring is unavailable ` +
      '(it is an optional dependency). Falling back to the remaining credential sources.',
    );
  }

  if (profile.auth === 'keychain' && profile.keychainEntry && keyringGet) {
    try {
      const [service, account] = profile.keychainEntry.split('/');
      const secret = await keyringGet(service || 'ssh-mcp', account || profile.name);
      if (secret) {
        if (profile.keyRef) {
          creds.privateKey = secret;
        } else {
          creds.password = secret;
        }
      }
    } catch (err) {
      console.error(`Keychain lookup failed for ${profile.keychainEntry}:`, err);
    }
  }

  if (process.env[`${envPrefix}_PASSWORD`]) {
    creds.password = creds.password || process.env[`${envPrefix}_PASSWORD`];
  } else if (process.env.SSH_MCP_PASSWORD) {
    creds.password = creds.password || process.env.SSH_MCP_PASSWORD;
  }

  if (process.env[`${envPrefix}_SUDO_PASSWORD`]) {
    creds.sudoPassword = process.env[`${envPrefix}_SUDO_PASSWORD`];
  } else if (process.env.SSH_MCP_SUDO_PASSWORD) {
    creds.sudoPassword = process.env.SSH_MCP_SUDO_PASSWORD;
  }

  if (process.env[`${envPrefix}_PASSPHRASE`]) {
    creds.passphrase = process.env[`${envPrefix}_PASSPHRASE`];
  } else if (process.env.SSH_MCP_PASSPHRASE) {
    creds.passphrase = process.env.SSH_MCP_PASSPHRASE;
  }

  const keyPath = profile.keyRef || process.env[`${envPrefix}_KEY`] || process.env.SSH_MCP_KEY;
  if (keyPath && !creds.privateKey) {
    try {
      creds.privateKey = await readFile(resolve(keyPath.replace(/^~/, process.env.HOME || '~')), 'utf8');
    } catch (err: any) {
      if (err.code !== 'ENOENT') throw err;
    }
  }

  if (profile.cert && creds.privateKey) {
    const certPath = process.env[`${envPrefix}_CERT`]
      || (keyPath ? `${keyPath.replace(/\.pub$/, '')}-cert.pub` : undefined);
    if (certPath) {
      try {
        creds.certificate = await readFile(resolve(certPath.replace(/^~/, process.env.HOME || '~')), 'utf8');
      } catch (err: any) {
        if (err.code !== 'ENOENT') throw err;
      }
    }
  }

  if (!creds.password && !creds.privateKey && !creds.agentSocket) {
    throw new Error(
      `No credentials resolved for profile "${profile.name}". ` +
      `Available methods: SSH agent (SSH_AUTH_SOCK), OS keychain (auth=keychain), env vars (SSH_MCP_PASSWORD), or key file (SSH_MCP_KEY).`,
    );
  }

  return creds;
}
