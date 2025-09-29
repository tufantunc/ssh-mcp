import { describe, it, expect } from 'vitest';
import { execSshCommand } from '../src/index';

const host = process.env.SSH_HOST || '127.0.0.1';
const port = Number(process.env.SSH_PORT || 2222);
const username = process.env.SSH_USER || 'test';
const password = process.env.SSH_PASSWORD || 'secret';

describe('ssh smoke', () => {
  it('executes echo ok', async () => {
    const result: any = await execSshCommand({ host, port, username, password }, 'echo ok');
    expect(result.content[0]).toEqual({ type: 'text', text: 'ok\n' });
  }, 20000);
});


