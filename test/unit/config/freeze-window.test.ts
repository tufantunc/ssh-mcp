import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { loadConfig } from '../../../src/config/loader.js';
import { makeConfigDir, type ConfigDir } from './helpers.js';

let cfg: ConfigDir;
beforeEach(async () => { cfg = await makeConfigDir(); });
afterEach(async () => { await cfg.cleanup(); });

const config = (window: string) => `
[[profiles]]
name = "prod-trading"
group = "prod"
host = "localhost"
user = "ops"

[[policy.freezeWindows]]
groups = ["prod"]
timezone = "Asia/Shanghai"
weekdays = [1, 2, 3, 4, 5]
${window}
`;

describe('freeze window config', () => {
  it('loads an explicit IANA-zone weekly window', async () => {
    const loaded = await loadConfig(await cfg.write(config('start = "09:00"\nend = "15:30"')));
    expect(loaded.policy?.freezeWindows?.[0]).toEqual({
      groups: ['prod'], timezone: 'Asia/Shanghai', weekdays: [1, 2, 3, 4, 5],
      start: '09:00', end: '15:30',
    });
  });

  it.each([
    'start = "9:00"\nend = "15:30"',
    'start = "09:00"\nend = "09:00"',
  ])('rejects an invalid time window', async (window) => {
    await expect(loadConfig(await cfg.write(config(window)))).rejects.toThrow(/Config validation/);
  });

  it('rejects an invalid timezone', async () => {
    await expect(loadConfig(await cfg.write(config(
      'timezone = "Not/AZone"\nstart = "09:00"\nend = "15:30"',
    ).replace('timezone = "Asia/Shanghai"\n', '')))).rejects.toThrow(/Config validation/);
  });
});
