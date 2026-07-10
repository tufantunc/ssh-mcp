import { describe, expect, it } from 'vitest';

import { parseTomlConfig } from '../../src/config/toml-loader.js';

const source = `
[[sources]]
id = "x"
host = "h"
user = "u"
auth = "kerberos"
`;

describe('WebUI effective boot validation', () => {
  it('resolves auth_token when the CLI enables a disabled TOML WebUI', () => {
    const cfg = parseTomlConfig(`${source}
[webui]
enabled = false
host = "0.0.0.0"
auth_token = "env:WEBUI_TOKEN"
`, { env: { WEBUI_TOKEN: 'resolved-token' }, webuiEnabled: true });

    expect(cfg.webui?.enabled).toBe(false);
    expect(cfg.webui?.auth_token).toBe('resolved-token');
  });

  it('rejects non-integer and out-of-range ports before listen()', () => {
    for (const port of [-1, 22.5, 65536]) {
      expect(() => parseTomlConfig(`${source}
[webui]
port = ${port}
`)).toThrow(/port must be an integer between 0 and 65535/);
    }
  });

  it('accepts the Node listen boundary ports', () => {
    for (const port of [0, 65535]) {
      const cfg = parseTomlConfig(`${source}
[webui]
port = ${port}
`);
      expect(cfg.webui?.port).toBe(port);
    }
  });
});
