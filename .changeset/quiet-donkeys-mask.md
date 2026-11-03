---
'ssh-mcp': patch
---

Mask short, low-entropy credentials in plaintext configuration assignments (`name=value`, UCI `option name 'value'`) during output redaction when the field name indicates a secret.
