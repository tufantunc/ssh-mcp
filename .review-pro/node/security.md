# Stack pack: node — security
extends: core/skills/security/SKILL.md

## Stack-specific signals
- `eval` / `new Function` / `vm.runIn*` on non-static input → RCE.
- `child_process.exec(...)` / `execSync` with interpolated input → command injection (use `execFile`/`spawn` with arg arrays).
- `require(userInput)` / dynamic `import(userInput)` → arbitrary module load.
- `fs`/path operations on user-supplied paths without normalization → path traversal (`../`). Check against a resolved base with `path.relative`.
- Regex from user/external input, or catastrophic patterns → ReDoS.
- `Object.assign` / spread into objects in a way that allows `__proto__`/`constructor.prototype` pollution.
- Response/header injection from unescaped CRLF in `setHeader` values.
- Insecure deserialization via `node-serialize` / `cson` / similar.

## Stack-specific remedies
- Never pass dynamic strings to `exec`/`eval`; use arg-array APIs and allowlists.
- Resolve and confine user paths to a known root; reject escapes.
- Use `http.Server` response helpers carefully; strip CR/LF from header values.
- Avoid prototype-pollutable merges; use `Object.create(null)` / maps where keys are external.

## Stack-specific severity guidance
- Command injection / RCE via `child_process.exec` on input: Critical.
- Path traversal letting a user read/write outside their dir: Critical/High.
- ReDoS on a public endpoint: High.
