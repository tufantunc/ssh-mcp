# Progress Notifications — Design Spec

**Date:** 2026-07-11
**Status:** Approved
**Goal:** Send MCP `notifications/progress` during long-running SSH commands so clients can display live output instead of a blind spinner.

---

## Context

When the agent runs a long command (`npm run build`, `apt upgrade`, `tail`), the MCP server waits silently until the command completes. The client sees only a spinner — no indication of progress, no partial output, no way to tell if the command is stuck.

The MCP spec defines `notifications/progress` for exactly this. The client provides a `progressToken` in the request's `_meta`; the server sends periodic notifications with `{ progressToken, progress, message }` referencing that token. Claude Desktop supports this; clients that don't send a token simply never receive notifications (no breaking change).

## Design

### ExecOpts gets `onProgress`

```typescript
// types.ts
export interface ExecOpts {
  tty?: boolean;
  stdin?: string;
  timeoutMs?: number;
  profile?: string;
  session?: string;
  onProgress?: (bytesReceived: number, recentOutput: string) => void;
}
```

### SSHConnection.exec() throttles and calls onProgress

Inside `exec()`, the existing `stream.on('data', ...)` handler already accumulates `stdout`. Add a 500ms throttle: every 500ms (at most), if `onProgress` is set, call it with the current byte count and the last 3 lines of stdout.

```typescript
// connection.ts exec() — inside stream.on('data')
let lastProgressSent = 0;
const PROGRESS_INTERVAL = 500;

stream.on('data', (data: Buffer) => {
  if (stdout.length < maxOutput) stdout += data.toString();
  if (opts.onProgress && Date.now() - lastProgressSent >= PROGRESS_INTERVAL) {
    lastProgressSent = Date.now();
    const lines = stdout.split('\n').filter(Boolean).slice(-3).join('\n');
    opts.onProgress(stdout.length, lines);
  }
});
```

### registry.ts creates progress sender from extra

In the `runAudited` helper and inline handlers, extract `progressToken` from the MCP request's `_meta`:

```typescript
function makeProgressSender(extra: any): ((bytes: number, tail: string) => void) | undefined {
  const token = extra?._meta?.progressToken;
  if (token === undefined) return undefined;
  return (bytes, tail) => {
    extra.sendNotification({
      method: 'notifications/progress',
      params: { progressToken: token, progress: bytes, message: tail },
    }).catch(() => {});
  };
}
```

Pass it to `exec()` via `ExecOpts.onProgress`.

### Affected tools

- `read-command` — via `runAudited`
- `run-command` — inline handler
- `privileged-command` — inline handler

Not affected (too fast to need progress): `list-connections`, `list-sessions`, `open-session`, `close-session`, `read-session-output`, `sftp-upload`, `sftp-download`, `signal-process`.

### Notification shape

```json
{
  "method": "notifications/progress",
  "params": {
    "progressToken": 42,
    "progress": 5023,
    "message": "> Building src/index.ts...\n> Bundling..."
  }
}
```

- `progress`: bytes of stdout received so far (monotonically increasing)
- `message`: last 3 non-empty lines of stdout (tail)
- No `total` (we don't know output size ahead of time)

### Throttle

500ms minimum between notifications per command. Implemented as a timestamp check in the `data` handler.

### Graceful degradation

If the client doesn't provide `progressToken`, `makeProgressSender` returns `undefined`, `opts.onProgress` is `undefined`, the throttle check is skipped. Zero overhead, zero notifications.

## Testing

Add one integration test: run a command that produces output over ~2 seconds, verify progress notification was sent at least once. This requires an in-process MCP client that provides a `progressToken` and captures notifications.

## Files Modified

| File | Change |
|------|--------|
| `src/types.ts` | `ExecOpts.onProgress` field |
| `src/ssh/connection.ts` | Throttle + callback call in `exec()` |
| `src/tools/registry.ts` | `makeProgressSender()`, pass to `exec()` in 3 handlers |
