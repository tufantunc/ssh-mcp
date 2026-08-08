/**
 * Retry opening an SSH channel a couple of times before giving up.
 *
 * Not every server allocates a channel reliably on the first ask. Dropbear in
 * particular fails intermittently right after a previous channel was released —
 * reproduced with raw ssh2, no code of ours involved:
 *
 *   cycle #1: ok
 *   cycle #2: FAIL - Unable to request a pseudo-terminal
 *   cycle #3: ok
 *
 * The same happens for the SFTP subsystem. Without a retry, opening a session
 * or transferring a file is a coin flip on a whole class of hosts (embedded
 * targets, routers, minimal images) — and the failure surfaces to the user as a
 * flat "failed to open interactive session".
 *
 * Retrying an *open* is safe: a failed open created nothing. The budget is
 * deliberately small, so a genuinely broken host still fails fast rather than
 * stalling behind retries.
 */
export interface RetryOptions {
  attempts?: number;
  delayMs?: number;
}

export async function openWithRetry<T>(
  open: () => Promise<T>,
  { attempts = 3, delayMs = 150 }: RetryOptions = {},
): Promise<T> {
  let lastError: unknown;

  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      return await open();
    } catch (err) {
      lastError = err;
      if (attempt < attempts) {
        await new Promise((resolve) => setTimeout(resolve, delayMs * attempt));
      }
    }
  }

  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}
