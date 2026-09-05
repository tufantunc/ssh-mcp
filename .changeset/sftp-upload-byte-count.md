---
"ssh-mcp": patch
---

**Fix:** `sftp-upload` reports the number of bytes it wrote, not the string's UTF-16 length.

`content` is a JS string, so `content.length` counts UTF-16 code units. Every character that
takes more than one byte in UTF-8 was counted once instead of two or three, so the reported
size was systematically low for any non-ASCII upload — measured as `Uploaded 26501 bytes` for
a file that is 34138 bytes on disk, 22% under.

The transfer itself was never affected. `SftpClient.upload` writes `Buffer.from(content)`,
which is utf8, and the md5 of the uploaded file matched the source byte for byte. Only the
number in the reply was wrong.

That number is the only confirmation a caller gets that an upload succeeded, so a systematic
mismatch means checking a transfer takes a second `md5sum` round-trip — the report is least
trustworthy exactly where it is relied on. `Buffer.byteLength(content, 'utf8')` is by
definition the length of the buffer `Buffer.from(content)` produces, so the count now
describes what reached the remote side.
