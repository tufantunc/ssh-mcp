---
"ssh-mcp": minor
---

`[policy].denylist` patterns are now also tested against the remote path of the five SFTP tools, as given and lexically normalized (`//`, `/./` and `..` resolved, `\` read as `/`), not only against the command string this server composes for them (#230). A rule written for the path, such as `authorized_keys$`, used to miss `sftp-upload-file` and `sftp-download-file`, whose strings end with the local path, and a spelling like `/root//.ssh/` slipped past a substring rule on every tool. OPA's input gains `resource.remotePath` for these tools.

**Upgrade note — minor, not patch, because a call that was allowed can now be refused.** A pattern written for commands is now also tested against SFTP paths, so `^rm` refuses an `sftp-download` of `rmlist.txt`. The refusal says whether the command or the remote path matched. Nothing is resolved on the target: relative paths stay relative and symlinks are not followed, so anchor a path rule on its trailing segments.
