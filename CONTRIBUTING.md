# Contributing to ssh-mcp

Thank you for your interest in contributing to ssh-mcp! Your help is greatly appreciated. Please follow these guidelines to make the process smooth for everyone.

## How to Contribute

1. **Fork the repository** and create your branch from `main`.
2. **Clone your fork** to your local machine.
3. **Create a descriptive branch name** (e.g., `feature/add-ssh-support` or `bugfix/fix-connection-issue`).
4. **Make your changes** with clear, concise commits.
5. **Test your changes** to ensure nothing is broken.
6. **Push to your fork** and submit a Pull Request (PR) to the `main` branch.

## Code Style
- Follow the existing code style and conventions.
- Write clear, descriptive commit messages.
- Add comments where necessary for clarity.

## Issues and Bugs
- If you find a bug, please open an issue with detailed steps to reproduce it.
- If you want to work on an existing issue, comment on it to let others know.

## Feature Requests
- Open an issue to discuss new features before submitting a PR.
- Describe your proposed feature and its use case.

## Pull Requests
- Ensure your PR is up to date with the latest `main` branch.
- Reference related issues in your PR description (e.g., `Closes #12`).
- Be responsive to feedback and requested changes.
- **Add a changeset:** Run `npm run changeset` before pushing. Select the bump type (patch/minor/major) and write a short changelog entry. This ensures your change appears in the release notes.

### Changeset Example

```bash
npm run changeset
# Select ssh-mcp
# Select minor (for new features) or patch (for fixes)
# Write: "Add ProxyJump support for bastion connections"
```

This creates a file in `.changeset/` — commit it with your PR. When the PR merges, the changesets bot opens a "Version Packages" PR that bumps the version, updates CHANGELOG.md, and publishes to npm. Publishing to npm also lists the new version on the [official MCP registry](https://registry.modelcontextprotocol.io).

### server.json

`server.json` is the MCP registry entry. Its two version fields — the listing's own `version`, and the npm version it points at — are written by `npm run version` from `package.json`, so they arrive already bumped in the "Version Packages" PR and should not be edited by hand. Everything else in the file is hand-maintained; if you change the `title` or `description`, note that the registry schema caps both at 100 characters, which `test/unit/sync-server-json.test.ts` asserts.

## Review Criteria

The `.review-pro/` directory holds the criteria this project's changes are reviewed against — `node/` for general Node.js server concerns (security, correctness, API contracts, tests, performance), and `ssh-mcp/` for signals specific to this codebase: progress and cancellation, OTEL, the HTTP rate limit, ProxyJump, CA certificates, and MCP resources.

They are plain markdown. Reading the files relevant to your change is a useful checklist before you open a PR, and nothing needs to be installed to do that. Anything touching the policy engine, the audit chain, or host-key handling is worth checking against `.review-pro/ssh-mcp/security.md` in particular.

Those same files are the rubric for [review-pro](https://github.com/tufantunc/review-pro) (`npx review-pro`), which runs them as an automated review. That tool is mine and lives in a separate repository; using it is entirely optional, CI does not run it, and no PR is held up for skipping it.

## Code of Conduct
- Be respectful and inclusive in all interactions.
- See the [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) if available.

Thank you for helping make ssh-mcp better! 