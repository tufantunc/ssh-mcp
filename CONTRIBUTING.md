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

This creates a file in `.changeset/` — commit it with your PR. When the PR merges, the changesets bot opens a "Version Packages" PR that bumps the version, updates CHANGELOG.md, and publishes to npm.

## Code of Conduct
- Be respectful and inclusive in all interactions.
- See the [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) if available.

Thank you for helping make ssh-mcp better! 