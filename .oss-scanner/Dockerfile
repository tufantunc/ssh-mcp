# Image for Anthropic's OSS Scanner (https://github.com/anthropics/oss-scanner).
#
# Not the image this project ships — that is the root Dockerfile, which keeps
# only build/ and node_modules/. A scanning agent needs the opposite: the whole
# checkout at /src, dev dependencies, the test suite, and something to run it
# against. The scan runs with no network, so everything is fetched here.
#
# Built with the repository root as context. The root .dockerignore drops
# test/, docs and every *.md — right for the shipped image, wrong for this one —
# so Dockerfile.dockerignore beside this file replaces it (BuildKit reads the
# per-Dockerfile ignore file first; the scanner builds with DOCKER_BUILDKIT=1).
#
# Pinned by digest like the root Dockerfile; .github/dependabot.yml refreshes it.
FROM node:22-bookworm@sha256:69a5713e7f4997e96d579aafd78734810e0dac0dd5ee4621d72c27a2891a4088

# openssh-server and dropbear stand in for the docker-compose test servers,
# which cannot run inside the scan. busybox gives one user an `ash` login
# shell, the axis the compose file's Alpine server exists for.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        openssh-server dropbear-bin sudo busybox \
    && rm -rf /var/lib/apt/lists/*

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# Fail the build, not the scan, if an ignore file hid the sources: a scan of
# src/ without test/ or SECURITY.md would run, and quietly be worse.
RUN test -d test/integration && test -f SECURITY.md && test -f .oss-scanner/threat_model.md

# `prepare` runs `npm run build`, so this also compiles build/.
RUN npm ci

RUN .oss-scanner/test-servers.sh setup

# Cheap tests only, so a broken image shows up in the build log. Not allowed to
# fail the build: the scan is still worth running on a red unit suite.
RUN npm run test:unit || echo "WARNING: unit tests reported failures"
