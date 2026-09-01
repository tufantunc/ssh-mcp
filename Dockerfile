# Pinned by digest, with the tag left readable beside it.
#
# `node:22-slim` is a moving tag: two builds of the same commit could resolve to
# different base images, which is exactly the reproducibility hole OpenSSF
# Scorecard's Pinned-Dependencies check flags — it scored this file 8/10. The
# digest is the multi-platform OCI index, so linux/amd64 and linux/arm64 both
# still resolve from it.
#
# Pinning is only safe because something refreshes it: .github/dependabot.yml
# watches the `docker` ecosystem monthly and rewrites the digest while keeping
# the tag, the same arrangement the four sshd images in docker-compose.yml
# already use. Without that, a digest pin is how a base image quietly stays on
# unpatched CVEs for a year — strictly worse than the moving tag it replaced.
FROM node:22-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5 AS builder
WORKDIR /app
COPY package*.json ./
# --ignore-scripts because `prepare` runs `npm run build`, and at this layer neither
# tsconfig.json nor src/ has been copied yet, so tsc exits 1. The image has never
# built from this repo — `prepare` predates the Dockerfile and no workflow builds
# the image, which is why nobody noticed. Copying the sources first would also work
# but throws away dependency layer caching on every source change; the build runs
# explicitly below, once there is something to compile.
RUN npm ci --ignore-scripts
COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

FROM node:22-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5
WORKDIR /app

RUN groupadd -r -g 65532 appgroup && useradd -r -u 65532 -g appgroup appuser

COPY --from=builder /app/build ./build
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
# From the build context, not the builder stage: the builder copies only
# package*.json, tsconfig.json and src/, so this path never existed there. The
# earlier `npm ci` failure had been masking it.
COPY config.default.toml ./config.default.toml

# 0700 because the loader refuses a config whose directory is group- or
# world-readable, and mkdir under Docker's default umask produces 0755 — so a
# container with a config bind-mounted at this path met that refusal on every
# start, with no way to chmod a directory baked into the image (#138 review).
RUN mkdir -p /home/appuser/.config/ssh-mcp && \
    chmod 700 /home/appuser/.config /home/appuser/.config/ssh-mcp && \
    chown -R appuser:appgroup /home/appuser /app

USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "process.exit(0)" || exit 1

ENV NODE_ENV=production
ENV SSH_MCP_DISABLE_MAIN=0

ENTRYPOINT ["node", "build/index.js"]
