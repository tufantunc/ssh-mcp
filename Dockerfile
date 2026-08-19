FROM node:22-slim AS builder
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

FROM node:22-slim
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
