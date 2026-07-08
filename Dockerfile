FROM node:22-slim AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

FROM node:22-slim
WORKDIR /app

RUN groupadd -r -g 65532 appgroup && useradd -r -u 65532 -g appgroup appuser

COPY --from=builder /app/build ./build
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/config.default.toml ./config.default.toml

RUN mkdir -p /home/appuser/.config/ssh-mcp && \
    chown -R appuser:appgroup /home/appuser /app

USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "process.exit(0)" || exit 1

ENV NODE_ENV=production
ENV SSH_MCP_DISABLE_MAIN=0

ENTRYPOINT ["node", "build/index.js"]
