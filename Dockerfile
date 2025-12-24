# Multi-stage build for ssh-mcp with gcloud CLI
FROM node:20-slim AS builder

# Install build dependencies
WORKDIR /app
COPY package*.json ./
RUN npm ci

# Copy source and build
COPY . .
RUN npm run build

# Production image
FROM node:20-slim

# Install gcloud CLI
RUN apt-get update && \
    apt-get install -y \
        curl \
        gnupg \
        apt-transport-https \
        ca-certificates && \
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | \
        tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | \
        gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && \
    apt-get update && \
    apt-get install -y google-cloud-cli && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -m -u 1000 sshmcp

# Install production dependencies
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production && \
    npm cache clean --force

# Copy built application
COPY --from=builder /app/build ./build

# Change ownership
RUN chown -R sshmcp:sshmcp /app

# Switch to non-root user
USER sshmcp

# Expose default HTTP port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Default command - HTTP/SSE mode on port 3000
CMD ["node", "build/index.js", "--port=3000"]
