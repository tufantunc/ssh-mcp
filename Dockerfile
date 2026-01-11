# Multi-stage build for SSH MCP Server
# Stage 1: Build
FROM node:20-alpine AS builder

# Install build dependencies
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Copy package files and source code
COPY package*.json ./
COPY tsconfig.json ./
COPY src ./src

# Install all dependencies (including dev dependencies for build)
# This will trigger the prepare script which runs npm run build
RUN npm install

# Stage 2: Production
FROM node:20-alpine

# Install runtime dependencies (for SSH key support)
RUN apk add --no-cache openssh-client

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install only production dependencies (ignore scripts to prevent prepare from running)
RUN npm install --omit=dev --ignore-scripts && \
    npm cache clean --force

# Copy built application from builder
COPY --from=builder /app/build ./build

# Create directory for SSH keys (optional, can be mounted)
RUN mkdir -p /root/.ssh && chmod 700 /root/.ssh

# Set the entrypoint to node with the built index.js
ENTRYPOINT ["node", "build/index.js"]

# No default CMD - user must provide SSH connection parameters
