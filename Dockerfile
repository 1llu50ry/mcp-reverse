# syntax=docker/dockerfile:1.7

# ---- stage 1: build -----------------------------------------
# Pin to Node 24 LTS: that's the floor for stable node:sqlite
# (the DB backing of this project). Node 22 can run with
# --experimental-sqlite but the extra flag isn't worth the risk.
FROM node:26-bookworm-slim AS build

WORKDIR /src

# Install just the manifest first so the npm cache mounts can reuse
# dependencies across rebuilds that touch only source files.
COPY package.json package-lock.json* ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --no-audit --no-fund --ignore-scripts

# Then the rest of the tree. `dist/` is gitignored so we rebuild from
# `src/` here — the published layer never carries a stale compile.
COPY tsconfig.json ./
COPY src/ ./src/
RUN npx tsc

# ---- stage 2: runtime ---------------------------------------
# -slim gets us a Debian base with glibc; needed because Frida and
# some plugin tooling expect dynamic linker/libstdc++ at runtime,
# which Alpine would make awkward. Still only ~75 MiB base.
FROM node:26-bookworm-slim AS runtime

# dumb-init turns Node into a well-behaved PID 1 inside the
# container — correct SIGTERM/SIGINT handling so `docker stop`
# finishes cleanly without the 10 s kill fallback.
RUN apt-get update \
 && apt-get install -y --no-install-recommends dumb-init \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install only production deps. node_modules shrinks ~40% without
# dev dependencies (tsx / typescript / @types).
COPY package.json package-lock.json* ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --omit=dev --no-audit --no-fund --ignore-scripts

# Compiled JS + static assets. All of the content library (skills,
# plugins, agents, subagents, prompts) lives in a single SQLite file
# under db/skills.db — the server opens it read-only on boot and
# every list/search/read goes through FTS5 instead of walking
# 10,000+ files. ~18 MiB vs the 19 GiB raw tree.
COPY --from=build /src/dist ./dist
COPY bin/        ./bin/
COPY db/         ./db/
COPY signatures/ ./signatures/
COPY scripts/    ./scripts/

# Drop to the non-root `node` user baked into the base image.
# All of /app is owned by this user already (COPY --chown would
# just add build time); the runtime scratch dirs are created at
# server startup under /app, which is writable for this uid.
USER node

# Default to HTTP transport on 0.0.0.0 inside the container; let
# the orchestrator (compose / k8s) decide the external binding.
# stdio consumers (Claude Desktop etc.) pass -e MCP_TRANSPORT=stdio.
ENV MCP_TRANSPORT=http \
    MCP_HTTP_HOST=0.0.0.0 \
    MCP_HTTP_PORT=7777 \
    NODE_ENV=production
EXPOSE 7777

# Health probe for compose / k8s. /healthz is always open and
# answers in <5 ms, so we don't need curl in the image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('node:http').get('http://127.0.0.1:7777/healthz', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "dist/index.js"]
