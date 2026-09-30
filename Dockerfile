# ─── Base ────────────────────────────────────────────────────────────
FROM node:22-alpine AS base
WORKDIR /app

# Install dependencies needed for some npm packages and git operations
RUN apk add --no-cache libc6-compat git unzip

COPY package.json package-lock.json ./
RUN npm ci --production=false

COPY next.config.ts tsconfig.json postcss.config.mjs components.json prisma.config.ts ./
COPY prisma ./prisma
COPY public ./public
COPY src ./src
COPY scripts ./scripts
COPY compliance ./compliance
COPY rules ./rules

# Generate Prisma client
RUN npx prisma generate

# ─── API (Next.js) ──────────────────────────────────────────────────
FROM base AS api-build
RUN npm run build

FROM node:22-alpine AS api
WORKDIR /app
RUN apk add --no-cache libc6-compat git unzip poppler-utils

COPY --from=api-build /app/package.json /app/package-lock.json ./
COPY --from=api-build /app/node_modules ./node_modules
COPY --from=api-build /app/.next ./.next
COPY --from=api-build /app/public ./public
COPY --from=api-build /app/next.config.ts ./
COPY --from=api-build /app/prisma ./prisma
COPY --from=api-build /app/prisma.config.ts ./
COPY --from=api-build /app/src/generated ./src/generated
COPY --from=api-build /app/compliance ./compliance
COPY --from=api-build /app/scripts ./scripts
COPY --from=api-build /app/scripts/docker-entrypoint-api.sh /usr/local/bin/docker-entrypoint-api.sh
RUN chmod +x /usr/local/bin/docker-entrypoint-api.sh

ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000

# Apply schema (migrate + push), seed, then start the Next.js server.
CMD ["/usr/local/bin/docker-entrypoint-api.sh"]

# ─── Worker ─────────────────────────────────────────────────────────
FROM base AS worker
ENV NODE_ENV=production

# Worker needs git for cloning repositories, subversion for SVN repos
RUN apk add --no-cache subversion

# OpenGrep powers rule-based SAST (SAST_PATTERN) with the packs in rules/.
# Pinned release, checksum-verified per architecture.
ARG OPENGREP_VERSION=1.30.0
RUN set -eux; \
    case "$(apk --print-arch)" in \
      x86_64)  asset=opengrep_musllinux_x86;     sha=ee21fa70714531e1eccbcb50993a871e198fb0f4ade254ef7636c433304fe4bd ;; \
      aarch64) asset=opengrep_musllinux_aarch64; sha=937d0f35fc05af8877f5f34e04465f2466a8da3c33c2a0d510b8a896383354ef ;; \
      *) echo "unsupported architecture for OpenGrep: $(apk --print-arch)"; exit 1 ;; \
    esac; \
    wget -q -O /usr/local/bin/opengrep "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/${asset}"; \
    echo "${sha}  /usr/local/bin/opengrep" | sha256sum -c -; \
    chmod +x /usr/local/bin/opengrep; \
    LC_ALL=C.UTF-8 opengrep --version

CMD ["npx", "tsx", "src/worker/index.ts"]
