# ─── Base ────────────────────────────────────────────────────────────
FROM node:20-alpine AS base
WORKDIR /app

# Install dependencies needed for some npm packages and git operations
RUN apk add --no-cache libc6-compat git unzip

COPY package.json package-lock.json ./
RUN npm ci --production=false

COPY . .

# Generate Prisma client
RUN npx prisma generate

# ─── API (Next.js) ──────────────────────────────────────────────────
FROM base AS api-build
RUN npm run build

FROM node:20-alpine AS api
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

ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000

# Run migrations and seed on startup, then start the app
CMD ["sh", "-c", "npx prisma migrate deploy && npx tsx prisma/seed.ts && npm start"]

# ─── Worker ─────────────────────────────────────────────────────────
FROM base AS worker
ENV NODE_ENV=production

# Worker needs git for cloning repositories, subversion for SVN repos
RUN apk add --no-cache git unzip subversion

CMD ["npx", "tsx", "src/worker/index.ts"]
